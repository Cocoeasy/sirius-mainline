#!/usr/bin/env python3
"""Read-only validator for the EA8074 display evidence fixture (stage 1).

Scope
-----
This module reads ``config/ea8074-evidence.json`` and nothing else.  It never
touches a phone, the network, or the Git state, and it never writes to the
fixture: every mutation performed by the tests happens on ``copy.deepcopy``
objects in memory.

Two independent verdicts
------------------------
The fixture can be *internally consistent* while the hardware is still not
safe to drive.  Those are deliberately separate:

* ``Report.fixture_valid`` -- the recorded numbers agree with each other, the
  on/off ``bytes_hex`` arrays really parse with the documented 7-byte header
  layout, their SHA-256 matches a re-hash of the real bytes, and the
  brightness / power / reset claims are backed by the pinned downstream
  source snippets that are quoted in the fixture.
* ``Report.hardware_ready`` -- an explicit gate.  It stays closed while a
  high/medium blocker is still open.  Today ``hardware_test_ready = false``
  because ``dts/sdm710-xiaomi-sirius.dts`` still wires the 3.0 V rail through
  tlmm GPIO76 and still declares an unsupported 3.3 V ``vdd3p3-supply``
  (blocker B1).  The evidence itself is now complete.

``fixture_valid = True`` together with ``hardware_ready = False`` is the
expected, correct outcome for the current evidence.  It is not a defect.

The gate is never silently dropped: a claim of ``hardware_test_ready = true``
while a blocker is open *or* while any of the three evidence criteria is unmet
is a hard error.  The flag is checked against the evidence, never trusted.

Evidence is read from raw bytes and from source snippets, not from summaries
-----------------------------------------------------------------------------
Two claims are re-derived rather than believed:

* the DCS 0x51 zero-brightness write inside the 204-byte on-command array is
  decoded from ``init_commands.on.bytes_hex`` itself; and
* the 0x51 wire byte order is *computed* from the three pinned snippets
  (EA8074 dtsi ``bl-inverted-dbv`` -> the ``dsi_panel.c`` u16 swap -> the
  little-endian packing in ``drm_mipi_dsi.c``), simulating the swap so that the
  "cancels into MSB-first" claim is demonstrated instead of asserted.

FDT honesty
-----------
The fixture carries only *summary* FDT numbers (sizes, token counts, phandle
count) -- the raw FDT bytes are absent by design (they were parsed in memory
only).  This validator therefore re-derives the summary's internal arithmetic
(block offsets, block sizes, token balance) but does NOT claim to re-verify the
full FDT token stream.  The token counts remain recorded claims.  See the
``[fdt.tokens_unverifiable]`` note emitted on every run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections import namedtuple
from typing import Any, Sequence

# --------------------------------------------------------------------------
# Constants: record format, legal ranges, and the task pins.
# The pins below come from the approved plan, deliberately NOT from the
# fixture, so that a mutated fixture cannot define its own acceptance.
# --------------------------------------------------------------------------

FIXTURE_ID = "ea8074-display-evidence"

HEADER_BYTES = 7
RECORD_FIELDS = ["dtype", "last", "vc", "ack", "wait_ms_u8", "dlen_hi", "dlen_lo"]

# MIPI DSI DCS write data types that may legally appear in a
# qcom,mdss-dsi-*-command array: short write (0x05), short write with one
# parameter (0x15), long write (0x39), generic long write (0x29).
ALLOWED_DTYPES = frozenset({0x05, 0x15, 0x29, 0x39})
MAX_VC = 3  # virtual channel id is 2 bits

PINNED = {
    "on": {
        "length_bytes": 204,
        "record_count": 21,
        "sha256": "1c25248bc7206c438080a8c7958f3196a9d1426ded9dca592f644b71c987e594",
    },
    "off": {
        "length_bytes": 18,
        "record_count": 2,
        "sha256": "1d4f64f5b407e84e631e4f3691c2a8823482f2b3b337c1b7587f787c39aea82d",
    },
}

# Fields that were fabricated in an earlier revision of this fixture and must
# not come back.  ``task_pinned_hash`` was a 63-character truncation of the
# SHA-256, and ``hash_discrepancy_note`` described the same digest as both
# 64 and 63 characters.  The real 64-hex SHA-256 fields are verified directly.
STALE_HASH_FIELDS = (
    "task_pinned_hash",
    "task_pinned_hash_is_63_hex_chars",
    "task_pinned_hash_equals_sha256_minus_leading_nibble",
)
STALE_TOP_LEVEL_FIELDS = ("hash_discrepancy_note",)

PINNED_PANEL_MODEL = "SS-FHD-EA8074-CMD-PANEL"
PINNED_PANEL_PATH = "/soc/qcom,mdss_dsi_ss_fhd_ea8074_cmd"
PINNED_PANEL_TYPE = "dsi_cmd_mode"
PINNED_BPP = 24
PINNED_LANES = [0, 1, 2, 3]
PINNED_TIMING = {
    "qcom_mdss_dsi_panel_width": 1080,
    "qcom_mdss_dsi_panel_height": 2244,
    "qcom_mdss_dsi_panel_framerate": 60,
    "qcom_mdss_dsi_h_front_porch": 48,
    "qcom_mdss_dsi_h_back_porch": 48,
    "qcom_mdss_dsi_h_pulse_width": 16,
    "qcom_mdss_dsi_v_front_porch": 28,
    "qcom_mdss_dsi_v_back_porch": 28,
    "qcom_mdss_dsi_v_pulse_width": 12,
}
PINNED_RESET_GPIO = 75
PINNED_TE_GPIO = 10
PINNED_TLMM_PHANDLE = 50
PINNED_RESET_PAIRS = [[0, 2], [1, 11]]
PINNED_VCI_GPIO = 5
PINNED_TE_DCS_COMMAND = 1
PINNED_BRIGHTNESS_MAX = 1023
PINNED_BRIGHTNESS_MIN = 1
# Vendor panel-supply-entries: exactly two rails, 1.8 V vddio and 3.0 V vci.
# Nothing else may be enabled: no LAB, no IBB, no GPIO76, no 3.3 V rail.
PINNED_SUPPLY_ENTRY_COUNT = 2
PINNED_SUPPLY_UV = {0: ("vddio", 1800000), 1: ("vci", 3000000)}
FORBIDDEN_RAIL_NAMES = ("lab", "ibb", "lcdb")
FORBIDDEN_UV = (3300000,)

# DCS 0x51 (set display brightness) inside the on-command array.
DCS_BRIGHTNESS_CMD = 0x51
PINNED_INIT_BRIGHTNESS_LEVEL = 0

# Doze levels are NOT a boot default: they are separate low-brightness values.
PINNED_DOZE_LBM = 10
PINNED_DOZE_HBM = 133

# Supply sequencing derived from dsi_pwr.c plus the vendor supply table order.
PINNED_ENABLE_ORDER = ["vddio", "vci"]
PINNED_DISABLE_ORDER = ["vci", "vddio"]
PINNED_INTER_RAIL_SLEEP_MS = 10

# Pinned downstream source.
DOWNSTREAM_COMMIT = "06a01bad75939c58be53418f5d71d9d2e25634cf"
DOWNSTREAM_REPO = "SDM710-Development/android_kernel_xiaomi_sdm710"
DTSI_EA8074 = "arch/arm64/boot/dts/qcom/dsi-panel-ss-fhd-ea8074-cmd.dtsi"
DTSI_SIRIUS = "arch/arm64/boot/dts/qcom/sirius-sdm710.dtsi"
DSI_PANEL_C = "drivers/gpu/drm/msm/dsi-staging/dsi_panel.c"
DSI_PWR_C = "drivers/gpu/drm/msm/dsi-staging/dsi_pwr.c"
DRM_MIPI_DSI_C = "drivers/gpu/drm/drm_mipi_dsi.c"
FIXED_C = "drivers/regulator/fixed.c"
REQUIRED_SOURCE_FILES = (DTSI_EA8074, DTSI_SIRIUS, DSI_PANEL_C, DSI_PWR_C, DRM_MIPI_DSI_C, FIXED_C)

# Each entry must be satisfied by ONE snippet string that contains every token.
REQUIRED_SNIPPETS = (
    (DTSI_EA8074, "bl-inverted-dbv", ("qcom,mdss-dsi-bl-inverted-dbv",)),
    (DTSI_EA8074, "reset sequence", ("qcom,mdss-dsi-reset-sequence", "<0 2>", "<1 11>")),
    (DTSI_EA8074, "doze lbm", ("qcom,disp-doze-lbm-backlight", "<10>")),
    (DTSI_EA8074, "doze hbm", ("qcom,disp-doze-hbm-backlight", "<133>")),
    (DTSI_EA8074, "brightness max", ("qcom,mdss-brightness-max-level", "<1023>")),
    (DTSI_SIRIUS, "vci on tlmm gpio5", ("gpio = <&tlmm 5 0>", "enable-active-high")),
    (DTSI_SIRIUS, "vendor start-delay-us", ("start-delay-us = <4000>",)),
    (DSI_PANEL_C, "u16 byte swap", ("bl_inverted_dbv", "<< 8", ">> 8")),
    (DSI_PANEL_C, "inverted-dbv parsed", ("of_property_read_bool", "qcom,mdss-dsi-bl-inverted-dbv")),
    (DSI_PANEL_C, "reset gpio acquired", ("qcom,platform-reset-gpio",)),
    (DSI_PANEL_C, "reset driven with raw levels", ("gpio_set_value(reset_gpio", "sequence")),
    (DRM_MIPI_DSI_C, "little-endian packing", ("brightness & 0xff, brightness >> 8", "MIPI_DCS_SET_DISPLAY_BRIGHTNESS")),
    (DSI_PWR_C, "enable forward loop", ("for (i = 0; i < regs->count; i++)", "post_on_sleep")),
    (DSI_PWR_C, "disable reverse loop", ("for (i = (regs->count - 1); i >= 0; i--)", "pre_off_sleep")),
    (FIXED_C, "reads startup-delay-us", ("startup-delay-us",)),
)

# Messages that must never cite a non-EA8074 helper as byte-order evidence.
NOT_BYTE_ORDER_EVIDENCE = ("ams639rq08", "_large")

# Prose anchors for the derived DCS 0x51 wire order.  Both directions are
# checked so that a reversed-order edit cannot slip through.
MSB_FIRST_PHRASE = re.compile(r"most significant byte first|msb[- ]first|msb\s*,\s*lsb|msb\s+then\s+lsb")
LSB_FIRST_PHRASE = re.compile(r"least significant byte first|lsb[- ]first|lsb\s*,\s*msb|lsb\s+then\s+msb")

# Severities that keep the hardware gate closed.
GATING_SEVERITIES = frozenset({"high", "medium", "critical"})

Record = namedtuple("Record", "offset dtype last vc ack wait_ms dlen payload")


class RecordParseError(ValueError):
    """A qcom,mdss-dsi-*-command byte array could not be walked safely."""


# --------------------------------------------------------------------------
# Parsing / small helpers
# --------------------------------------------------------------------------


def normalize_fdt_path(path: Any) -> Any:
    """Collapse a doubled (or tripled...) leading slash to a single one.

    The live FDT parser reports node paths with a doubled leading slash because
    the root node name is the empty string (documented in
    ``sources[fdt_live].note``).  Normalisation happens only for comparison --
    the fixture is never rewritten.
    """
    if not isinstance(path, str):
        return path
    return re.sub(r"^/+", "/", path)


def sha256_of_hex(byte_hex: str) -> str:
    """SHA-256 of the *bytes* described by a hex string (not of the string)."""
    return hashlib.sha256(bytes.fromhex(re.sub(r"\s+", "", byte_hex))).hexdigest()


def sha1_of_hex(byte_hex: str) -> str:
    return hashlib.sha1(bytes.fromhex(re.sub(r"\s+", "", byte_hex))).hexdigest()


def is_hex_digest(value: Any, length: int) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{%d}" % length, value) is not None


def compact(text: Any) -> str:
    """Lower-cased single-spaced text, for robust prose anchoring."""
    return re.sub(r"\s+", " ", str(text)).strip().lower()


def parse_records(byte_hex: Any, context: str = "command array") -> list:
    """Walk a qcom DSI command array using the documented 7-byte header.

    Header layout (matches ``init_commands.record_format.fields``)::

        dtype | last | vc | ack | wait_ms_u8 | dlen_hi | dlen_lo   -> dlen payload

    Raises :class:`RecordParseError` on a truncated header, a declared payload
    length that overruns the buffer, an illegal data type, or an out-of-range
    vc/ack/last.
    """
    if not isinstance(byte_hex, str):
        raise RecordParseError(f"{context}: bytes_hex must be a string, got {type(byte_hex).__name__}")
    body_hex = re.sub(r"\s+", "", byte_hex)
    if len(body_hex) == 0:
        raise RecordParseError(f"{context}: bytes_hex is empty")
    if len(body_hex) % 2:
        raise RecordParseError(f"{context}: odd number of hex digits ({len(body_hex)})")
    if not re.fullmatch(r"[0-9a-fA-F]+", body_hex):
        raise RecordParseError(f"{context}: bytes_hex contains non-hex characters")

    data = bytes.fromhex(body_hex)
    records = []
    off = 0
    while off < len(data):
        remaining = len(data) - off
        if remaining < HEADER_BYTES:
            raise RecordParseError(
                f"{context}: truncated {HEADER_BYTES}-byte header at offset {off} "
                f"({remaining} byte(s) left, header needs {HEADER_BYTES})"
            )
        dtype, last, vc, ack, wait_ms, dlen_hi, dlen_lo = data[off : off + HEADER_BYTES]
        dlen = (dlen_hi << 8) | dlen_lo
        body = off + HEADER_BYTES
        if dlen == 0:
            raise RecordParseError(f"{context}: record at offset {off} declares a zero-length payload")
        if body + dlen > len(data):
            raise RecordParseError(
                f"{context}: record at offset {off} declares {dlen} payload byte(s) "
                f"but only {len(data) - body} remain (length overrun)"
            )
        if dtype not in ALLOWED_DTYPES:
            raise RecordParseError(
                f"{context}: record at offset {off} has unsupported data type "
                f"0x{dtype:02x} (allowed: "
                + ", ".join(sorted("0x%02x" % d for d in ALLOWED_DTYPES))
                + ")"
            )
        if last > 1:
            raise RecordParseError(f"{context}: record at offset {off} has out-of-range last flag {last}")
        if vc > MAX_VC:
            raise RecordParseError(f"{context}: record at offset {off} has out-of-range vc {vc} (max {MAX_VC})")
        if ack > 1:
            raise RecordParseError(f"{context}: record at offset {off} has out-of-range ack {ack}")

        payload = data[body : body + dlen]
        if dtype == 0x05:
            # DCS short write, no parameters: payload is the command byte
            # followed by 0x00 padding.  Padding must never be read as a
            # parameter.
            if payload[0] == 0x00:
                raise RecordParseError(f"{context}: 0x05 record at offset {off} carries command byte 0x00")
            padded = [i for i, b in enumerate(payload[1:], start=1) if b != 0]
            if padded:
                raise RecordParseError(
                    f"{context}: 0x05 record at offset {off} (cmd 0x{payload[0]:02x}) has non-zero "
                    f"byte(s) at payload index {padded}; bytes after the DCS command of a 0x05 "
                    "short write are 0x00 padding and must not be treated as parameters"
                )

        records.append(Record(off, dtype, last, vc, ack, wait_ms, dlen, payload))
        off = body + dlen
    return records


def decode_u32_triplet(raw_hex: Any) -> tuple:
    """Decode a 12-byte big-endian ``<phandle gpio flag>`` property blob."""
    if not isinstance(raw_hex, str):
        raise RecordParseError(f"raw_hex must be a string, got {type(raw_hex).__name__}")
    compacted = re.sub(r"\s+", "", raw_hex)
    if len(compacted) != 24 or not re.fullmatch(r"[0-9a-fA-F]{24}", compacted):
        raise RecordParseError(f"expected a 12-byte (24 hex digit) triple, got {len(compacted)} hex digits")
    raw = bytes.fromhex(compacted)
    return tuple(int.from_bytes(raw[i : i + 4], "big") for i in (0, 4, 8))


def find_dcs_brightness_records(records) -> list:
    """0x39 long writes whose payload starts with DCS 0x51 (set brightness)."""
    return [r for r in records if r.dtype == 0x39 and r.payload[:1] == bytes([DCS_BRIGHTNESS_CMD])]


def source_snippets(doc: dict, path: str) -> list:
    files = ((doc.get("downstream_source_evidence") or {}).get("files")) or {}
    entry = files.get(path) or {}
    snippets = entry.get("snippets")
    return [s for s in snippets if isinstance(s, str)] if isinstance(snippets, list) else []


def snippets_blob(doc: dict, path: str) -> str:
    return " || ".join(source_snippets(doc, path))


def derive_wire_byte_order(doc: dict) -> dict:
    """Re-derive the DCS 0x51 wire order from the pinned snippets.

    Simulates the two operations that the downstream source performs:

    1. ``dsi_panel.c`` byte-swaps the 16-bit level when the panel declares
       ``qcom,mdss-dsi-bl-inverted-dbv``; and
    2. ``mipi_dsi_dcs_set_display_brightness()`` packs little-endian.

    A probe value with distinct bytes is pushed through the same arithmetic, so
    "the swap and the packing cancel into MSB-first" is demonstrated rather than
    taken on trust.
    """
    dtsi = snippets_blob(doc, DTSI_EA8074)
    panel = snippets_blob(doc, DSI_PANEL_C)
    drm = snippets_blob(doc, DRM_MIPI_DSI_C)

    inverted = "qcom,mdss-dsi-bl-inverted-dbv" in dtsi
    swap_present = ("bl_inverted_dbv" in panel) and ("<< 8" in panel) and (">> 8" in panel)
    helper_little_endian = "brightness & 0xff, brightness >> 8" in drm

    probe = 0x0342  # MSB 0x03, LSB 0x42 - distinct, so order is observable
    value = probe
    if inverted and swap_present:
        value = ((value & 0xFF) << 8) | (value >> 8)
    if helper_little_endian:
        payload = bytes([value & 0xFF, (value >> 8) & 0xFF])
    else:
        payload = bytes([(value >> 8) & 0xFF, value & 0xFF])

    msb_first = payload[0] == ((probe >> 8) & 0xFF)
    # What a LSB-first panel would emit without the inverted-dbv swap.
    without_swap = bytes([probe & 0xFF, (probe >> 8) & 0xFF])

    return {
        "inverted_dbv": inverted,
        "swap_present": swap_present,
        "helper_little_endian": helper_little_endian,
        "probe": probe,
        "payload_hex": payload.hex(),
        "without_swap_hex": without_swap.hex(),
        "msb_first": msb_first,
        "swap_is_load_bearing": inverted and swap_present and msb_first and without_swap[0] != payload[0],
    }


def derive_power_sequence(doc: dict) -> dict:
    """Derive the enable/disable rail sequence from dsi_pwr.c + the supply table."""
    pwr = snippets_blob(doc, DSI_PWR_C)
    forward = "for (i = 0; i < regs->count; i++)" in pwr
    reverse = "for (i = (regs->count - 1); i >= 0; i--)" in pwr

    entries = ((doc.get("power") or {}).get("panel_supply_entries") or {}).get("entries") or []
    table = [e for e in entries if isinstance(e, dict)]
    order = [str(e.get("qcom_supply_name")) for e in table]

    def entry_for(name):
        for e in table:
            if str(e.get("qcom_supply_name")) == name:
                return e
        return {}

    enable = list(order) if forward else []
    disable = list(reversed(order)) if reverse else []
    last_enabled = enable[-1] if enable else None
    first_disabled = disable[0] if disable else None
    return {
        "forward_loop": forward,
        "reverse_loop": reverse,
        "enable": enable,
        "disable": disable,
        "enable_trailing_sleep_ms": entry_for(last_enabled).get("post_on_sleep_ms") if last_enabled else None,
        "disable_leading_sleep_ms": entry_for(first_disabled).get("pre_off_sleep_ms") if first_disabled else None,
    }


# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------


class Report:
    """Collected findings plus the two verdicts."""

    def __init__(self, path: str | None = None) -> None:
        self.path = path
        self.errors: list = []
        self.warnings: list = []
        self.notes: list = []
        self.hardware_declared_ready: Any = None
        self.hardware_blockers: list = []
        self.evidence_criteria_unmet: list = []
        self.derived: dict = {}
        self.checked: list = []

    # -- collection -------------------------------------------------------
    def error(self, message: str) -> None:
        self.errors.append(message)

    def warn(self, message: str) -> None:
        self.warnings.append(message)

    def note(self, message: str) -> None:
        self.notes.append(message)

    def mark(self, check_id: str) -> None:
        self.checked.append(check_id)

    # -- verdicts ---------------------------------------------------------
    @property
    def fixture_valid(self) -> bool:
        """True when the document is internally consistent and un-tampered."""
        return not self.errors

    @property
    def hardware_ready(self) -> bool:
        """True only when the fixture claims readiness *and* no gate is open."""
        return bool(self.hardware_declared_ready) and not self.hardware_blockers

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "fixture_valid": self.fixture_valid,
            "hardware_declared_ready": self.hardware_declared_ready,
            "hardware_ready": self.hardware_ready,
            "hardware_blockers": list(self.hardware_blockers),
            "evidence_criteria_unmet": list(self.evidence_criteria_unmet),
            "derived": self.derived,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "notes": list(self.notes),
            "checks": list(self.checked),
        }


def _get(doc: Any, dotted: str, report: Report, default: Any = None) -> Any:
    """Fetch ``a.b.c`` and record a structure error when the key is missing."""
    cur = doc
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            report.error(f"[structure] missing required key: {dotted}")
            return default
    return cur


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------


def _check_identity(doc: dict, report: Report) -> None:
    if _get(doc, "fixture", report) != FIXTURE_ID:
        report.error(f"[identity.fixture] fixture != {FIXTURE_ID!r}")

    dev = _get(doc, "device", report, default={}) or {}
    if not isinstance(dev, dict) or not dev.get("model"):
        report.error("[identity.device] device.model is missing or empty")
    else:
        report.note(f"device.model = {dev.get('model')!r}, codename = {dev.get('codename')!r}, mode = {dev.get('mode')!r}")
    if dev.get("codename") not in (None, "sirius"):
        report.error(f"[identity.codename] device.codename is {dev.get('codename')!r}, expected 'sirius'")

    panel = _get(doc, "panel", report, default={}) or {}
    model = panel.get("qcom_mdss_dsi_panel_model")
    if model != PINNED_PANEL_MODEL:
        report.error(f"[identity.panel_model] panel model is {model!r}, expected {PINNED_PANEL_MODEL!r}")
    if not (isinstance(model, str) and "EA8074" in model.upper()):
        report.error("[identity.ea8074] panel model does not identify an EA8074 panel")
    panel_path = normalize_fdt_path(panel.get("fdt_path"))
    if not (isinstance(panel_path, str) and "ea8074" in panel_path.lower()):
        report.error(f"[identity.ea8074_path] panel fdt_path is not EA8074: {panel.get('fdt_path')!r}")
    report.mark("identity")


def _check_paths(doc: dict, report: Report) -> None:
    """Report (never rewrite) the doubled-slash FDT path quirk."""

    def walk(node: Any, trail: str = "") -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                walk(value, f"{trail}.{key}")
        elif isinstance(node, list):
            for i, value in enumerate(node):
                walk(value, f"{trail}[{i}]")
        elif isinstance(node, str):
            if node.startswith("//") or "//soc" in node:
                report.note(
                    f"[paths.doubled_slash] {trail} = {node!r} carries a doubled leading slash; "
                    "it was normalised for comparison only and NOT written back to the fixture"
                )

    walk(doc)
    report.mark("paths")


def _check_sources_and_fdt(doc: dict, report: Report) -> None:
    sources = _get(doc, "sources", report, default=[]) or []
    by_id = {}
    for entry in sources:
        if isinstance(entry, dict) and "id" in entry:
            by_id[entry["id"]] = entry

    fdt = by_id.get("fdt_live")
    if fdt is None:
        report.error("[sources.fdt] sources[] has no 'fdt_live' entry")
        return
    if "sysfs_live" not in by_id:
        report.warn("[sources.sysfs] sources[] has no 'sysfs_live' entry")

    header = fdt.get("fdt_header") or {}
    integrity = fdt.get("parse_integrity") or {}

    if header.get("magic") != "0xd00dfeed":
        report.error(f"[fdt.magic] fdt_header.magic is {header.get('magic')!r}, expected '0xd00dfeed'")

    totalsize = header.get("totalsize")
    if fdt.get("size_bytes") != totalsize:
        report.error(f"[fdt.size] sources.size_bytes={fdt.get('size_bytes')} != fdt_header.totalsize={totalsize}")

    off_struct, size_struct = header.get("off_dt_struct"), header.get("size_dt_struct")
    off_strings, size_strings = header.get("off_dt_strings"), header.get("size_dt_strings")
    off_rsvmap = header.get("off_mem_rsvmap")
    if None not in (off_struct, size_struct, off_strings):
        if off_struct + size_struct != off_strings:
            report.error(
                f"[fdt.layout] off_dt_struct+size_dt_struct = {off_struct + size_struct} != off_dt_strings = {off_strings}"
            )
    if None not in (off_strings, size_strings, totalsize):
        if off_strings + size_strings != totalsize:
            report.error(
                f"[fdt.layout] off_dt_strings+size_dt_strings = {off_strings + size_strings} != totalsize = {totalsize}"
            )
    if None not in (off_rsvmap, off_struct) and not off_rsvmap < off_struct:
        report.error(f"[fdt.layout] off_mem_rsvmap ({off_rsvmap}) must precede off_dt_struct ({off_struct})")
    if None not in (header.get("version"), header.get("last_comp_version")):
        if header["version"] < header["last_comp_version"]:
            report.error("[fdt.layout] header version is older than last_comp_version")

    begin, end = integrity.get("tokens_FDT_BEGIN_NODE"), integrity.get("tokens_FDT_END_NODE")
    if begin != end:
        report.error(f"[fdt.tokens] FDT_BEGIN_NODE ({begin}) != FDT_END_NODE ({end})")
    if integrity.get("node_count") != begin:
        report.error(f"[fdt.tokens] node_count ({integrity.get('node_count')}) != FDT_BEGIN_NODE ({begin})")
    if integrity.get("tokens_FDT_END") != 1:
        report.error(f"[fdt.tokens] FDT_END token count is {integrity.get('tokens_FDT_END')}, expected 1")
    if integrity.get("unknown_tokens") != 0:
        report.error(f"[fdt.tokens] unknown_tokens is {integrity.get('unknown_tokens')}, expected 0")
    if not integrity.get("tokens_FDT_PROP"):
        report.error("[fdt.tokens] tokens_FDT_PROP is missing or zero")
    if not integrity.get("phandle_count"):
        report.error("[fdt.tokens] phandle_count is missing or zero")
    if integrity.get("struct_block_end") != off_strings:
        report.error(
            f"[fdt.layout] parse_integrity.struct_block_end ({integrity.get('struct_block_end')}) != off_dt_strings ({off_strings})"
        )
    if integrity.get("strings_block_end") != totalsize:
        report.error(
            f"[fdt.layout] parse_integrity.strings_block_end ({integrity.get('strings_block_end')}) != totalsize ({totalsize})"
        )
    if integrity.get("contiguous_and_exact") is not True:
        report.error("[fdt.layout] parse_integrity.contiguous_and_exact is not true")

    if not is_hex_digest(fdt.get("sha256"), 64):
        report.error(f"[fdt.sha256] sources.fdt_live.sha256 is not a 64-hex digest: {fdt.get('sha256')!r}")

    # The raw FDT is deliberately absent, so token/phandle counts are recorded
    # claims that this validator can only cross-check arithmetically.
    if report.path and os.path.exists(report.path):
        try:
            fixture_size = os.path.getsize(report.path)
        except OSError:
            fixture_size = None
        if isinstance(totalsize, int) and fixture_size is not None and fixture_size >= totalsize:
            report.error(
                f"[fdt.raw_absent] fixture file ({fixture_size} B) is not smaller than the live FDT "
                f"({totalsize} B); a raw FDT blob appears to be embedded, which the fixture says it is not"
            )
        elif isinstance(totalsize, int):
            report.note(
                f"[fdt.raw_absent] fixture is {fixture_size} B vs FDT {totalsize} B: no raw FDT blob is embedded"
            )
    report.note(
        "[fdt.tokens_unverifiable] raw FDT bytes are not in the fixture; the token counts "
        f"(BEGIN={begin}, END={end}, PROP={integrity.get('tokens_FDT_PROP')}), node_count "
        f"({integrity.get('node_count')}) and phandle_count ({integrity.get('phandle_count')}) are RECORDED "
        "CLAIMS. Only their mutual arithmetic was re-derived here -- the full FDT token stream was NOT re-verified."
    )
    report.mark("fdt_summary")


def _check_phandle_links(doc: dict, report: Report, ctx: dict) -> None:
    phandles = _get(doc, "phandles", report, default={}) or {}
    display = _get(doc, "display_node", report, default={}) or {}
    triplets_seen = ctx.setdefault("triplets", {})

    for key, value in phandles.items():
        if isinstance(value, list):
            if len(value) != 2 or not all(isinstance(v, int) and v > 0 for v in value):
                report.error(f"[phandle.{key}] expected two positive phandle ints, got {value!r}")
        elif not (isinstance(value, int) and value > 0 and not isinstance(value, bool)):
            report.error(f"[phandle.{key}] expected a positive phandle int, got {value!r}")

    # Named scalar links: display_node attribute -> phandles key.
    links = {
        "qcom_dsi_panel_phandle": "panel_mdss_dsi_ss_fhd_ea8074_cmd",
        "qcom_dsi_ctrl_phandle": "mdss_dsi_ctrl0",
        "qcom_dsi_phy_phandle": "mdss_dsi_phy0",
        "vci_supply_phandle": "disp_vci_vreg",
        "vddio_supply_phandle": "pm660_l11_vddio",
        "lab_supply_phandle": "lcdb_ldo_lab",
        "ibb_supply_phandle": "lcdb_ncp_ibb",
    }
    for attr, key in links.items():
        if attr not in display:
            report.error(f"[phandle.link] display_node.{attr} is missing")
            continue
        if key not in phandles:
            report.error(f"[phandle.link] phandles.{key} is missing")
            continue
        if display[attr] != phandles[key]:
            report.error(
                f"[phandle.link] display_node.{attr} ({display[attr]}) != phandles.{key} ({phandles[key]})"
            )

    # Raw <phandle gpio flag> blobs must agree with their sibling scalars.
    # NOTE: the gpio76 blob is stored under "raw_hex_where_bound" because it is
    # the property value on the nt35597 nodes where that line *is* bound, and
    # it has no sibling phandle/gpio/flag scalars of its own.
    roles = doc.get("gpio_role_resolution") or {}
    triplets = [
        ("display_node.qcom_platform_reset_gpio", display.get("qcom_platform_reset_gpio") or {}, "raw_hex"),
        ("display_node.qcom_platform_te_gpio", display.get("qcom_platform_te_gpio") or {}, "raw_hex"),
        ("panel.esd_err_irq_gpio", ((doc.get("panel") or {}).get("esd_err_irq_gpio")) or {}, "raw_hex"),
        ("gpio_role_resolution.gpio5", roles.get("gpio5") or {}, "raw_hex"),
        ("gpio_role_resolution.gpio76", roles.get("gpio76") or {}, "raw_hex_where_bound"),
    ]
    for label, blob, hex_key in triplets:
        try:
            ph, gpio, flag = decode_u32_triplet(blob.get(hex_key))
        except RecordParseError as exc:
            report.error(f"[phandle.raw_hex] {label}.{hex_key}: {exc}")
            continue
        for field, observed in (("phandle", ph), ("gpio", gpio), ("flag", flag)):
            if field in blob and blob[field] != observed:
                report.error(
                    f"[phandle.raw_hex] {label}.{field} = {blob[field]} disagrees with {hex_key} decode ({observed})"
                )
        # Kept in a side context, never written back into the document.
        triplets_seen[label] = (ph, gpio, flag)

    tlmm = phandles.get("tlmm_pinctrl_03400000")
    reset_decoded = triplets_seen.get("display_node.qcom_platform_reset_gpio")
    if reset_decoded and reset_decoded[0] != tlmm:
        report.error(
            f"[phandle.reset] reset gpio phandle {reset_decoded[0]} != phandles.tlmm_pinctrl_03400000 ({tlmm})"
        )

    # dsi-display@17 must resolve to the EA8074 panel node.
    resolves = normalize_fdt_path(display.get("qcom_dsi_panel_resolves_to"))
    panel_path = normalize_fdt_path((doc.get("panel") or {}).get("fdt_path"))
    if resolves is not None and panel_path is not None and resolves != panel_path:
        report.error(
            f"[phandle.panel_resolution] display_node.qcom_dsi_panel_resolves_to ({resolves}) != panel.fdt_path ({panel_path})"
        )
    if display.get("qcom_display_type") != "primary":
        report.error(f"[phandle.display_type] qcom_display_type is {display.get('qcom_display_type')!r}, expected 'primary'")
    report.mark("phandle_links")


def _check_pinctrl(doc: dict, report: Report) -> None:
    states = _get(doc, "pinctrl_states", report, default={}) or {}
    display = _get(doc, "display_node", report, default={}) or {}
    expected = ["sde_dsi_active", "sde_dsi_suspend", "sde_te_active", "sde_te_suspend"]
    for name in expected:
        if name not in states:
            report.error(f"[pinctrl] pinctrl_states.{name} is missing")

    for name in expected:
        state = states.get(name)
        if not isinstance(state, dict):
            continue
        mux_pins = (state.get("mux") or {}).get("pins")
        cfg_pins = (state.get("config") or {}).get("pins")
        if not mux_pins or not cfg_pins:
            report.error(f"[pinctrl.{name}] mux.pins / config.pins missing")
            continue
        if sorted(mux_pins) != sorted(cfg_pins):
            report.error(f"[pinctrl.{name}] mux.pins {mux_pins} != config.pins {cfg_pins}")
        if name.startswith("sde_te") and list(mux_pins) != ["gpio10"]:
            report.error(f"[pinctrl.{name}] TE state pins are {mux_pins}, expected ['gpio10']")
        if name.startswith("sde_dsi"):
            if "gpio75" not in mux_pins:
                report.error(f"[pinctrl.{name}] reset pin gpio75 is missing from {mux_pins}")
            if "gpio76" not in mux_pins:
                report.error(f"[pinctrl.{name}] expected the shared gpio76 pinctrl line in {mux_pins}")

    # display_node pinctrl lists must point at the recorded states.
    for idx, key in ((0, "pinctrl_0_panel_active"), (1, "pinctrl_1_panel_suspend")):
        paths = display.get(key)
        if not isinstance(paths, list) or len(paths) != 2:
            report.error(f"[pinctrl.link] display_node.{key} must list 2 paths, got {paths!r}")
            continue
        for path in paths:
            base = normalize_fdt_path(path).rsplit("/", 1)[-1]
            if base not in states:
                report.error(f"[pinctrl.link] display_node.{key} references {path!r} which is not a recorded pinctrl state")
    names = display.get("pinctrl_names")
    if names != ["panel_active", "panel_suspend"]:
        report.error(f"[pinctrl.names] display_node.pinctrl_names is {names!r}")

    # Source-scoped difference, deliberately NOT an error: the local mainline
    # DTS pins only gpio75 while the vendor FDT / downstream dtsi state is
    # shared with the nt35597 panels and therefore also carries gpio76.
    src = None
    for entry in doc.get("sources") or []:
        if isinstance(entry, dict) and entry.get("id") == "local_mainline_dts":
            src = entry
    if src:
        lines = src.get("observed_lines") or {}
        blob = " ".join(str(v) for v in lines.values())
        if "gpio75" in blob and "gpio76" not in blob:
            report.note(
                "[pinctrl.source_scope] local mainline DTS pinctrl lists gpio75 only, while the vendor "
                "sde_dsi_* states also carry gpio76 (shared with nt35597). Different sources, not a "
                "contradiction - it is the documented subject of blocker B1."
            )
    report.mark("pinctrl")


def _check_panel(doc: dict, report: Report) -> None:
    panel = _get(doc, "panel", report, default={}) or {}
    phandles = _get(doc, "phandles", report, default={}) or {}

    if panel.get("qcom_mdss_dsi_panel_type") != PINNED_PANEL_TYPE:
        report.error(
            f"[panel.type] panel type is {panel.get('qcom_mdss_dsi_panel_type')!r}, expected {PINNED_PANEL_TYPE!r}"
        )
    if panel.get("qcom_mdss_dsi_bpp") != PINNED_BPP:
        report.error(f"[panel.bpp] bpp is {panel.get('qcom_mdss_dsi_bpp')}, expected {PINNED_BPP}")
    if panel.get("lane_count") != len(PINNED_LANES):
        report.error(f"[panel.lanes] lane_count is {panel.get('lane_count')}, expected {len(PINNED_LANES)}")
    if panel.get("lanes_active") != PINNED_LANES:
        report.error(f"[panel.lanes] lanes_active is {panel.get('lanes_active')}, expected {PINNED_LANES}")
    if panel.get("qcom_mdss_dsi_virtual_channel_id") != 0:
        report.error(f"[panel.vc] panel virtual channel id is {panel.get('qcom_mdss_dsi_virtual_channel_id')}, expected 0")

    # TE: qcom,mdss-dsi-te-dcs-command is a u32 SCALAR, never a byte array.
    te = _get(doc, "panel.te", report, default={}) or {}
    te_dcs = te.get("qcom_mdss_dsi_te_dcs_command")
    if isinstance(te_dcs, bool) or not isinstance(te_dcs, int):
        report.error(
            f"[te.scalar] qcom_mdss_dsi_te_dcs_command must be a u32 scalar int, got "
            f"{type(te_dcs).__name__} {te_dcs!r}"
        )
    elif te_dcs != PINNED_TE_DCS_COMMAND:
        report.error(f"[te.scalar] qcom_mdss_dsi_te_dcs_command is {te_dcs}, expected {PINNED_TE_DCS_COMMAND}")
    if te.get("qcom_mdss_dsi_te_pin_select") != 1:
        report.error(f"[te.pin] te_pin_select is {te.get('qcom_mdss_dsi_te_pin_select')}, expected 1")
    if te.get("qcom_mdss_dsi_te_using_te_pin") is not True:
        report.error("[te.pin] qcom_mdss_dsi_te_using_te_pin is not true")

    # Reset waveform.
    reset = _get(doc, "panel.reset_sequence", report, default={}) or {}
    raw = reset.get("raw_hex")
    if isinstance(raw, str):
        compacted = re.sub(r"\s+", "", raw)
        if len(compacted) != 32:
            report.error(f"[reset.raw] reset_sequence.raw_hex is {len(compacted) // 2} bytes, expected 16 (4 x u32)")
        else:
            words = [int.from_bytes(bytes.fromhex(compacted)[i : i + 4], "big") for i in (0, 4, 8, 12)]
            if words != [0, 2, 1, 11]:
                report.error(f"[reset.raw] reset_sequence.raw_hex decodes to {words}, expected [0, 2, 1, 11]")
    if reset.get("pairs_value_delay_ms") != PINNED_RESET_PAIRS:
        report.error(
            f"[reset.pairs] reset pairs are {reset.get('pairs_value_delay_ms')!r}, expected {PINNED_RESET_PAIRS!r}"
        )
    if reset.get("qcom_platform_reset_gpio_dt_flag") != 0:
        report.error("[reset.flag] reset gpio DT flag is not 0")
    cross = reset.get("mainline_convention_cross_check") or {}
    if cross.get("matches_vendor_physical_sequence") is not True:
        report.error(
            "[reset.waveform] reset_sequence.mainline_convention_cross_check."
            "matches_vendor_physical_sequence is not true"
        )
    if "GPIO_ACTIVE_LOW" not in str(cross.get("dt_binding_used", "")):
        report.error("[reset.cross_check] mainline cross-check does not use a GPIO_ACTIVE_LOW reset binding")

    # Reset / TE GPIO identity on dsi-display@17.
    display = doc.get("display_node") or {}
    r_gpio = display.get("qcom_platform_reset_gpio") or {}
    if r_gpio.get("gpio") != PINNED_RESET_GPIO:
        report.error(f"[gpio.reset] platform-reset-gpio is {r_gpio.get('gpio')}, expected {PINNED_RESET_GPIO}")
    if r_gpio.get("flag") != 0:
        report.error(f"[gpio.reset] platform-reset-gpio flag is {r_gpio.get('flag')}, expected 0")
    if r_gpio.get("phandle") != PINNED_TLMM_PHANDLE and r_gpio.get("phandle") is not None:
        report.error(f"[gpio.reset] platform-reset-gpio phandle is {r_gpio.get('phandle')}, expected {PINNED_TLMM_PHANDLE}")
    t_gpio = display.get("qcom_platform_te_gpio") or {}
    if t_gpio.get("gpio") != PINNED_TE_GPIO:
        report.error(f"[gpio.te] platform-te-gpio is {t_gpio.get('gpio')}, expected {PINNED_TE_GPIO}")
    if t_gpio.get("flag") != 0:
        report.error(f"[gpio.te] platform-te-gpio flag is {t_gpio.get('flag')}, expected 0")

    en = display.get("qcom_platform_en_gpio") or {}
    if en.get("present") is not False:
        report.error("[gpio.en] qcom,platform-en-gpio must be recorded as absent")

    # Brightness control type and level range.
    bright = _get(doc, "panel.brightness_properties", report, default={}) or {}
    if bright.get("qcom_mdss_dsi_bl_pmic_control_type") != "bl_ctrl_dcs":
        report.error(
            f"[brightness.type] bl_pmic_control_type is {bright.get('qcom_mdss_dsi_bl_pmic_control_type')!r}, expected 'bl_ctrl_dcs'"
        )
    for key, expected in (
        ("qcom_mdss_brightness_max_level", PINNED_BRIGHTNESS_MAX),
        ("qcom_mdss_dsi_bl_max_level", PINNED_BRIGHTNESS_MAX),
        ("qcom_mdss_dsi_bl_min_level", PINNED_BRIGHTNESS_MIN),
    ):
        if bright.get(key) != expected:
            report.error(f"[brightness.range] {key} is {bright.get(key)}, expected {expected}")
    if bright.get("qcom_mdss_dsi_bl_dcs_type_ss") is not True:
        report.error("[brightness.type] qcom_mdss_dsi_bl_dcs_type_ss is not true")

    if phandles.get("panel_mdss_dsi_ss_fhd_ea8074_cmd") is not None and display.get("qcom_dsi_panel_phandle") != phandles.get(
        "panel_mdss_dsi_ss_fhd_ea8074_cmd"
    ):
        report.error("[panel.phandle] panel phandle link disagrees with phandles[]")
    report.mark("panel")


def _check_timing(doc: dict, report: Report) -> None:
    timing = _get(doc, "timing", report, default={}) or {}
    for key, expected in PINNED_TIMING.items():
        observed = timing.get(key)
        if observed != expected:
            report.error(f"[timing.{key}] {key} is {observed}, expected {expected}")
    if timing.get("all_values_match_task_pin") is not True:
        report.error("[timing.pin] all_values_match_task_pin is not true")
    if timing.get("display_topology") != [1, 0, 1]:
        report.error(f"[timing.topology] display_topology is {timing.get('display_topology')!r}, expected [1, 0, 1]")
    if timing.get("default_topology_index") != 0:
        report.error(f"[timing.topology] default_topology_index is {timing.get('default_topology_index')}, expected 0")
    phy = timing.get("qcom_mdss_dsi_panel_phy_timings_hex")
    if not (isinstance(phy, str) and re.fullmatch(r"[0-9a-fA-F]{24}", re.sub(r"\s+", "", phy))):
        report.error(f"[timing.phy] phy timings are not a 12-byte hex blob: {phy!r}")

    t_path = normalize_fdt_path(timing.get("fdt_path"))
    p_path = normalize_fdt_path((doc.get("panel") or {}).get("fdt_path"))
    if isinstance(t_path, str) and isinstance(p_path, str) and not t_path.startswith(p_path + "/"):
        report.error(f"[timing.path] timing fdt_path {t_path!r} is not under panel path {p_path!r}")
    report.mark("timing")


def _check_commands(doc: dict, report: Report) -> dict:
    init = _get(doc, "init_commands", report, default={}) or {}
    fmt = init.get("record_format") or {}
    if fmt.get("header_bytes") != HEADER_BYTES:
        report.error(f"[cmds.format] record_format.header_bytes is {fmt.get('header_bytes')}, expected {HEADER_BYTES}")
    if fmt.get("fields") != RECORD_FIELDS:
        report.error(f"[cmds.format] record_format.fields is {fmt.get('fields')!r}, expected {RECORD_FIELDS!r}")

    parsed: dict = {}
    for name in ("on", "off"):
        arr = init.get(name)
        if not isinstance(arr, dict):
            report.error(f"[cmds.{name}] init_commands.{name} is missing")
            continue
        hexs = arr.get("bytes_hex")
        try:
            records = parse_records(hexs, context=f"init_commands.{name}.bytes_hex")
        except RecordParseError as exc:
            report.error(f"[cmds.{name}.parse] {exc}")
            continue
        parsed[name] = records

        size = len(bytes.fromhex(re.sub(r"\s+", "", hexs)))
        if size != arr.get("length_bytes"):
            report.error(f"[cmds.{name}.length] length_bytes is {arr.get('length_bytes')}, parsed {size}")
        if len(records) != arr.get("record_count"):
            report.error(f"[cmds.{name}.count] record_count is {arr.get('record_count')}, parsed {len(records)}")
        if arr.get("parser_consumed_all_bytes") is not True:
            report.error(f"[cmds.{name}.consumed] parser_consumed_all_bytes is not true")

        # The real digest of the real bytes is the only hash that matters. The
        # truncated/fabricated task_pinned_hash fields are gone for good.
        recomputed = sha256_of_hex(hexs)
        if not is_hex_digest(arr.get("sha256"), 64):
            report.error(f"[hash.{name}] sha256 field is not a 64-hex digest: {arr.get('sha256')!r}")
        elif recomputed != str(arr.get("sha256")).lower():
            report.error(
                f"[hash.{name}] sha256 mismatch: field={arr.get('sha256')}, recomputed-from-bytes={recomputed}"
            )
        if arr.get("sha256_algorithm") != "sha256":
            report.error(
                f"[hash.{name}.algo] sha256_algorithm is {arr.get('sha256_algorithm')!r}, expected 'sha256'"
            )
        if arr.get("sha1_algorithm") != "sha1":
            report.error(f"[hash.{name}.algo] sha1_algorithm is {arr.get('sha1_algorithm')!r}, expected 'sha1'")
        for stale in STALE_HASH_FIELDS:
            if stale in arr:
                report.error(
                    f"[meta.stale_field] init_commands.{name}.{stale} reappeared; that field was a fabricated "
                    "63-character truncation of the SHA-256 and must not be reintroduced"
                )

        # SHA-1 is optional: verify it when present, never fabricate it.
        recorded_sha1 = arr.get("sha1")
        if recorded_sha1 is None:
            report.note(
                f"[hash.{name}.sha1_absent] init_commands.{name} records no sha1 field; none was invented. "
                "The SHA-256 above is the authoritative digest."
            )
        elif not is_hex_digest(recorded_sha1, 40):
            report.error(f"[hash.{name}.sha1] sha1 field is not a 40-hex digest: {recorded_sha1!r}")
        elif sha1_of_hex(hexs) != recorded_sha1:
            report.error(f"[hash.{name}.sha1] sha1 field does not match the SHA-1 of the recorded bytes")

        pin = PINNED.get(name, {})
        if size != pin.get("length_bytes"):
            report.error(f"[pin.{name}.length] parses {size} bytes, task pin says {pin.get('length_bytes')}")
        if len(records) != pin.get("record_count"):
            report.error(f"[pin.{name}.count] parses {len(records)} records, task pin says {pin.get('record_count')}")
        if recomputed != pin.get("sha256"):
            report.error(f"[pin.{name}.sha256] recomputed {recomputed} != task pin {pin.get('sha256')}")

        # Per-record field ranges and DCS payload semantics.
        for rec in records:
            code = f"init_commands.{name} record@{rec.offset}"
            if rec.dtype not in ALLOWED_DTYPES:
                report.error(f"[cmds.type] {code}: data type 0x{rec.dtype:02x}")
            if not 0 <= rec.vc <= MAX_VC:
                report.error(f"[cmds.vc] {code}: vc {rec.vc} out of range")
            if rec.ack not in (0, 1):
                report.error(f"[cmds.ack] {code}: ack {rec.ack} out of range")
            if rec.last not in (0, 1):
                report.error(f"[cmds.last] {code}: last {rec.last} out of range")
            if rec.dtype == 0x39 and len(rec.payload) < 1:
                report.error(f"[cmds.long] {code}: 0x39 long packet has no command byte")
    if parsed:
        report.note(
            "[cmds.parsed] "
            + "; ".join(
                f"{name}: {len(recs)} records over {sum(HEADER_BYTES + r.dlen for r in recs)} bytes "
                f"(types {sorted({'0x%02x' % r.dtype for r in recs})})"
                for name, recs in parsed.items()
            )
        )

    # off_decoded must agree record-for-record with the real off array.
    decoded = init.get("off_decoded")
    off_records = parsed.get("off")
    if isinstance(decoded, list) and off_records is not None:
        if len(decoded) != len(off_records):
            report.error(f"[cmds.off_decoded] off_decoded has {len(decoded)} entries, parsed {len(off_records)} records")
        else:
            for idx, (entry, rec) in enumerate(zip(decoded, off_records)):
                checks = {
                    "dtype": f"0x{rec.dtype:02x}",
                    "last": rec.last,
                    "vc": rec.vc,
                    "ack": rec.ack,
                    "wait_ms": rec.wait_ms,
                    "dlen": rec.dlen,
                    "payload_hex": rec.payload.hex(),
                }
                for field, expected in checks.items():
                    if field in entry and entry[field] != expected:
                        report.error(
                            f"[cmds.off_decoded] off_decoded[{idx}].{field} is {entry[field]!r}, parsed {expected!r}"
                        )
    report.mark("commands")
    return parsed


def _check_brightness_init_write(doc: dict, report: Report, parsed: dict) -> None:
    """Prove the initial DCS 0x51 zero-brightness write from the raw bytes.

    The metadata flag ``dcs_0x51_in_init_sequence`` is only accepted when the
    204-byte on-command array itself contains a 0x39 long write whose payload is
    ``51 00 00``.  The metadata must not be able to deny (or invent) the raw
    decode.
    """
    bright = _get(doc, "panel.brightness_properties", report, default={}) or {}
    on_records = parsed.get("on")
    if on_records is None:
        report.error("[brightness.init_raw] the on-command array could not be parsed; cannot verify the 0x51 write")
        return

    hits = find_dcs_brightness_records(on_records)
    if not hits:
        report.error(
            "[brightness.init_missing] the on-command array contains no 0x39 long write with a 0x51 payload, "
            "but panel.brightness_properties.dcs_0x51_in_init_sequence claims one is present"
        )
        return
    if len(hits) != 1:
        report.error(
            f"[brightness.init_count] the on-command array contains {len(hits)} DCS 0x51 records "
            f"(offsets {[r.offset for r in hits]}), expected exactly 1"
        )
    rec = hits[0]
    if rec.dlen != 3:
        report.error(f"[brightness.init_dlen] the DCS 0x51 record at offset {rec.offset} has dlen {rec.dlen}, expected 3")

    payload = rec.payload
    msb_first = int.from_bytes(payload[1:3], "big") if len(payload) >= 3 else None
    lsb_first = int.from_bytes(payload[1:3], "little") if len(payload) >= 3 else None
    if msb_first != PINNED_INIT_BRIGHTNESS_LEVEL:
        report.error(
            f"[brightness.init_level] the DCS 0x51 record at offset {rec.offset} carries payload "
            f"{payload.hex()} (MSB-first level {msb_first}), expected an initial level of "
            f"{PINNED_INIT_BRIGHTNESS_LEVEL}"
        )

    flag = bright.get("dcs_0x51_in_init_sequence")
    if flag is not True:
        report.error(
            f"[brightness.init_meta] panel.brightness_properties.dcs_0x51_in_init_sequence is {flag!r} while the "
            f"raw on-command bytes contain a 0x39 write of {payload.hex()} at offset {rec.offset}; "
            "the metadata denies what the raw bytes prove"
        )

    note = compact(bright.get("dcs_0x51_note", ""))
    if not note:
        report.error("[brightness.init_note] panel.brightness_properties.dcs_0x51_note is missing")
    else:
        if "zero" not in note:
            report.error(
                "[brightness.init_note] dcs_0x51_note does not state that the in-sequence write zeroes brightness, "
                "which is what the raw payload decodes to"
            )
        if "doze" not in note or not re.search(r"do(?:es)?\s+not\s+treat|not\s+treat", note):
            report.error(
                "[brightness.init_note] dcs_0x51_note must warn against treating a doze LBM value as the normal "
                "initial brightness default"
            )
    report.note(
        f"[brightness.init_verified] independently decoded from init_commands.on.bytes_hex: 0x39 record at offset "
        f"{rec.offset}, payload {payload.hex()} -> DCS 0x51, initial level {msb_first}. Because the level is 0x0000 "
        "the initial write is byte-order agnostic and cannot by itself discriminate MSB- from LSB-first; the wire "
        "order comes from the downstream source derivation, not from this record."
    )
    report.mark("brightness_init_write")


def _check_doze_versus_default(doc: dict, report: Report) -> None:
    """Doze LBM/HBM are not the boot default, and must not be presented as one."""
    bright = _get(doc, "panel.brightness_properties", report, default={}) or {}
    ilb = bright.get("initial_low_brightness")
    if not isinstance(ilb, dict):
        report.error("[brightness.doze] panel.brightness_properties.initial_low_brightness is missing")
        return
    if ilb.get("doze_lbm_level") != PINNED_DOZE_LBM:
        report.error(f"[brightness.doze] doze_lbm_level is {ilb.get('doze_lbm_level')}, expected {PINNED_DOZE_LBM}")
    if ilb.get("doze_hbm_level") != PINNED_DOZE_HBM:
        report.error(f"[brightness.doze] doze_hbm_level is {ilb.get('doze_hbm_level')}, expected {PINNED_DOZE_HBM}")
    src = compact(ilb.get("source", ""))
    if "doze" not in src or "lbm" not in src or "hbm" not in src:
        report.error(
            "[brightness.doze] initial_low_brightness.source does not cite the downstream doze luminance properties"
        )
    note = compact(ilb.get("note", ""))
    if not re.search(r"no\s+initial|no\s+default|not\s+a\s+default|not\s+the\s+default", note):
        report.error(
            "[brightness.doze_default] initial_low_brightness presents the doze LBM/HBM levels without stating that "
            "they are not the boot/default brightness; a doze level must not be mistaken for the normal default"
        )

    # No field may present the doze levels as the boot-time default level.
    for key, value in bright.items():
        if "default" in str(key).lower() and value in (PINNED_DOZE_LBM, PINNED_DOZE_HBM):
            report.error(
                f"[brightness.doze_default] panel.brightness_properties.{key} = {value} reuses a doze level as the "
                "boot default brightness"
            )
    report.mark("doze_versus_default")


def _check_downstream_source(doc: dict, report: Report) -> None:
    """Verify the pinned downstream commit, blob/content hashes and snippets."""
    ev = _get(doc, "downstream_source_evidence", report, default={}) or {}
    if not ev:
        return

    commit = ev.get("commit_full_sha")
    if commit != DOWNSTREAM_COMMIT:
        report.error(f"[source.commit] downstream commit_full_sha is {commit!r}, expected {DOWNSTREAM_COMMIT!r}")
    elif not is_hex_digest(commit, 40):
        report.error(f"[source.commit] downstream commit_full_sha is not a 40-hex sha: {commit!r}")
    if not is_hex_digest(ev.get("commit_full_sha"), 40):
        report.error("[source.commit] downstream commit_full_sha is missing or not a 40-hex sha")
    if ev.get("repo") != DOWNSTREAM_REPO:
        report.error(f"[source.repo] downstream repo is {ev.get('repo')!r}, expected {DOWNSTREAM_REPO!r}")

    files = ev.get("files")
    if not isinstance(files, dict) or not files:
        report.error("[source.files] downstream_source_evidence.files is missing or empty")
        return

    for path in REQUIRED_SOURCE_FILES:
        entry = files.get(path)
        if not isinstance(entry, dict):
            report.error(f"[source.file_missing] pinned file absent from downstream_source_evidence.files: {path}")
            continue
        if not is_hex_digest(entry.get("git_blob_sha1"), 40):
            report.error(
                f"[source.blob_sha1] {path}: git_blob_sha1 is missing or not a 40-hex blob sha: "
                f"{entry.get('git_blob_sha1')!r}"
            )
        if not is_hex_digest(entry.get("content_sha256"), 64):
            report.error(
                f"[source.content_sha256] {path}: content_sha256 is missing or not a 64-hex digest: "
                f"{entry.get('content_sha256')!r}"
            )
        if not source_snippets(doc, path):
            report.error(f"[source.snippets] {path}: no snippets are quoted, so the claim is unbacked")

    # Every load-bearing fact must still be anchored by a quoted snippet.
    for path, label, tokens in REQUIRED_SNIPPETS:
        snippets = source_snippets(doc, path)
        if not any(all(tok in s for tok in tokens) for s in snippets):
            report.error(
                f"[source.snippet] {path}: no quoted snippet supports {label!r} "
                f"(needs all of {list(tokens)!r} in one snippet)"
            )

    # The gating blocker must point at a source that was actually read.
    gh = None
    for entry in doc.get("sources") or []:
        if isinstance(entry, dict) and entry.get("id") == "github_downstream":
            gh = entry
    if gh is None:
        report.warn("[source.github] sources[] has no 'github_downstream' entry")
    else:
        if gh.get("status") == "BLOCKED":
            report.error("[source.github] the downstream source is recorded as BLOCKED but its evidence is used")
        if gh.get("commit_full_sha") != commit:
            report.error(
                f"[source.github] sources[github_downstream].commit_full_sha ({gh.get('commit_full_sha')!r}) != "
                f"downstream_source_evidence.commit_full_sha ({commit!r})"
            )
        read = set(gh.get("files_read") or [])
        for path in REQUIRED_SOURCE_FILES:
            if path not in read:
                report.error(f"[source.github] {path} is quoted as evidence but is not in files_read")
    report.mark("downstream_source")


def _check_brightness_byte_order(doc: dict, report: Report, ctx: dict) -> None:
    """Re-derive the 0x51 wire order from source and check every claim of it."""
    derivation = derive_wire_byte_order(doc)
    ctx["wire_order"] = derivation
    report.derived["wire_byte_order"] = {
        "msb_first": derivation["msb_first"],
        "probe": "0x%04x" % derivation["probe"],
        "payload_hex": derivation["payload_hex"],
        "swap_is_load_bearing": derivation["swap_is_load_bearing"],
    }

    if not derivation["inverted_dbv"]:
        report.error(
            "[byte_order.source] the pinned EA8074 dtsi snippet does not declare qcom,mdss-dsi-bl-inverted-dbv; "
            "without it the swap does not happen and the conclusion changes"
        )
    if not derivation["swap_present"]:
        report.error("[byte_order.source] dsi_panel.c does not show the bl_inverted_dbv u16 byte swap")
    if not derivation["helper_little_endian"]:
        report.error(
            "[byte_order.source] drm_mipi_dsi.c does not show mipi_dsi_dcs_set_display_brightness() packing "
            "{ brightness & 0xff, brightness >> 8 } little-endian"
        )
    if not derivation["msb_first"]:
        report.error(
            f"[byte_order.wire_order] the derived DCS 0x51 payload for probe 0x{derivation['probe']:04x} is "
            f"{derivation['payload_hex']}, which is LSB-first; the EA8074 wire order must be MSB-first"
        )
    if not derivation["swap_is_load_bearing"]:
        report.error(
            "[byte_order.derivation] the inverted-dbv swap does not change the emitted payload, so the "
            "'swap and little-endian packing cancel into MSB-first' derivation is not demonstrated"
        )
    if derivation["msb_first"] and derivation["without_swap_hex"]:
        report.note(
            "[byte_order.derived] probe 0x%04x -> payload %s (MSB-first). Without the inverted-dbv swap the same "
            "panel would emit %s (LSB-first), so the swap is load-bearing."
            % (derivation["probe"], derivation["payload_hex"], derivation["without_swap_hex"])
        )

    # The metadata must claim the same order that was just derived.
    bright = _get(doc, "panel.brightness_properties", report, default={}) or {}
    encoding = compact(bright.get("level_encoding", ""))
    if not encoding:
        report.error("[byte_order.meta] panel.brightness_properties.level_encoding is missing")
    else:
        if not re.search(r"1\s*\.\.\s*1023", encoding):
            report.error(f"[byte_order.meta] level_encoding does not state the 1..1023 range: {encoding!r}")
        if not MSB_FIRST_PHRASE.search(encoding):
            report.error(
                "[byte_order.meta] level_encoding does not state that the most significant byte is sent first, "
                "which is what the source derivation produces"
            )
        if LSB_FIRST_PHRASE.search(encoding):
            report.error(
                "[byte_order.meta] level_encoding states the reversed (least-significant-byte-first) wire order"
            )

    # The resolution must be recorded, and must not rest on a different panel.
    resolved_item = None
    for item in doc.get("resolved") or []:
        if isinstance(item, dict) and "0x51" in str(item.get("item", "")) and "byte order" in str(item.get("item", "")):
            resolved_item = item
    if resolved_item is None:
        report.error("[byte_order.resolved] no resolved[] item records the EA8074 DCS 0x51 byte order")
    else:
        if resolved_item.get("status") != "resolved":
            report.error(f"[byte_order.resolved] the 0x51 item status is {resolved_item.get('status')!r}, expected 'resolved'")
        if resolved_item.get("must_not_guess") is not False:
            report.error(
                "[byte_order.resolved] the 0x51 item is still marked must_not_guess; it cannot be treated as resolved"
            )
        detail = compact(resolved_item.get("detail", ""))
        if DOWNSTREAM_COMMIT not in detail:
            report.error(f"[byte_order.resolved] the 0x51 item does not cite the pinned commit {DOWNSTREAM_COMMIT}")
        if "inverted-dbv" not in detail and "inverted_dbv" not in detail:
            report.error("[byte_order.resolved] the 0x51 item does not cite qcom,mdss-dsi-bl-inverted-dbv")

    # The derivation must be EA8074-specific and must exclude the wrong sources.
    not_used = (doc.get("downstream_source_evidence") or {}).get("explicitly_not_used_as_byte_order_evidence")
    if not isinstance(not_used, list) or not not_used:
        report.error(
            "[byte_order.not_used] downstream_source_evidence.explicitly_not_used_as_byte_order_evidence is missing; "
            "the non-EA8074 helpers must be excluded explicitly"
        )
    else:
        blob = compact(" ".join(str(x) for x in not_used))
        for token in NOT_BYTE_ORDER_EVIDENCE:
            if token not in blob:
                report.error(
                    f"[byte_order.not_used] {token!r} is not listed as excluded from the byte-order derivation"
                )
    conclusion = compact((doc.get("downstream_source_evidence") or {}).get("byte_order_conclusion", ""))
    if not MSB_FIRST_PHRASE.search(conclusion):
        report.error(
            "[byte_order.conclusion] byte_order_conclusion does not state the derived MSB-then-LSB wire order"
        )
    if LSB_FIRST_PHRASE.search(conclusion):
        report.error("[byte_order.conclusion] byte_order_conclusion states the reversed (LSB-first) wire order")
    for banned in ("dcs-type-ss", "dcs_type_ss", "ams639rq08", "_large"):
        if banned in conclusion:
            report.error(
                f"[byte_order.conclusion] byte_order_conclusion cites {banned!r}, which is not EA8074 byte-order evidence"
            )

    # BL dcs-type-ss semantics stay unknown and must not be used as evidence.
    semantics = compact(bright.get("qcom_mdss_dsi_bl_dcs_type_ss_semantics", ""))
    if "not resolvable" not in semantics and "unresolved" not in semantics:
        report.error(
            "[byte_order.dcs_type_ss] qcom_mdss_dsi_bl_dcs_type_ss_semantics must record that this property's "
            "behaviour is not resolvable from the available source"
        )
    if "inverted-dbv" not in semantics and "inverted_dbv" not in semantics:
        report.error(
            "[byte_order.dcs_type_ss] the dcs-type-ss note must point at qcom,mdss-dsi-bl-inverted-dbv as the "
            "actual byte-order evidence"
        )
    dcs_ss_unresolved = any(
        isinstance(u, dict) and "dcs-type-ss" in str(u.get("item", "")) for u in (doc.get("unresolved") or [])
    )
    if not dcs_ss_unresolved:
        report.error("[byte_order.dcs_type_ss] no unresolved[] item records the dcs-type-ss semantics as open")
    report.mark("brightness_byte_order")


def _check_power(doc: dict, report: Report, ctx: dict) -> None:
    power = _get(doc, "power", report, default={}) or {}
    entries_block = _get(doc, "power.panel_supply_entries", report, default={}) or {}
    entries = entries_block.get("entries")
    if not isinstance(entries, list):
        report.error("[power.entries] panel_supply_entries.entries is missing")
        entries = []
    if entries_block.get("entry_count") != len(entries):
        report.error(
            f"[power.entries] entry_count is {entries_block.get('entry_count')}, entries[] has {len(entries)}"
        )
    if len(entries) != PINNED_SUPPLY_ENTRY_COUNT:
        report.error(
            f"[power.entries] {len(entries)} supply entries present, the vendor EA8074 panel has exactly "
            f"{PINNED_SUPPLY_ENTRY_COUNT} (vddio 1.8 V, vci 3.0 V)"
        )

    seen_regs = []
    for entry in entries:
        if not isinstance(entry, dict):
            report.error(f"[power.entries] entry is not an object: {entry!r}")
            continue
        reg = entry.get("reg")
        seen_regs.append(reg)
        name = str(entry.get("qcom_supply_name", "")).lower()
        lo, hi = entry.get("min_uv"), entry.get("max_uv")
        expected = PINNED_SUPPLY_UV.get(reg)
        label = expected[0] if expected else (name or f"reg{reg}")
        if expected is None:
            report.error(f"[power.entries] unexpected supply entry reg={reg!r} ({entry.get('qcom_supply_name')!r})")
        else:
            exp_name, exp_uv = expected
            if name != exp_name:
                report.error(f"[power.entries] reg {reg} is named {entry.get('qcom_supply_name')!r}, expected {exp_name!r}")
            if lo != exp_uv or hi != exp_uv:
                report.error(
                    f"[power.entries] reg {reg} ({exp_name}) is {lo}..{hi} uV, expected a fixed {exp_uv} uV"
                )
        for banned in FORBIDDEN_RAIL_NAMES:
            if banned in name:
                report.error(
                    f"[power.forbidden] supply entry reg {reg} enables the {banned.upper()} rail; LAB/IBB are "
                    "referenced by dsi-display@17 but are NOT part of qcom,panel-supply-entries"
                )
        for banned_uv in FORBIDDEN_UV:
            if lo == banned_uv or hi == banned_uv:
                report.error(
                    f"[power.forbidden] supply entry reg {reg} ({label}) carries "
                    f"{banned_uv / 1_000_000:.1f} V; there is no 3.3 V rail in the vendor panel supply entries"
                )
    if sorted(r for r in seen_regs if isinstance(r, int)) != [0, 1]:
        report.error(f"[power.entries] supply entry regs are {seen_regs}, expected [0, 1]")

    vci_entry = next((e for e in entries if isinstance(e, dict) and e.get("reg") == 1), {}) or {}
    if vci_entry.get("post_on_sleep_ms") != PINNED_INTER_RAIL_SLEEP_MS or vci_entry.get("pre_off_sleep_ms") != PINNED_INTER_RAIL_SLEEP_MS:
        report.error(
            f"[power.vci_delay] vci sleeps are post_on={vci_entry.get('post_on_sleep_ms')} "
            f"pre_off={vci_entry.get('pre_off_sleep_ms')}, expected {PINNED_INTER_RAIL_SLEEP_MS} / "
            f"{PINNED_INTER_RAIL_SLEEP_MS}"
        )

    # VDDIO rail = PM660L L11 at 1.8 V.
    vddio = _get(doc, "power.vddio_rail", report, default={}) or {}
    if vddio.get("voltage_uv") != 1_800_000:
        report.error(f"[power.vddio] vddio rail voltage is {vddio.get('voltage_uv')}, expected 1800000")
    if "pm660-l11" not in str(vddio.get("fdt_node", "")):
        report.error(f"[power.vddio] vddio fdt_node is {vddio.get('fdt_node')!r}, expected the PM660L L11 regulator")
    if (vddio.get("live_sysfs") or {}).get("microvolts") != 1_800_000:
        report.error("[power.vddio] live sysfs microvolts for the vddio rail is not 1800000")

    # VCI rail = fixed regulator on tlmm GPIO5, active high, boot on.
    vci = _get(doc, "power.vci_rail", report, default={}) or {}
    if vci.get("gpio") != PINNED_VCI_GPIO:
        report.error(
            f"[power.vci] vci enable gpio is {vci.get('gpio')}, expected {PINNED_VCI_GPIO}. "
            "GPIO76 is a dual-DSI mode-select line for nt35597 panels and must not be used as the VCI enable"
        )
    if vci.get("gpio_flag") != 0:
        report.error(f"[power.vci] vci gpio flag is {vci.get('gpio_flag')}, expected 0")
    if vci.get("enable_active_high") is not True:
        report.error("[power.vci] enable_active_high is not true")
    if vci.get("regulator_boot_on") is not True:
        report.error("[power.vci] regulator_boot_on is not true")
    if vci.get("start_delay_us") != 4000:
        report.error(f"[power.vci] start_delay_us is {vci.get('start_delay_us')}, expected 4000")
    if vci.get("has_min_max_microvolt_properties") is not False:
        report.error("[power.vci] has_min_max_microvolt_properties is not false for this regulator-fixed")
    if vci.get("voltage_uv_from_panel_supply_entry") != 3_000_000:
        report.error(
            f"[power.vci] voltage_uv_from_panel_supply_entry is {vci.get('voltage_uv_from_panel_supply_entry')}, expected 3000000"
        )
    if vci.get("compatible") != "regulator-fixed":
        report.error(f"[power.vci] vci compatible is {vci.get('compatible')!r}, expected 'regulator-fixed'")

    # The vendor start-delay-us has no consumer; fixed.c only reads startup-delay-us.
    fixed_snippets = snippets_blob(doc, FIXED_C)
    fixed_conclusion = compact((((doc.get("downstream_source_evidence") or {}).get("files") or {}).get(FIXED_C) or {}).get("conclusion", ""))
    if "startup-delay-us" not in fixed_snippets:
        report.error("[power.fixed_delay] fixed.c snippet does not show the read of startup-delay-us")
    if "start-delay-us" in fixed_snippets:
        report.error(
            "[power.fixed_delay] a fixed.c snippet appears to read start-delay-us; only startup-delay-us is consumed"
        )
    if "not start-delay-us" not in fixed_conclusion:
        report.error(
            "[power.fixed_delay] the fixed.c conclusion does not state that startup-delay-us (not start-delay-us) "
            "is what the driver reads"
        )
    delay_item = None
    for item in doc.get("resolved") or []:
        if isinstance(item, dict) and "delay property" in str(item.get("item", "")):
            delay_item = item
    if delay_item is None:
        report.error("[power.fixed_delay] no resolved[] item records the GPIO5 fixed-regulator delay property")
    elif "inert" not in compact(delay_item.get("detail", "")):
        report.error(
            "[power.fixed_delay] the fixed-regulator delay item does not record that the vendor delay is inert"
        )

    # GPIO5 vs GPIO76 role resolution.
    roles = doc.get("gpio_role_resolution") or {}
    g5 = roles.get("gpio5") or {}
    g76 = roles.get("gpio76") or {}
    if g5.get("gpio") != PINNED_VCI_GPIO:
        report.error(f"[gpio.role] gpio_role_resolution.gpio5.gpio is {g5.get('gpio')}, expected 5")
    if g5.get("enable_active_high") is not True or g5.get("regulator_boot_on") is not True:
        report.error("[gpio.role] gpio5 must be enable-active-high and regulator-boot-on")
    # gpio76 carries no scalar 'gpio' field: its line number is only in the
    # raw_hex_where_bound blob, so it must be cross-checked through the decode.
    triplets_seen = ctx.get("triplets", {})
    g5_dec = triplets_seen.get("gpio_role_resolution.gpio5")
    g76_dec = triplets_seen.get("gpio_role_resolution.gpio76")
    if g5_dec and g5_dec[1] != PINNED_VCI_GPIO:
        report.error(f"[gpio.role] gpio5 raw_hex decodes to line {g5_dec[1]}, expected {PINNED_VCI_GPIO}")
    if g76_dec and g76_dec[1] != 76:
        report.error(f"[gpio.role] gpio76 raw_hex_where_bound decodes to line {g76_dec[1]}, expected 76")
    elif not g76_dec:
        report.error("[gpio.role] gpio76 raw_hex_where_bound could not be decoded")
    if g76.get("bound_on_ea8074_nodes") is not False:
        report.error("[gpio.role] gpio76 must not be recorded as bound on EA8074 nodes")
    if "qcom,panel-mode-gpio" not in str(g76.get("property_that_binds_it", "")):
        report.error("[gpio.role] gpio76 must be recorded as bound through qcom,panel-mode-gpio")

    # LAB/IBB must stay out of the required supply set.
    lab_ibb = _get(doc, "power.lab_ibb", report, default={}) or {}
    if lab_ibb.get("in_panel_supply_entries") is not False:
        report.error("[power.lab_ibb] lab_ibb.in_panel_supply_entries is not false")
    if lab_ibb.get("referenced_by_dsi_display_17") is not True:
        report.warn("[power.lab_ibb] lab_ibb.referenced_by_dsi_display_17 is not recorded as true")

    discrepancies = power.get("mainline_discrepancies") or []
    if len(discrepancies) < 2:
        report.warn(f"[power.discrepancies] {len(discrepancies)} mainline discrepancy record(s) present")
    blob = json.dumps(discrepancies)
    if "76" not in blob:
        report.warn("[power.discrepancies] the GPIO76-vs-GPIO5 mainline conflict is not documented")
    if "3.3" not in blob:
        report.warn("[power.discrepancies] the unsupported 3.3 V rail is not documented")

    # Enable/disable sequence, derived from dsi_pwr.c + the supply table.
    seq = derive_power_sequence(doc)
    ctx["power_sequence"] = seq
    report.derived["power_sequence"] = {
        "enable": seq["enable"],
        "disable": seq["disable"],
        "enable_trailing_sleep_ms": seq["enable_trailing_sleep_ms"],
        "disable_leading_sleep_ms": seq["disable_leading_sleep_ms"],
    }
    if not seq["forward_loop"]:
        report.error("[power.sequence] dsi_pwr.c does not show the forward enable loop over the supply table")
    if not seq["reverse_loop"]:
        report.error("[power.sequence] dsi_pwr.c does not show the reverse disable loop over the supply table")
    if seq["enable"] != PINNED_ENABLE_ORDER:
        report.error(
            f"[power.sequence] derived enable order is {seq['enable']}, expected {PINNED_ENABLE_ORDER} "
            "(vddio then vci)"
        )
    if seq["disable"] != PINNED_DISABLE_ORDER:
        report.error(
            f"[power.sequence] derived disable order is {seq['disable']}, expected {PINNED_DISABLE_ORDER} "
            "(vci then vddio)"
        )
    if seq["enable_trailing_sleep_ms"] != PINNED_INTER_RAIL_SLEEP_MS:
        report.error(
            f"[power.sequence] the trailing post-on sleep after {PINNED_ENABLE_ORDER[-1]} is "
            f"{seq['enable_trailing_sleep_ms']} ms, expected {PINNED_INTER_RAIL_SLEEP_MS} ms"
        )
    if seq["disable_leading_sleep_ms"] != PINNED_INTER_RAIL_SLEEP_MS:
        report.error(
            f"[power.sequence] the leading pre-off sleep before {PINNED_DISABLE_ORDER[0]} is "
            f"{seq['disable_leading_sleep_ms']} ms, expected {PINNED_INTER_RAIL_SLEEP_MS} ms"
        )

    # The recorded resolution must state the derived sequence.
    order_item = None
    for item in doc.get("resolved") or []:
        if isinstance(item, dict) and "order" in str(item.get("item", "")).lower() and "rail" in str(item.get("item", "")).lower():
            order_item = item
    if order_item is None:
        report.error("[power.sequence] no resolved[] item records the rail enable/disable ORDER")
    else:
        if order_item.get("status") != "resolved":
            report.error(f"[power.sequence] the rail ORDER item status is {order_item.get('status')!r}, expected 'resolved'")
        detail = compact(order_item.get("detail", ""))
        if DOWNSTREAM_COMMIT not in detail:
            report.error(f"[power.sequence] the rail ORDER item does not cite the pinned commit {DOWNSTREAM_COMMIT}")
        if not re.search(r"enable[^.]*vddio[^.]*vci", detail):
            report.error("[power.sequence] the rail ORDER item does not state the derived enable sequence vddio -> vci")
        if not re.search(r"disable[^.]*vci[^.]*vddio", detail):
            report.error("[power.sequence] the rail ORDER item does not state the derived disable sequence vci -> vddio")
        if re.search(r"enable[^.]*vci[^.]*vddio", detail) or re.search(r"disable[^.]*vddio[^.]*vci", detail):
            report.error(
                "[power.sequence] the rail ORDER item states an enable/disable sequence opposite to the one derived "
                "from dsi_pwr.c"
            )
    report.mark("power")


def _check_reset_evidence(doc: dict, report: Report) -> None:
    """The reset waveform claim must be anchored in the pinned source."""
    panel_snippets = snippets_blob(doc, DSI_PANEL_C)
    if "qcom,platform-reset-gpio" not in panel_snippets:
        report.error("[reset.source] dsi_panel.c does not show how the reset gpio is acquired")
    if "gpio_set_value(reset_gpio" not in panel_snippets:
        report.error(
            "[reset.source] dsi_panel.c does not show the reset line being driven with the raw sequence levels "
            "through legacy gpio_set_value(), so the physical-level mapping is not backed"
        )
    if "qcom,mdss-dsi-reset-sequence" not in snippets_blob(doc, DTSI_EA8074):
        report.error("[reset.source] the EA8074 dtsi snippet does not carry qcom,mdss-dsi-reset-sequence")

    candidates = [
        entry
        for entry in (doc.get("resolved") or [])
        if isinstance(entry, dict)
        and "reset" in str(entry.get("item", "")).lower()
        and "waveform" in str(entry.get("item", "")).lower()
    ]
    if not candidates:
        report.error("[reset.source] no resolved[] item records the reset GPIO physical waveform")
    else:
        # Order-independent: ANY resolved item may carry the claim, but at least
        # one must state both the vendor sequence and the ACTIVE_LOW encoding.
        satisfied = False
        for entry in candidates:
            if entry.get("status") != "resolved":
                continue
            detail = compact(entry.get("detail", ""))
            if "<0 2>" in detail and "<1 11>" in detail and "gpio_active_low" in detail:
                satisfied = True
                break
        if not satisfied:
            report.error(
                "[reset.source] no resolved reset-waveform item states both the vendor <0 2> / <1 11> sequence and "
                "the ACTIVE_LOW mainline encoding"
            )
    report.mark("reset_evidence")


def _check_hash_metadata(doc: dict, report: Report) -> None:
    """The fabricated pin/truncation narrative must stay gone."""
    for stale in STALE_TOP_LEVEL_FIELDS:
        if stale in doc:
            report.error(
                f"[meta.stale_field] {stale} reappeared; the previous version of that note described the same "
                "digest as both 64 and 63 characters, and it was removed deliberately"
            )
    report.note(
        "[meta.hash_algo] the per-array sha256 fields are verified by re-hashing the real bytes_hex; no truncated "
        "or fabricated 63-character pin field is used or required, and no missing digest digits were invented."
    )
    report.mark("hash_metadata")


def _evidence_criteria(doc: dict, ctx: dict) -> list:
    """The three bring-up evidence criteria, each re-checked against raw data.

    Returns the list of criteria that are NOT satisfied.  An empty list means
    the evidence itself is complete -- which is a different question from
    whether the DTS is ready to run.
    """
    unmet: list = []

    # 1. supply / enable GPIO identity
    power = doc.get("power") or {}
    vci = power.get("vci_rail") or {}
    entries = (power.get("panel_supply_entries") or {}).get("entries") or []
    names = [str(e.get("qcom_supply_name")) for e in entries if isinstance(e, dict)]
    if vci.get("gpio") != PINNED_VCI_GPIO or vci.get("enable_active_high") is not True:
        unmet.append("supply/enable GPIO identity: the 3.0 V rail is not confirmed on tlmm GPIO5, active high")
    if names != [PINNED_SUPPLY_UV[0][0], PINNED_SUPPLY_UV[1][0]]:
        unmet.append(f"supply/enable GPIO identity: the supply table names are {names}, expected ['vddio', 'vci']")

    # 2. level and ordering sequence
    reset = (doc.get("panel") or {}).get("reset_sequence") or {}
    seq = ctx.get("power_sequence") or derive_power_sequence(doc)
    panel_snippets = snippets_blob(doc, DSI_PANEL_C)
    if reset.get("pairs_value_delay_ms") != PINNED_RESET_PAIRS or reset.get("qcom_platform_reset_gpio_dt_flag") != 0:
        unmet.append("level/ordering: the vendor reset sequence <0 2>, <1 11> with DT flag 0 is not recorded")
    if "gpio_set_value(reset_gpio" not in panel_snippets:
        unmet.append("level/ordering: the reset raw-level drive is not backed by a pinned snippet")
    if seq.get("enable") != PINNED_ENABLE_ORDER or seq.get("disable") != PINNED_DISABLE_ORDER:
        unmet.append(
            f"level/ordering: derived enable {seq.get('enable')} / disable {seq.get('disable')} do not match "
            f"{PINNED_ENABLE_ORDER} / {PINNED_DISABLE_ORDER}"
        )
    if seq.get("enable_trailing_sleep_ms") != PINNED_INTER_RAIL_SLEEP_MS:
        unmet.append("level/ordering: the inter-rail post-on sleep is not confirmed at 10 ms")

    # 3. brightness wire byte order
    wire = ctx.get("wire_order") or derive_wire_byte_order(doc)
    if not wire.get("msb_first"):
        unmet.append("brightness byte order: the EA8074 source derivation does not yield MSB-first")
    if not wire.get("swap_is_load_bearing"):
        unmet.append("brightness byte order: the inverted-dbv swap derivation is not demonstrated")
    return unmet


def _collect_hardware_blockers(doc: dict) -> list:
    """Declared high/medium blockers that are still open."""
    blockers: list = []
    for entry in doc.get("blockers") or []:
        if not isinstance(entry, dict):
            continue
        severity = str(entry.get("severity", "")).lower()
        if severity not in GATING_SEVERITIES:
            continue
        if entry.get("still_open") is False:
            continue
        blockers.append(
            f"{entry.get('id', '?')} ({severity}): {entry.get('item', '')} "
            f"-> required_action: {entry.get('required_action', '')}"
        )
    return blockers


def _check_hardware_gate(doc: dict, report: Report, ctx: dict) -> None:
    declared = doc.get("hardware_test_ready")
    report.hardware_declared_ready = declared
    if not isinstance(declared, bool):
        report.error(f"[gate.flag] hardware_test_ready must be a boolean, got {declared!r}")

    report.hardware_blockers = _collect_hardware_blockers(doc)
    report.evidence_criteria_unmet = _evidence_criteria(doc, ctx)

    non_gating = [
        f"{b.get('id')} ({b.get('severity')}): {b.get('item')}"
        for b in (doc.get("blockers") or [])
        if isinstance(b, dict) and str(b.get("severity", "")).lower() not in GATING_SEVERITIES
    ]
    if non_gating:
        report.note(
            "[gate.non_gating] recorded but non-gating blocker(s): "
            + "; ".join(non_gating)
            + " -- listed for transparency, not counted against hardware readiness"
        )

    if declared is True:
        # The flag is checked against the evidence, never trusted.
        if report.hardware_blockers:
            report.error(
                "[gate.forged] hardware_test_ready is true while "
                f"{len(report.hardware_blockers)} blocker(s) are still open: "
                + "; ".join(report.hardware_blockers)
            )
        if report.evidence_criteria_unmet:
            report.error(
                "[gate.forged_evidence] hardware_test_ready is true while evidence criteria are unmet: "
                + "; ".join(report.evidence_criteria_unmet)
            )
    else:
        if not report.hardware_blockers:
            report.error(
                "[gate.empty] hardware_test_ready is false but no open high/medium blocker explains why"
            )
        reason = doc.get("hardware_test_ready_reason")
        if not (isinstance(reason, str) and reason.strip()):
            report.error("[gate.reason] hardware_test_ready is false but no reason is recorded")
        elif not re.search(r"device tree|dts/", compact(reason)):
            report.error(
                "[gate.reason] the not-ready reason does not name the device tree that still blocks bring-up; "
                "the concrete blocker must be stated"
            )
        if report.evidence_criteria_unmet:
            report.note(
                "[gate.evidence] the gate is also held closed on evidence grounds: "
                + "; ".join(report.evidence_criteria_unmet)
            )
        else:
            report.note(
                "[gate.evidence] all three evidence criteria are satisfied from the pinned source; the gate is "
                "held closed only by the still-open device-tree blocker(s), not by missing evidence"
            )
    report.mark("hardware_gate")


# --------------------------------------------------------------------------
# Entry points
# --------------------------------------------------------------------------


def validate_document(doc: dict, path: str | None = None) -> Report:
    report = Report(path=path)
    if not isinstance(doc, dict):
        report.error(f"[structure] top level must be a JSON object, got {type(doc).__name__}")
        return report
    ctx: dict = {"triplets": {}}
    _check_identity(doc, report)
    _check_paths(doc, report)
    _check_sources_and_fdt(doc, report)
    _check_phandle_links(doc, report, ctx)
    _check_pinctrl(doc, report)
    _check_panel(doc, report)
    _check_timing(doc, report)
    parsed = _check_commands(doc, report)
    _check_hash_metadata(doc, report)
    _check_brightness_init_write(doc, report, parsed)
    _check_doze_versus_default(doc, report)
    _check_downstream_source(doc, report)
    _check_brightness_byte_order(doc, report, ctx)
    _check_power(doc, report, ctx)
    _check_reset_evidence(doc, report)
    _check_hardware_gate(doc, report, ctx)
    return report


def load_and_validate(path: str) -> Report:
    with open(path, "r", encoding="utf-8") as handle:
        doc = json.load(handle)
    return validate_document(doc, path=path)


def exit_code(report: Report, require_hardware_ready: bool = False) -> int:
    """0 = valid; 1 = fixture invalid; 2 = hardware gate closed while required."""
    if not report.fixture_valid:
        return 1
    if require_hardware_ready and not report.hardware_ready:
        return 2
    return 0


def _print_report(report: Report, require_hardware_ready: bool, stream) -> None:
    print(f"fixture: {report.path}", file=stream)
    print(f"fixture_valid: {str(report.fixture_valid).lower()}", file=stream)
    print(f"hardware_declared_ready: {report.hardware_declared_ready}", file=stream)
    print(f"hardware_ready: {str(report.hardware_ready).lower()}", file=stream)
    if report.evidence_criteria_unmet:
        print("evidence criteria unmet:", file=stream)
        for item in report.evidence_criteria_unmet:
            print(f"  - {item}", file=stream)
    else:
        print("evidence criteria unmet: none", file=stream)
    if report.derived:
        print("derived from pinned source:", file=stream)
        for key, value in report.derived.items():
            print(f"  - {key}: {value}", file=stream)

    if report.hardware_blockers:
        print("hardware blockers:", file=stream)
        for item in report.hardware_blockers:
            print(f"  - {item}", file=stream)
    else:
        print("hardware blockers: none", file=stream)

    if report.errors:
        print("errors:", file=stream)
        for item in report.errors:
            print(f"  - {item}", file=stream)
    if report.warnings:
        print("warnings:", file=stream)
        for item in report.warnings:
            print(f"  - {item}", file=stream)
    if report.notes:
        print("notes:", file=stream)
        for item in report.notes:
            print(f"  - {item}", file=stream)

    if require_hardware_ready and not report.hardware_ready:
        print(
            "HARDWARE GATE: NOT READY -- refusing to treat this fixture as hardware-tested evidence.",
            file=stream,
        )
        print(
            f"  {len(report.hardware_blockers)} blocker(s) must be resolved through an authorized source:",
            file=stream,
        )
        for item in report.hardware_blockers:
            print(f"  * {item}", file=stream)
        if report.evidence_criteria_unmet:
            print("  evidence criteria still unmet:", file=stream)
            for item in report.evidence_criteria_unmet:
                print(f"  * {item}", file=stream)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="validate_ea8074_evidence.py",
        description=(
            "Read-only validator for config/ea8074-evidence.json. Reports two separate verdicts: "
            "fixture consistency and hardware readiness."
        ),
    )
    parser.add_argument("fixture", help="path to the EA8074 evidence fixture (read only)")
    parser.add_argument(
        "--require-hardware-ready",
        action="store_true",
        help="exit non-zero (2) and list the concrete blockers when the hardware gate is closed",
    )
    parser.add_argument("--json", action="store_true", help="emit the report as JSON")
    args = parser.parse_args(argv)

    if not os.path.exists(args.fixture):
        print(f"error: fixture not found: {args.fixture}", file=sys.stderr)
        return 1
    try:
        report = load_and_validate(args.fixture)
    except json.JSONDecodeError as exc:
        print(f"error: {args.fixture} is not valid JSON: {exc}", file=sys.stderr)
        return 1

    if args.json:
        json.dump(report.to_dict(), sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        _print_report(report, args.require_hardware_ready, sys.stdout)
    return exit_code(report, args.require_hardware_ready)


if __name__ == "__main__":
    sys.exit(main())
