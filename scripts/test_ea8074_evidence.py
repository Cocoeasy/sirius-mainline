#!/usr/bin/env python3
"""Stage-1 tests for scripts/validate_ea8074_evidence.py.

Run from the repository root::

    python -B -m unittest -v scripts.test_ea8074_evidence

What is asserted
----------------
1. The *real* fixture (``config/ea8074-evidence.json``) is internally
   consistent: the on/off ``bytes_hex`` arrays are genuinely parsed with the
   documented 7-byte header (not trusted from the recorded summary), their
   SHA-256 matches a fresh hash of the real bytes, and the FDT summary, phandle
   links, timing, model and power entries agree with the task pins.
2. The brightness and power claims are re-derived rather than believed: the
   in-sequence DCS 0x51 zero-brightness write is decoded from the raw bytes, and
   the 0x51 wire byte order plus the rail enable/disable sequence are computed
   from the pinned downstream snippets.
3. ``fixture_valid`` and ``hardware_ready`` are independent verdicts.  The
   current fixture is expected to be VALID while NOT hardware-ready (the
   evidence is complete; the device tree is still wrong), and that combination
   must not turn an evidence test red.
4. Every negative case mutates a ``copy.deepcopy`` of the fixture and is paired
   with a control assertion on the unmutated copy, so a rejection can never
   pass vacuously.  The fixture on disk is never modified.

Nothing here touches a phone, the network, Git state, or any other file: the
only file opened for reading is the fixture itself.
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import sys
import unittest
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPTS_DIR.parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import validate_ea8074_evidence as V  # noqa: E402  (path set up above)

FIXTURE_PATH = REPO_ROOT / "config" / "ea8074-evidence.json"
VALIDATOR_PATH = SCRIPTS_DIR / "validate_ea8074_evidence.py"


class FixtureTestCase(unittest.TestCase):
    """Shared fixture loading plus the control/reject protocol."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.raw_text = FIXTURE_PATH.read_text(encoding="utf-8")
        cls.pristine = json.loads(cls.raw_text)
        cls.pristine_file_sha256 = hashlib.sha256(cls.raw_text.encode("utf-8")).hexdigest()

    # -- helpers ----------------------------------------------------------
    def doc(self) -> dict:
        """A fresh deepcopy: mutations can never leak into the fixture."""
        return copy.deepcopy(self.pristine)

    def accept(self, doc: dict, label: str) -> V.Report:
        report = V.validate_document(doc)
        self.assertTrue(report.fixture_valid, f"{label}: expected acceptance, errors={report.errors}")
        return report

    def reject(self, doc: dict, label: str, expect_code: str) -> V.Report:
        """Assert a specific rejection AND that the same validator accepts the pristine copy."""
        report = V.validate_document(doc)
        self.assertFalse(report.fixture_valid, f"{label}: expected rejection but the document was accepted")
        self.assertTrue(
            any(expect_code in err for err in report.errors),
            f"{label}: no error containing {expect_code!r}; got {report.errors}",
        )
        self.accept(self.doc(), f"{label} [control]")
        return report

    def retamper(self, doc: dict, name: str, new_hex: str) -> None:
        """Replace an on/off array and make every hash/size field agree again.

        Recomputing the SHA-256 is deliberate: it proves a structural defect is
        rejected *on its own*, not merely because a hash stopped matching.
        """
        arr = doc["init_commands"][name]
        arr["bytes_hex"] = new_hex
        arr["length_bytes"] = len(bytes.fromhex(new_hex))
        arr["sha256"] = hashlib.sha256(bytes.fromhex(new_hex)).hexdigest()

    def on_bytes(self, doc: dict) -> bytearray:
        return bytearray(bytes.fromhex(doc["init_commands"]["on"]["bytes_hex"]))

    def commit_on(self, doc: dict, raw: bytearray) -> None:
        self.retamper(doc, "on", bytes(raw).hex())

    def snippets(self, doc: dict, path: str) -> list:
        return doc["downstream_source_evidence"]["files"][path]["snippets"]

    def replace_snippet(self, doc: dict, path: str, token: str, new_text: str) -> None:
        """Replace the one snippet containing ``token``."""
        found = False
        for i, text in enumerate(self.snippets(doc, path)):
            if token in text:
                self.snippets(doc, path)[i] = new_text
                found = True
                break
        self.assertTrue(found, f"no snippet in {path} contains {token!r}")

    def drop_snippet(self, doc: dict, path: str, token: str) -> None:
        kept = [s for s in self.snippets(doc, path) if token not in s]
        self.assertLess(len(kept), len(self.snippets(doc, path)), f"no snippet in {path} contains {token!r}")
        doc["downstream_source_evidence"]["files"][path]["snippets"] = kept

    def resolved_item(self, doc: dict, *needles: str) -> dict:
        """The first resolved[] item whose name matches every needle."""
        matches = self.resolved_items(doc, *needles)
        self.assertTrue(matches, f"no resolved[] item matched {needles}")
        return matches[0]

    def resolved_items(self, doc: dict, *needles: str) -> list:
        """All resolved[] items whose name matches every needle (order independent)."""
        return [
            item
            for item in doc["resolved"]
            if all(n.lower() in str(item.get("item", "")).lower() for n in needles)
        ]

    # -- convenience indexes ---------------------------------------------
    def on_51_offset(self) -> int:
        """Offset of the DCS 0x51 record, derived from the raw bytes."""
        records = V.parse_records(self.pristine["init_commands"]["on"]["bytes_hex"], "on")
        hits = V.find_dcs_brightness_records(records)
        self.assertEqual(len(hits), 1)
        return hits[0].offset


# ==========================================================================
# 1. The real fixture
# ==========================================================================


class TestRealFixtureIsConsistent(FixtureTestCase):
    def test_pristine_fixture_is_valid_but_hardware_not_ready(self) -> None:
        report = self.accept(self.doc(), "pristine fixture")
        self.assertFalse(report.hardware_declared_ready)
        self.assertFalse(report.hardware_ready)
        self.assertTrue(report.hardware_blockers, "the closed hardware gate must list concrete blockers")

    def test_on_off_arrays_are_really_parsed_from_hex(self) -> None:
        on = V.parse_records(self.pristine["init_commands"]["on"]["bytes_hex"], "on")
        off = V.parse_records(self.pristine["init_commands"]["off"]["bytes_hex"], "off")
        self.assertEqual((len(on), len(off)), (21, 2))
        self.assertEqual(sum(V.HEADER_BYTES + r.dlen for r in on), 204)
        self.assertEqual(sum(V.HEADER_BYTES + r.dlen for r in off), 18)
        for rec in on + off:
            self.assertEqual(rec.vc, 0, "panel virtual channel is 0")
            self.assertEqual(rec.ack, 0, "no ack is requested by this panel")
            self.assertIn(rec.dtype, V.ALLOWED_DTYPES)

    def test_stored_sha256_matches_real_bytes(self) -> None:
        for name, expected in (
            ("on", "1c25248bc7206c438080a8c7958f3196a9d1426ded9dca592f644b71c987e594"),
            ("off", "1d4f64f5b407e84e631e4f3691c2a8823482f2b3b337c1b7587f787c39aea82d"),
        ):
            arr = self.pristine["init_commands"][name]
            recomputed = V.sha256_of_hex(arr["bytes_hex"])
            self.assertEqual(recomputed, arr["sha256"])
            self.assertEqual(recomputed, expected)
            self.assertRegex(recomputed, r"^[0-9a-f]{64}$")

    def test_long_packet_keeps_its_own_type(self) -> None:
        """0x39 long packets stay 0x39; the parsed type equals the raw header byte."""
        raw = bytes.fromhex(self.pristine["init_commands"]["on"]["bytes_hex"])
        on = V.parse_records(self.pristine["init_commands"]["on"]["bytes_hex"], "on")
        for rec in on:
            self.assertEqual(rec.dtype, raw[rec.offset], "parsed dtype must equal the raw header byte")
        long_records = [r for r in on if r.dtype == 0x39]
        self.assertEqual(len(long_records), 19)
        # A 0x39 payload is command + real parameters and is never re-typed.
        self.assertEqual(long_records[0].payload.hex(), "2b000008c3")
        self.assertEqual(len(long_records[0].payload), long_records[0].dlen)
        self.assertTrue(all(r.payload[0] != 0x00 for r in long_records), "0x39 must start with a real DCS command")

    def test_short_writes_carry_zero_padding_not_parameters(self) -> None:
        """0x05 payload is <cmd> + 0x00 padding; the padding is not a parameter."""
        on = V.parse_records(self.pristine["init_commands"]["on"]["bytes_hex"], "on")
        off = V.parse_records(self.pristine["init_commands"]["off"]["bytes_hex"], "off")
        short = [r for r in on + off if r.dtype == 0x05]
        self.assertEqual(len(short), 4)
        commands = []
        for rec in short:
            cmd, padding = rec.payload[0], rec.payload[1:]
            commands.append(cmd)
            self.assertNotEqual(cmd, 0x00)
            self.assertTrue(all(b == 0x00 for b in padding), f"0x{cmd:02x} padding must be zero")
            # DCS parameter count for a 0x05 short write is always zero.
            self.assertEqual(len(rec.payload) - 1, len(padding))
        self.assertEqual(commands, [0x11, 0x29, 0x28, 0x10])

    def test_te_dcs_command_is_a_scalar_not_an_array(self) -> None:
        te_dcs = self.pristine["panel"]["te"]["qcom_mdss_dsi_te_dcs_command"]
        self.assertIsInstance(te_dcs, int)
        self.assertNotIsInstance(te_dcs, bool)
        self.assertEqual(te_dcs, 1)
        # It must not be fed to the 7-byte-per-record command parser.
        with self.assertRaises(V.RecordParseError):
            V.parse_records("01", "te-dcs-command scalar")

    def test_model_timing_and_lanes_match_the_pin(self) -> None:
        self.assertEqual(self.pristine["panel"]["qcom_mdss_dsi_panel_model"], "SS-FHD-EA8074-CMD-PANEL")
        self.assertEqual(self.pristine["panel"]["lane_count"], 4)
        self.assertEqual(self.pristine["panel"]["lanes_active"], [0, 1, 2, 3])
        self.assertEqual(self.pristine["panel"]["qcom_mdss_dsi_panel_type"], "dsi_cmd_mode")
        self.assertEqual(self.pristine["panel"]["qcom_mdss_dsi_bpp"], 24)
        timing = self.pristine["timing"]
        self.assertEqual((timing["qcom_mdss_dsi_panel_width"], timing["qcom_mdss_dsi_panel_height"]), (1080, 2244))
        self.assertEqual(timing["qcom_mdss_dsi_panel_framerate"], 60)
        self.assertEqual(
            (
                timing["qcom_mdss_dsi_h_front_porch"],
                timing["qcom_mdss_dsi_h_back_porch"],
                timing["qcom_mdss_dsi_h_pulse_width"],
            ),
            (48, 48, 16),
        )
        self.assertEqual(
            (
                timing["qcom_mdss_dsi_v_front_porch"],
                timing["qcom_mdss_dsi_v_back_porch"],
                timing["qcom_mdss_dsi_v_pulse_width"],
            ),
            (28, 28, 12),
        )

    def test_reset_and_te_gpio_pin(self) -> None:
        display = self.pristine["display_node"]
        self.assertEqual(display["qcom_platform_reset_gpio"]["gpio"], 75)
        self.assertEqual(display["qcom_platform_reset_gpio"]["flag"], 0)
        self.assertEqual(display["qcom_platform_te_gpio"]["gpio"], 10)
        self.assertEqual(self.pristine["panel"]["reset_sequence"]["pairs_value_delay_ms"], [[0, 2], [1, 11]])
        self.assertEqual(V.decode_u32_triplet(display["qcom_platform_reset_gpio"]["raw_hex"]), (50, 75, 0))
        self.assertTrue(
            self.pristine["panel"]["reset_sequence"]["mainline_convention_cross_check"][
                "matches_vendor_physical_sequence"
            ]
        )

    def test_vci_is_gpio5_and_supplies_are_exactly_two(self) -> None:
        power = self.pristine["power"]
        roles = self.pristine["gpio_role_resolution"]
        self.assertEqual(power["vci_rail"]["gpio"], 5)
        self.assertEqual(power["vci_rail"]["gpio_phandle"], roles["gpio5"]["phandle"])
        self.assertTrue(power["vci_rail"]["enable_active_high"])
        self.assertTrue(power["vci_rail"]["regulator_boot_on"])
        self.assertEqual(power["vci_rail"]["start_delay_us"], 4000)
        # The only raw <phandle gpio flag> blob for GPIO5 lives under gpio_role_resolution.
        self.assertEqual(V.decode_u32_triplet(roles["gpio5"]["raw_hex"]), (50, 5, 0))
        entries = power["panel_supply_entries"]["entries"]
        self.assertEqual(power["panel_supply_entries"]["entry_count"], 2)
        self.assertEqual(len(entries), 2)
        self.assertEqual([(e["reg"], e["qcom_supply_name"], e["min_uv"]) for e in entries],
                         [(0, "vddio", 1800000), (1, "vci", 3000000)])
        names = " ".join(str(e.get("qcom_supply_name", "")) for e in entries).lower()
        for banned in ("lab", "ibb", "lcdb"):
            self.assertNotIn(banned, names)
        voltages = {e.get("min_uv") for e in entries} | {e.get("max_uv") for e in entries}
        self.assertNotIn(3300000, voltages)
        # GPIO76 is a dual-DSI mode select for nt35597 panels, not the VCI enable.
        self.assertFalse(roles["gpio76"]["bound_on_ea8074_nodes"])
        self.assertEqual(V.decode_u32_triplet(roles["gpio76"]["raw_hex_where_bound"])[1], 76)

    def test_fdt_verdict_is_summary_level_only(self) -> None:
        """No raw FDT means the token stream is NOT re-verified, and we say so."""
        report = self.accept(self.doc(), "fdt summary")
        joined = " ".join(report.notes)
        self.assertIn("[fdt.tokens_unverifiable]", joined)
        self.assertIn("RECORDED CLAIMS", joined)
        self.assertIn("NOT re-verified", joined)
        for note in report.notes:
            if "token" in note.lower():
                self.assertNotIn("re-verified: true", note.lower())
        # And the raw FDT genuinely is not embedded: the fixture is far smaller.
        fdt_size = self.pristine["sources"][0]["size_bytes"]
        self.assertEqual(fdt_size, 503401)
        self.assertLess(FIXTURE_PATH.stat().st_size, fdt_size)

        def longest_string(node) -> int:
            if isinstance(node, dict):
                return max([0] + [longest_string(v) for v in node.values()])
            if isinstance(node, list):
                return max([0] + [longest_string(v) for v in node])
            return len(node) if isinstance(node, str) else 0

        self.assertLess(longest_string(self.pristine), 4096, "no field is large enough to hold a raw FDT")

    def test_fdt_summary_arithmetic_is_self_consistent(self) -> None:
        fdt = self.pristine["sources"][0]
        header, integrity = fdt["fdt_header"], fdt["parse_integrity"]
        self.assertEqual(header["magic"], "0xd00dfeed")
        self.assertEqual(header["off_dt_struct"] + header["size_dt_struct"], header["off_dt_strings"])
        self.assertEqual(header["off_dt_strings"] + header["size_dt_strings"], header["totalsize"])
        self.assertEqual(fdt["size_bytes"], header["totalsize"])
        self.assertEqual(integrity["struct_block_end"], header["off_dt_strings"])
        self.assertEqual(integrity["strings_block_end"], header["totalsize"])
        self.assertEqual(integrity["tokens_FDT_BEGIN_NODE"], integrity["tokens_FDT_END_NODE"])
        self.assertEqual(integrity["node_count"], integrity["tokens_FDT_BEGIN_NODE"])
        self.assertEqual(integrity["tokens_FDT_END"], 1)
        self.assertEqual(integrity["unknown_tokens"], 0)
        self.assertTrue(integrity["contiguous_and_exact"])

    def test_phandle_links_are_mutually_consistent(self) -> None:
        report = self.accept(self.doc(), "phandle links")
        self.assertNotIn("phandle", " ".join(report.errors))
        phandles, display = self.pristine["phandles"], self.pristine["display_node"]
        self.assertEqual(display["qcom_dsi_panel_phandle"], phandles["panel_mdss_dsi_ss_fhd_ea8074_cmd"])
        self.assertEqual(display["vci_supply_phandle"], phandles["disp_vci_vreg"])
        self.assertEqual(display["vddio_supply_phandle"], phandles["pm660_l11_vddio"])
        self.assertEqual(len(phandles["pinctrl_panel_active"]), 2)
        self.assertEqual(len(phandles["pinctrl_panel_suspend"]), 2)
        self.assertEqual(display["qcom_dsi_panel_resolves_to"], self.pristine["panel"]["fdt_path"])
        for key, blob in (
            ("reset", display["qcom_platform_reset_gpio"]),
            ("te", display["qcom_platform_te_gpio"]),
            ("esd", self.pristine["panel"]["esd_err_irq_gpio"]),
        ):
            ph, gpio, flag = V.decode_u32_triplet(blob["raw_hex"])
            self.assertEqual((ph, gpio, flag), (blob["phandle"], blob["gpio"], blob["flag"]), key)

    # -- hash metadata: the fabricated narrative stays gone -----------------

    def test_fabricated_hash_and_pin_fields_are_absent(self) -> None:
        self.assertNotIn("hash_discrepancy_note", self.pristine)
        for name in ("on", "off"):
            arr = self.pristine["init_commands"][name]
            for stale in V.STALE_HASH_FIELDS:
                self.assertNotIn(stale, arr, f"{name}.{stale} must stay removed")
            self.assertRegex(arr["sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(arr["sha256_algorithm"], "sha256")
            self.assertEqual(arr["sha1_algorithm"], "sha1")

    def test_sha256_is_rehashed_and_sha1_is_optional(self) -> None:
        """Only the real 64-hex SHA-256 is required; sha1 is verified if present."""
        report = self.accept(self.doc(), "hash fields")
        on, off = self.pristine["init_commands"]["on"], self.pristine["init_commands"]["off"]
        self.assertNotIn("sha1", on, "on records no sha1 and none may be invented")
        self.assertTrue(
            any("[hash.on.sha1_absent]" in n for n in report.notes),
            f"the absent sha1 must be reported, not fabricated; notes={report.notes}",
        )
        self.assertEqual(V.sha256_of_hex(on["bytes_hex"]), on["sha256"])
        # off still carries a sha1: it must be the genuine SHA-1 of the same bytes.
        self.assertIn("sha1", off)
        self.assertEqual(V.sha1_of_hex(off["bytes_hex"]), off["sha1"])
        self.assertRegex(off["sha1"], r"^[0-9a-f]{40}$")
        self.assertNotEqual(off["sha1"], off["sha256"])

    # -- downstream source evidence ---------------------------------------

    def test_pinned_downstream_commit_and_file_hashes(self) -> None:
        ev = self.pristine["downstream_source_evidence"]
        self.assertEqual(ev["commit_full_sha"], "06a01bad75939c58be53418f5d71d9d2e25634cf")
        self.assertEqual(ev["repo"], "SDM710-Development/android_kernel_xiaomi_sdm710")
        # Every file the derivations depend on must be present with hashes.
        # Extra pinned entries are allowed (the transmission-state evidence
        # reads dsi_display.c as well), but only for a file that is also
        # recorded as read, so nothing can be quoted without having been
        # fetched at the pinned commit.
        required = set(V.REQUIRED_SOURCE_FILES)
        present = set(ev["files"])
        self.assertTrue(required <= present,
                        f"missing pinned file(s): {sorted(required - present)}")
        extra = present - required
        for path, entry in ev["files"].items():
            self.assertRegex(entry["git_blob_sha1"], r"^[0-9a-f]{40}$", path)
            self.assertRegex(entry["content_sha256"], r"^[0-9a-f]{64}$", path)
            self.assertTrue(entry["snippets"], f"{path} must quote at least one snippet")
        # The github source entry and the evidence block must agree.
        gh = next(s for s in self.pristine["sources"] if s["id"] == "github_downstream")
        self.assertEqual(gh["commit_full_sha"], ev["commit_full_sha"])
        self.assertNotEqual(gh["status"], "BLOCKED")
        for path in V.REQUIRED_SOURCE_FILES:
            self.assertIn(path, gh["files_read"])
        for path in extra:
            self.assertIn(path, gh["files_read"],
                          f"{path} is quoted as evidence but is not recorded as read")
        self.accept(self.doc(), "source evidence")

    def test_required_snippets_back_every_claim(self) -> None:
        doc = self.doc()
        for path, label, tokens in V.REQUIRED_SNIPPETS:
            snippets = V.source_snippets(doc, path)
            self.assertTrue(
                any(all(tok in s for tok in tokens) for s in snippets),
                f"{path}: no snippet supports {label!r}",
            )

    def test_wire_byte_order_derivation_is_msb_first(self) -> None:
        """The order is computed from source, not taken from a summary field."""
        derivation = V.derive_wire_byte_order(self.pristine)
        self.assertTrue(derivation["inverted_dbv"], "the EA8074 dtsi must declare bl-inverted-dbv")
        self.assertTrue(derivation["swap_present"], "dsi_panel.c must show the u16 swap")
        self.assertTrue(derivation["helper_little_endian"], "the helper must pack little-endian")
        self.assertTrue(derivation["msb_first"], derivation)
        self.assertEqual(derivation["payload_hex"], "0342", "probe 0x0342 must come out MSB-first")
        self.assertEqual(derivation["without_swap_hex"], "4203", "without the swap it would be LSB-first")
        self.assertTrue(derivation["swap_is_load_bearing"])

    def test_byte_order_metadata_matches_the_derivation(self) -> None:
        report = self.accept(self.doc(), "byte order metadata")
        self.assertTrue(report.derived["wire_byte_order"]["msb_first"])
        encoding = self.pristine["panel"]["brightness_properties"]["level_encoding"].lower()
        self.assertIn("most significant byte first", encoding)
        self.assertRegex(encoding, r"1\s*\.\.\s*1023")
        # The resolution must cite the pinned commit and the EA8074 property.
        item = self.resolved_item(self.pristine, "0x51", "byte order")
        self.assertEqual(item["status"], "resolved")
        self.assertIs(item["must_not_guess"], False)
        self.assertIn(V.DOWNSTREAM_COMMIT, item["detail"])
        self.assertIn("inverted-dbv", item["detail"])

    def test_dcs_type_ss_is_not_used_as_byte_order_evidence(self) -> None:
        doc = self.pristine
        semantics = doc["panel"]["brightness_properties"]["qcom_mdss_dsi_bl_dcs_type_ss_semantics"].lower()
        self.assertIn("not resolvable", semantics)
        self.assertIn("inverted-dbv", semantics)
        self.assertTrue(
            any("dcs-type-ss" in str(u.get("item", "")) for u in doc["unresolved"]),
            "the dcs-type-ss semantics must stay recorded as unresolved",
        )
        conclusion = doc["downstream_source_evidence"]["byte_order_conclusion"].lower()
        for banned in ("dcs-type-ss", "dcs_type_ss", "ams639rq08", "_large"):
            self.assertNotIn(banned, conclusion)
        not_used = " ".join(doc["downstream_source_evidence"]["explicitly_not_used_as_byte_order_evidence"]).lower()
        self.assertIn("ams639rq08", not_used)
        self.assertIn("_large", not_used)
        self.accept(self.doc(), "dcs-type-ss excluded")

    # -- init-sequence brightness write -----------------------------------

    def test_initial_0x51_write_proved_from_raw_bytes(self) -> None:
        doc = self.pristine
        records = V.parse_records(doc["init_commands"]["on"]["bytes_hex"], "on")
        hits = V.find_dcs_brightness_records(records)
        self.assertEqual(len(hits), 1, "exactly one in-sequence DCS 0x51 write is expected")
        rec = hits[0]
        self.assertEqual((rec.dtype, rec.dlen), (0x39, 3))
        self.assertEqual(rec.payload.hex(), "510000")
        self.assertEqual(int.from_bytes(rec.payload[1:3], "big"), 0)
        self.assertIs(doc["panel"]["brightness_properties"]["dcs_0x51_in_init_sequence"], True)
        report = self.accept(self.doc(), "0x51 init write")
        self.assertTrue(any("[brightness.init_verified]" in n for n in report.notes))

    def test_initial_write_cannot_discriminate_byte_order(self) -> None:
        """A 0x0000 level reads the same either way, so the wire order is not derived from it."""
        report = self.accept(self.doc(), "0x51 order agnostic")
        note = " ".join(report.notes)
        self.assertIn("byte-order agnostic", note)
        rec = V.find_dcs_brightness_records(
            V.parse_records(self.pristine["init_commands"]["on"]["bytes_hex"], "on")
        )[0]
        self.assertEqual(int.from_bytes(rec.payload[1:3], "big"), int.from_bytes(rec.payload[1:3], "little"))

    def test_doze_levels_are_not_a_boot_default(self) -> None:
        bright = self.pristine["panel"]["brightness_properties"]
        ilb = bright["initial_low_brightness"]
        self.assertEqual((ilb["doze_lbm_level"], ilb["doze_hbm_level"]), (10, 133))
        self.assertRegex(ilb["note"].lower(), r"no\s+initial|no\s+default")
        self.assertIn("doze", ilb["source"].lower())
        note = bright["dcs_0x51_note"].lower()
        self.assertIn("zero", note)
        self.assertIn("doze", note)
        self.assertTrue("do not treat" in note or "not treat" in note)
        # No field may present a doze level as the boot default.
        for key, value in bright.items():
            if "default" in key.lower():
                self.assertNotIn(value, (10, 133), key)
        self.accept(self.doc(), "doze not a default")

    # -- power sequencing and the inert vendor delay ----------------------

    def test_enable_disable_sequence_derived_from_source(self) -> None:
        seq = V.derive_power_sequence(self.pristine)
        self.assertTrue(seq["forward_loop"])
        self.assertTrue(seq["reverse_loop"])
        self.assertEqual(seq["enable"], ["vddio", "vci"])
        self.assertEqual(seq["disable"], ["vci", "vddio"])
        self.assertEqual(seq["enable_trailing_sleep_ms"], 10)
        self.assertEqual(seq["disable_leading_sleep_ms"], 10)
        report = self.accept(self.doc(), "power sequence")
        self.assertEqual(report.derived["power_sequence"]["enable"], ["vddio", "vci"])

    def test_vendor_start_delay_us_has_no_consumer(self) -> None:
        fixed = V.snippets_blob(self.pristine, V.FIXED_C)
        self.assertIn("startup-delay-us", fixed)
        self.assertNotIn("start-delay-us", fixed)
        conclusion = self.pristine["downstream_source_evidence"]["files"][V.FIXED_C]["conclusion"]
        self.assertIn("not start-delay-us", conclusion)
        vci_dtsi = V.snippets_blob(self.pristine, V.DTSI_SIRIUS)
        self.assertIn("start-delay-us = <4000>", vci_dtsi)
        self.assertEqual(self.pristine["power"]["vci_rail"]["start_delay_us"], 4000)
        item = self.resolved_item(self.pristine, "delay property")
        self.assertIn("inert", item["detail"].lower())
        self.accept(self.doc(), "inert vendor delay")

    def test_reset_evidence_is_anchored_in_source(self) -> None:
        panel_source = V.snippets_blob(self.pristine, V.DSI_PANEL_C)
        self.assertIn("qcom,platform-reset-gpio", panel_source)
        self.assertIn("gpio_set_value(reset_gpio", panel_source)
        self.assertIn("qcom,mdss-dsi-reset-sequence", V.snippets_blob(self.pristine, V.DTSI_EA8074))
        # Order independent: at least one resolved item must carry the claim.
        backed = [
            item
            for item in self.resolved_items(self.pristine, "reset", "waveform")
            if item["status"] == "resolved"
            and "<0 2>" in item["detail"]
            and "<1 11>" in item["detail"]
            and "GPIO_ACTIVE_LOW" in item["detail"]
        ]
        self.assertTrue(
            backed,
            "a resolved reset-waveform item must state both the vendor <0 2>/<1 11> sequence and ACTIVE_LOW",
        )
        self.accept(self.doc(), "reset source")

    # -- the gate itself --------------------------------------------------

    def test_gate_is_closed_by_the_open_blockers_not_by_missing_evidence(self) -> None:
        """The gate is held closed by what is genuinely still open.

        The three evidence criteria are satisfied, so the reason cannot be
        missing evidence. B1 (the rail mapping) is deliberately marked
        resolved_pending_review and must no longer gate; B4 is low severity and
        must never gate. The blockers that do gate are the packet-format
        deviation, the fact that nothing has been built or validated, and the
        missing independent re-review.
        """
        report = self.accept(self.doc(), "gate")
        self.assertEqual(report.evidence_criteria_unmet, [], "all three evidence criteria must be satisfied")
        self.assertTrue(report.hardware_blockers, "a closed gate must list concrete blockers")
        blob = " ".join(report.hardware_blockers)
        for expected in ("B2", "B3", "B5"):
            self.assertIn(expected, blob, f"{expected} must be an open gating blocker")
        self.assertNotIn("B1", blob, "the rail mapping is resolved_pending_review and must not gate")
        self.assertNotIn("B4", blob, "the low-severity debugfs blocker must not gate hardware")
        self.assertFalse(report.hardware_ready)
        joined = " ".join(report.notes)
        self.assertIn("[gate.non_gating]", joined, "non-gating blockers must still be surfaced")
        self.assertIn("B4", joined)

    def test_empirical_escape_hatch_never_opens_the_gate(self) -> None:
        """Adding an 'empirical' run-around to a blocker must not open the gate."""
        doc = self.doc()
        doc["blockers"][0]["required_action"] += " Alternatively determine the correct wiring empirically."
        self.accept(doc, "empirical hatch (document stays self-consistent)")
        report = V.validate_document(doc)
        self.assertFalse(report.hardware_ready, "an 'empirical' escape hatch must never open the hardware gate")
        self.assertTrue(report.hardware_blockers)

    def test_doubled_slash_paths_are_normalised_without_write_back(self) -> None:
        self.assertEqual(V.normalize_fdt_path("//soc/qcom,dsi-display@17"), "/soc/qcom,dsi-display@17")
        self.assertEqual(V.normalize_fdt_path("///soc/x"), "/soc/x")
        self.assertEqual(V.normalize_fdt_path("/soc/x"), "/soc/x")
        doc = self.doc()
        before = copy.deepcopy(doc)
        V.validate_document(doc)
        self.assertEqual(
            json.dumps(doc, sort_keys=True),
            json.dumps(before, sort_keys=True),
            "validate_document must not write normalised paths (or anything else) back into the document",
        )

    def test_validation_does_not_modify_the_fixture_on_disk(self) -> None:
        report = V.validate_document(self.doc(), path=str(FIXTURE_PATH))
        self.assertTrue(report.fixture_valid)
        with contextlib.redirect_stdout(io.StringIO()):
            V.main([str(FIXTURE_PATH)])
            V.main([str(FIXTURE_PATH), "--require-hardware-ready"])
        after = hashlib.sha256(FIXTURE_PATH.read_text(encoding="utf-8").encode("utf-8")).hexdigest()
        self.assertEqual(after, self.pristine_file_sha256)

    def test_validator_is_offline_and_pure_stdlib(self) -> None:
        source = VALIDATOR_PATH.read_text(encoding="utf-8")
        for forbidden in ("import subprocess", "import socket", "import urllib", "import http",
                          "import requests", "os.system", "adb ", "import shutil"):
            self.assertNotIn(forbidden, source, f"validator must stay offline/pure-stdlib: found {forbidden!r}")
        self.assertIn("import hashlib", source)


# ==========================================================================
# 2. Parser-level rejections (isolated: no hash or summary involved)
# ==========================================================================


class TestRecordParserRejections(FixtureTestCase):
    """Direct parse_records tests, so a rejection cannot come from the hash check."""

    def setUp(self) -> None:
        self.valid_on = self.pristine["init_commands"]["on"]["bytes_hex"]

    def control(self) -> None:
        self.assertEqual(len(V.parse_records(self.valid_on, "control")), 21)

    def test_truncated_header_is_rejected(self) -> None:
        self.control()
        for bad in ("0501", self.valid_on + "0501", "050100000a"):
            with self.assertRaises(V.RecordParseError, msg=bad) as ctx:
                V.parse_records(bad, "truncated")
            self.assertIn("truncated", str(ctx.exception))

    def test_length_overrun_is_rejected(self) -> None:
        self.control()
        for bad in ("390000000000ff", "050100000a0002", "05 01 00 00 0a 00 05 11 00"):
            with self.assertRaises(V.RecordParseError, msg=bad) as ctx:
                V.parse_records(bad, "overrun")
            self.assertIn("overrun", str(ctx.exception))

    def test_wrong_data_type_is_rejected(self) -> None:
        self.control()
        # dtype 0x99 at offset 0, dlen 1, and a clean 0x00 dtype record after a
        # valid first record -- only the data type is wrong in both cases.
        for bad in ("9900000000000100", "050100000a00021100" + "0000000000000100"):
            with self.assertRaises(V.RecordParseError, msg=bad) as ctx:
                V.parse_records(bad, "type")
            self.assertIn("data type", str(ctx.exception))

    def test_out_of_range_vc_and_ack_are_rejected(self) -> None:
        self.control()
        with self.assertRaises(V.RecordParseError) as ctx:
            V.parse_records("050104000a00021100", "vc")
        self.assertIn("vc", str(ctx.exception))
        with self.assertRaises(V.RecordParseError) as ctx:
            V.parse_records("050100020a00021100", "ack")
        self.assertIn("ack", str(ctx.exception))
        with self.assertRaises(V.RecordParseError) as ctx:
            V.parse_records("050200000a00021100", "last")
        self.assertIn("last", str(ctx.exception))

    def test_zero_length_payload_is_rejected(self) -> None:
        self.control()
        with self.assertRaises(V.RecordParseError) as ctx:
            V.parse_records("050100000a0000", "empty payload")
        self.assertIn("zero-length", str(ctx.exception))

    def test_short_write_padding_rule_is_enforced(self) -> None:
        self.control()
        # 0x05 with a non-zero byte after the command: that byte would be an
        # invented parameter, so it must be rejected.
        with self.assertRaises(V.RecordParseError) as ctx:
            V.parse_records("050100000a0003110300", "padding")
        self.assertIn("padding", str(ctx.exception))
        # 0x05 with a 0x00 command byte.
        with self.assertRaises(V.RecordParseError) as ctx:
            V.parse_records("050100000a00020000", "zero cmd")
        self.assertIn("command byte 0x00", str(ctx.exception))
        # Positive control: the same 0x05 record with proper zero padding parses.
        self.assertEqual(len(V.parse_records("050100000a00021100", "ok")), 1)

    def test_malformed_hex_is_rejected(self) -> None:
        self.control()
        with self.assertRaises(V.RecordParseError):
            V.parse_records("050", "odd")
        with self.assertRaises(V.RecordParseError):
            V.parse_records("zz", "non-hex")
        with self.assertRaises(V.RecordParseError):
            V.parse_records("", "empty")
        with self.assertRaises(V.RecordParseError):
            V.parse_records(None, "not a string")

    def test_u32_triplet_decoder(self) -> None:
        self.assertEqual(V.decode_u32_triplet("000000320000004b00000000"), (50, 75, 0))
        self.assertEqual(V.decode_u32_triplet("000000320000007a00002002"), (50, 122, 8194))
        with self.assertRaises(V.RecordParseError):
            V.decode_u32_triplet("0000")


# ==========================================================================
# 3. Document-level mutations (deepcopy) with a control per case
# ==========================================================================


class TestDocumentMutations(FixtureTestCase):
    # -- command arrays ---------------------------------------------------
    def test_truncated_record_header_is_rejected(self) -> None:
        doc = self.doc()
        self.retamper(doc, "on", doc["init_commands"]["on"]["bytes_hex"] + "0501")
        self.reject(doc, "truncated header", "[cmds.on.parse]")

    def test_length_overrun_is_rejected(self) -> None:
        doc = self.doc()
        raw = self.on_bytes(doc)
        raw[15] = 0xFF  # second record (0x39) payload length low byte 0x05 -> 0xFF
        self.commit_on(doc, raw)
        self.reject(doc, "length overrun", "[cmds.on.parse]")

    def test_wrong_data_type_is_rejected(self) -> None:
        doc = self.doc()
        raw = self.on_bytes(doc)
        raw[9] = 0x99  # first 0x39 long packet becomes an unknown data type
        self.commit_on(doc, raw)
        self.reject(doc, "wrong dtype", "[cmds.on.parse]")

    def test_long_packet_retyped_as_short_write_is_rejected(self) -> None:
        doc = self.doc()
        raw = self.on_bytes(doc)
        raw[9] = 0x05  # 0x39 long packet re-typed as a 0x05 short write
        self.commit_on(doc, raw)
        self.reject(doc, "retyped long packet", "[cmds.on.parse]")

    def test_out_of_range_vc_is_rejected(self) -> None:
        doc = self.doc()
        raw = self.on_bytes(doc)
        raw[2] = 0x04  # vc nibble out of range
        self.commit_on(doc, raw)
        self.reject(doc, "bad vc", "[cmds.on.parse]")

    def test_out_of_range_ack_is_rejected(self) -> None:
        doc = self.doc()
        raw = self.on_bytes(doc)
        raw[3] = 0x02  # ack out of range
        self.commit_on(doc, raw)
        self.reject(doc, "bad ack", "[cmds.on.parse]")

    def test_short_write_padding_as_parameter_is_rejected(self) -> None:
        doc = self.doc()
        raw = self.on_bytes(doc)
        self.assertEqual(raw[8], 0x00, "record 0 payload should be 11 00")
        raw[8] = 0x03  # turn the 0x00 padding into a bogus parameter
        self.commit_on(doc, raw)
        self.reject(doc, "padding as parameter", "[cmds.on.parse]")

    def test_hash_tampering_in_bytes_is_rejected(self) -> None:
        doc = self.doc()
        raw = self.on_bytes(doc)
        # Flip a parameter byte inside a 0x39 payload (bytes[18], record 1's
        # third payload byte): the record structure stays perfectly valid, so
        # only the hash check can catch this.
        raw[18] ^= 0xFF
        doc["init_commands"]["on"]["bytes_hex"] = bytes(raw).hex()
        self.assertEqual(
            len(V.parse_records(doc["init_commands"]["on"]["bytes_hex"], "tampered")),
            21,
            "the tampered array must still parse cleanly, isolating the hash check",
        )
        report = self.reject(doc, "byte tampering", "[hash.on]")
        self.assertTrue(any("[pin.on.sha256]" in e for e in report.errors), report.errors)

    def test_hash_tampering_in_the_recorded_digest_is_rejected(self) -> None:
        doc = self.doc()
        doc["init_commands"]["on"]["sha256"] = "0" * 64
        self.reject(doc, "digest tampering", "[hash.on]")

    def test_reinstating_the_fabricated_pin_field_is_rejected(self) -> None:
        doc = self.doc()
        doc["init_commands"]["on"]["task_pinned_hash"] = doc["init_commands"]["on"]["sha256"][1:]
        self.reject(doc, "fabricated pin field", "[meta.stale_field]")

    def test_reinstating_the_hash_discrepancy_note_is_rejected(self) -> None:
        doc = self.doc()
        doc["hash_discrepancy_note"] = "Both digests were supplied truncated to 63 hex characters."
        self.reject(doc, "stale hash note", "[meta.stale_field]")

    def test_sha1_field_is_cross_checked(self) -> None:
        doc = self.doc()
        doc["init_commands"]["off"]["sha1"] = "0" * 40
        self.reject(doc, "sha1 lie", "[hash.off.sha1]")

    def test_off_decoded_disagreement_is_rejected(self) -> None:
        doc = self.doc()
        doc["init_commands"]["off_decoded"][0]["wait_ms"] = 38
        self.reject(doc, "off_decoded drift", "[cmds.off_decoded]")

    def test_record_count_field_lie_is_rejected(self) -> None:
        doc = self.doc()
        doc["init_commands"]["on"]["record_count"] = 20
        self.reject(doc, "record_count lie", "[cmds.on.count]")

    def test_record_format_shape_change_is_rejected(self) -> None:
        doc = self.doc()
        doc["init_commands"]["record_format"]["header_bytes"] = 8
        self.reject(doc, "header_bytes changed", "[cmds.format]")

    # -- init-sequence 0x51 ------------------------------------------------
    def test_0x51_metadata_denying_the_raw_bytes_is_rejected(self) -> None:
        doc = self.doc()
        doc["panel"]["brightness_properties"]["dcs_0x51_in_init_sequence"] = False
        self.reject(doc, "0x51 metadata denies raw", "[brightness.init_meta]")

    def test_0x51_write_removed_from_raw_is_rejected(self) -> None:
        """If the raw array loses the 0x51 write, the metadata claim must fail."""
        doc = self.doc()
        raw = self.on_bytes(doc)
        payload_at = self.on_51_offset() + V.HEADER_BYTES
        self.assertEqual(raw[payload_at], 0x51)
        raw[payload_at] = 0x52  # a valid DCS long write, but no longer brightness
        self.commit_on(doc, raw)
        self.reject(doc, "0x51 removed from raw", "[brightness.init_missing]")

    def test_0x51_initial_level_change_is_rejected(self) -> None:
        doc = self.doc()
        raw = self.on_bytes(doc)
        payload_at = self.on_51_offset() + V.HEADER_BYTES
        raw[payload_at + 2] = 0x0A  # initial level 0 -> 10 (a doze-like value)
        self.commit_on(doc, raw)
        self.reject(doc, "0x51 initial level changed", "[brightness.init_level]")

    def test_default_mistaken_for_doze_in_the_doze_note_is_rejected(self) -> None:
        doc = self.doc()
        doc["panel"]["brightness_properties"]["initial_low_brightness"]["note"] = (
            "This is the normal boot default brightness for this panel."
        )
        self.reject(doc, "doze as default", "[brightness.doze_default]")

    def test_default_mistaken_for_doze_in_the_init_note_is_rejected(self) -> None:
        doc = self.doc()
        doc["panel"]["brightness_properties"]["dcs_0x51_note"] = (
            "The preserved 204-byte on-command array sets the initial brightness to the doze LBM level 10 "
            "during initialization."
        )
        self.reject(doc, "init note claims doze level", "[brightness.init_note]")

    # -- byte order --------------------------------------------------------
    def test_wrong_wire_order_in_the_metadata_is_rejected(self) -> None:
        doc = self.doc()
        doc["panel"]["brightness_properties"]["level_encoding"] = (
            "Unsigned 10-bit level, valid range 1..1023. Sent as a 2-byte DCS 0x51 payload with the "
            "least significant byte first."
        )
        self.reject(doc, "metadata says LSB first", "[byte_order.meta]")

    def test_reversed_wire_order_in_the_conclusion_is_rejected(self) -> None:
        doc = self.doc()
        doc["downstream_source_evidence"]["byte_order_conclusion"] = (
            "The wire payload after DCS 0x51 is [LSB, MSB]."
        )
        self.reject(doc, "conclusion says [LSB, MSB]", "[byte_order.conclusion]")

    def test_removing_the_inverted_dbv_snippet_flips_the_derived_order(self) -> None:
        """Dropping bl-inverted-dbv must make the derivation itself go LSB-first."""
        doc = self.doc()
        self.drop_snippet(doc, V.DTSI_EA8074, "qcom,mdss-dsi-bl-inverted-dbv")
        derivation = V.derive_wire_byte_order(doc)
        self.assertFalse(derivation["inverted_dbv"])
        self.assertFalse(derivation["msb_first"], "without the swap the derivation must flip to LSB-first")
        report = self.reject(doc, "inverted-dbv snippet removed", "[byte_order.wire_order]")
        self.assertTrue(any("[byte_order.source]" in e for e in report.errors), report.errors)

    def test_wrong_wire_order_by_removing_the_swap_is_rejected(self) -> None:
        doc = self.doc()
        self.drop_snippet(doc, V.DSI_PANEL_C, "bl_inverted_dbv")
        derivation = V.derive_wire_byte_order(doc)
        self.assertFalse(derivation["swap_present"])
        self.assertFalse(derivation["msb_first"])
        self.reject(doc, "swap snippet removed", "[byte_order.source]")

    def test_dcs_type_ss_used_as_byte_order_evidence_is_rejected(self) -> None:
        doc = self.doc()
        doc["downstream_source_evidence"]["byte_order_conclusion"] = (
            "The byte order follows from qcom,mdss-dsi-bl-dcs-type-ss, giving [MSB, LSB]."
        )
        self.reject(doc, "dcs-type-ss used as evidence", "[byte_order.conclusion]")

    def test_dcs_type_ss_no_longer_unresolved_is_rejected(self) -> None:
        doc = self.doc()
        doc["unresolved"] = [u for u in doc["unresolved"] if "dcs-type-ss" not in str(u.get("item", ""))]
        self.reject(doc, "dcs-type-ss dropped from unresolved", "[byte_order.dcs_type_ss]")

    # -- power sequence ----------------------------------------------------
    def test_reversed_disable_loop_is_rejected(self) -> None:
        doc = self.doc()
        self.replace_snippet(
            doc,
            V.DSI_PWR_C,
            "regs->count - 1",
            "L171-182 disable path: for (i = 0; i < regs->count; i++) { regulator_disable(); }",
        )
        seq = V.derive_power_sequence(doc)
        self.assertFalse(seq["reverse_loop"])
        self.assertEqual(seq["disable"], [])
        self.reject(doc, "forward disable loop", "[power.sequence]")

    def test_enable_loop_made_reverse_is_rejected(self) -> None:
        doc = self.doc()
        self.replace_snippet(
            doc,
            V.DSI_PWR_C,
            "i = 0; i < regs->count; i++",
            "L136-170 enable path: for (i = (regs->count - 1); i >= 0; i--) { regulator_enable(); }",
        )
        seq = V.derive_power_sequence(doc)
        self.assertFalse(seq["forward_loop"])
        self.assertEqual(seq["enable"], [])
        self.reject(doc, "reverse enable loop", "[power.sequence]")

    def test_order_item_stating_the_reversed_sequence_is_rejected(self) -> None:
        doc = self.doc()
        item = self.resolved_item(doc, "rail", "order")
        item["detail"] = (
            f"Resolved from downstream dsi_pwr.c (commit {V.DOWNSTREAM_COMMIT}). ENABLE order: vci then vddio. "
            "DISABLE order: vddio then vci."
        )
        self.reject(doc, "order item reversed", "[power.sequence]")

    def test_wrong_inter_rail_sleep_is_rejected(self) -> None:
        doc = self.doc()
        doc["power"]["panel_supply_entries"]["entries"][1]["post_on_sleep_ms"] = 5
        self.reject(doc, "inter-rail sleep changed", "[power.sequence]")

    def test_vendor_delay_snippet_tampering_is_rejected(self) -> None:
        doc = self.doc()
        self.replace_snippet(
            doc,
            V.FIXED_C,
            "startup-delay-us",
            'L85: of_property_read_u32(np, "start-delay-us", &config->startup_delay);',
        )
        self.reject(doc, "startup-delay-us snippet tampered", "[power.fixed_delay]")

    def test_little_endian_snippet_tampering_is_rejected(self) -> None:
        doc = self.doc()
        self.replace_snippet(
            doc,
            V.DRM_MIPI_DSI_C,
            "brightness & 0xff, brightness >> 8",
            "L1055-1067 int mipi_dsi_dcs_set_display_brightness(...) { "
            "u8 payload[2] = { brightness >> 8, brightness & 0xff }; "
            "err = mipi_dsi_dcs_write(dsi, MIPI_DCS_SET_DISPLAY_BRIGHTNESS, payload, sizeof(payload)); }",
        )
        derivation = V.derive_wire_byte_order(doc)
        self.assertFalse(derivation["helper_little_endian"])
        self.assertFalse(derivation["msb_first"], "the tampered helper must change the derived order")
        self.reject(doc, "little-endian snippet tampered", "[source.snippet]")

    # -- identifier / structure -------------------------------------------
    def test_different_model_is_rejected(self) -> None:
        doc = self.doc()
        doc["panel"]["qcom_mdss_dsi_panel_model"] = "SS-FHD-UNKNOWN-CMD-PANEL"
        self.reject(doc, "different panel model", "[identity.panel_model]")

    def test_non_ea8074_panel_path_is_rejected(self) -> None:
        doc = self.doc()
        doc["panel"]["fdt_path"] = "/soc/qcom,mdss_dsi_ss_fhd_nt35597_cmd"
        self.reject(doc, "non-EA8074 path", "[identity.ea8074_path]")

    def test_timing_error_is_rejected(self) -> None:
        doc = self.doc()
        doc["timing"]["qcom_mdss_dsi_panel_framerate"] = 61
        self.reject(doc, "framerate error", "[timing.qcom_mdss_dsi_panel_framerate]")

    def test_timing_porch_error_is_rejected(self) -> None:
        doc = self.doc()
        doc["timing"]["qcom_mdss_dsi_v_pulse_width"] = 13
        self.reject(doc, "vsw error", "[timing.qcom_mdss_dsi_v_pulse_width]")

    def test_wrong_lane_count_is_rejected(self) -> None:
        doc = self.doc()
        doc["panel"]["lane_count"] = 2
        doc["panel"]["lanes_active"] = [0, 1]
        self.reject(doc, "lane count", "[panel.lanes]")

    def test_te_dcs_command_as_array_is_rejected(self) -> None:
        doc = self.doc()
        doc["panel"]["te"]["qcom_mdss_dsi_te_dcs_command"] = [1]
        self.reject(doc, "te-dcs-command as array", "[te.scalar]")

    def test_te_gpio_change_is_rejected(self) -> None:
        doc = self.doc()
        doc["display_node"]["qcom_platform_te_gpio"]["gpio"] = 11
        self.reject(doc, "te gpio change", "[gpio.te]")

    def test_missing_key_is_reported(self) -> None:
        doc = self.doc()
        del doc["panel"]["te"]
        self.reject(doc, "missing key", "[structure]")

    def test_reset_pairs_change_is_rejected(self) -> None:
        doc = self.doc()
        doc["panel"]["reset_sequence"]["pairs_value_delay_ms"] = [[0, 2], [1, 12]]
        self.reject(doc, "reset timing change", "[reset.pairs]")

    def test_top_level_shape_change_is_rejected(self) -> None:
        report = V.validate_document(["not", "an", "object"])
        self.assertFalse(report.fixture_valid)
        self.assertTrue(any("[structure]" in e for e in report.errors), report.errors)

    # -- power rails / GPIO roles -----------------------------------------
    def test_gpio76_substituted_for_vci_is_rejected(self) -> None:
        doc = self.doc()
        doc["power"]["vci_rail"]["gpio"] = 76
        self.reject(doc, "gpio76 as VCI enable", "[power.vci]")

    def test_gpio76_role_flip_is_rejected(self) -> None:
        doc = self.doc()
        doc["gpio_role_resolution"]["gpio76"]["bound_on_ea8074_nodes"] = True
        self.reject(doc, "gpio76 bound on EA8074", "[gpio.role]")

    def test_gpio5_role_flip_is_rejected(self) -> None:
        doc = self.doc()
        doc["gpio_role_resolution"]["gpio5"]["gpio"] = 76
        self.reject(doc, "gpio5 role flip", "[gpio.role]")

    def test_3v3_supply_is_rejected(self) -> None:
        doc = self.doc()
        doc["power"]["panel_supply_entries"]["entries"][0]["min_uv"] = 3300000
        doc["power"]["panel_supply_entries"]["entries"][0]["max_uv"] = 3300000
        self.reject(doc, "3.3 V supply entry", "[power.forbidden]")

    def test_extra_lab_ibb_supply_entry_is_rejected(self) -> None:
        doc = self.doc()
        entries = doc["power"]["panel_supply_entries"]["entries"]
        entries.append({"reg": 2, "qcom_supply_name": "lab", "min_uv": 4600000, "max_uv": 5000000})
        doc["power"]["panel_supply_entries"]["entry_count"] = 3
        self.reject(doc, "LAB entry added", "[power.forbidden]")

    def test_third_supply_entry_is_rejected(self) -> None:
        doc = self.doc()
        entries = doc["power"]["panel_supply_entries"]["entries"]
        entries.append({"reg": 2, "qcom_supply_name": "vsn", "min_uv": -5500000, "max_uv": -5500000})
        doc["power"]["panel_supply_entries"]["entry_count"] = 3
        self.reject(doc, "third supply entry", "[power.entries]")

    # -- FDT summary / phandles -------------------------------------------
    def test_fdt_layout_break_is_rejected(self) -> None:
        doc = self.doc()
        doc["sources"][0]["fdt_header"]["off_dt_strings"] += 1
        self.reject(doc, "fdt layout break", "[fdt.layout]")

    def test_fdt_token_imbalance_is_rejected(self) -> None:
        doc = self.doc()
        doc["sources"][0]["parse_integrity"]["tokens_FDT_BEGIN_NODE"] += 1
        self.reject(doc, "fdt token imbalance", "[fdt.tokens]")

    def test_fdt_size_mismatch_is_rejected(self) -> None:
        doc = self.doc()
        doc["sources"][0]["size_bytes"] = 503400
        self.reject(doc, "fdt size mismatch", "[fdt.size]")

    def test_phandle_link_disagreement_is_rejected(self) -> None:
        doc = self.doc()
        doc["display_node"]["qcom_dsi_panel_phandle"] = 999
        self.reject(doc, "phandle link", "[phandle.link]")

    def test_raw_hex_and_scalar_disagreement_is_rejected(self) -> None:
        doc = self.doc()
        doc["display_node"]["qcom_platform_reset_gpio"]["gpio"] = 76
        self.reject(doc, "raw_hex vs scalar", "[phandle.raw_hex]")

    def test_stripping_the_reset_sequence_from_resolved_items_is_rejected(self) -> None:
        """The reset claim is order-independent but must still state the waveform."""
        doc = self.doc()
        touched = 0
        for item in doc["resolved"]:
            name = str(item.get("item", "")).lower()
            if "reset" in name and "waveform" in name:
                item["detail"] = "Reset GPIO waveform resolved from the downstream panel driver."
                touched += 1
        self.assertGreater(touched, 0)
        self.reject(doc, "reset waveform tokens stripped", "[reset.source]")

    # -- downstream source pins -------------------------------------------
    def test_deleting_the_pinned_commit_is_rejected(self) -> None:
        doc = self.doc()
        del doc["downstream_source_evidence"]["commit_full_sha"]
        self.reject(doc, "commit deleted", "[source.commit]")

    def test_changing_the_pinned_commit_is_rejected(self) -> None:
        doc = self.doc()
        doc["downstream_source_evidence"]["commit_full_sha"] = "0" * 40
        self.reject(doc, "commit changed", "[source.commit]")

    def test_deleting_a_blob_hash_is_rejected(self) -> None:
        doc = self.doc()
        del doc["downstream_source_evidence"]["files"][V.DSI_PWR_C]["git_blob_sha1"]
        self.reject(doc, "blob sha deleted", "[source.blob_sha1]")

    def test_deleting_a_content_hash_is_rejected(self) -> None:
        doc = self.doc()
        del doc["downstream_source_evidence"]["files"][V.DSI_PANEL_C]["content_sha256"]
        self.reject(doc, "content sha deleted", "[source.content_sha256]")

    def test_deleting_a_pinned_source_file_is_rejected(self) -> None:
        doc = self.doc()
        del doc["downstream_source_evidence"]["files"][V.DTSI_EA8074]
        self.reject(doc, "source file deleted", "[source.file_missing]")

    def test_deleting_all_snippets_of_a_file_is_rejected(self) -> None:
        doc = self.doc()
        doc["downstream_source_evidence"]["files"][V.DSI_PWR_C]["snippets"] = []
        self.reject(doc, "snippets emptied", "[source.snippets]")

    def test_tampering_the_doze_snippet_is_rejected(self) -> None:
        doc = self.doc()
        self.replace_snippet(
            doc, V.DTSI_EA8074, "qcom,disp-doze-hbm-backlight", "L70: qcom,disp-doze-hbm-backlight = <255>;"
        )
        self.reject(doc, "doze hbm snippet tampered", "[source.snippet]")

    def test_github_source_recorded_as_blocked_is_rejected(self) -> None:
        doc = self.doc()
        gh = next(s for s in doc["sources"] if s["id"] == "github_downstream")
        gh["status"] = "BLOCKED"
        self.reject(doc, "github source blocked", "[source.github]")

    def test_github_commit_mismatch_is_rejected(self) -> None:
        doc = self.doc()
        gh = next(s for s in doc["sources"] if s["id"] == "github_downstream")
        gh["commit_full_sha"] = "0" * 40
        self.reject(doc, "github commit mismatch", "[source.github]")

    def test_file_read_but_not_declared_is_rejected(self) -> None:
        doc = self.doc()
        gh = next(s for s in doc["sources"] if s["id"] == "github_downstream")
        gh["files_read"] = [f for f in gh["files_read"] if "fixed.c" not in f]
        self.reject(doc, "fixed.c not declared as read", "[source.github]")

    # -- the hardware gate -------------------------------------------------
    def test_forged_hardware_ready_is_rejected(self) -> None:
        """Claiming readiness while the DTS blocker is open must fail."""
        doc = self.doc()
        doc["hardware_test_ready"] = True
        report = self.reject(doc, "forged hardware_ready", "[gate.forged]")
        self.assertFalse(report.hardware_ready, "a forged flag must not open the gate")

    def test_forged_hardware_ready_with_unmet_evidence_is_rejected(self) -> None:
        """The flag is never trusted: unmet evidence also blocks a readiness claim."""
        doc = self.doc()
        doc["hardware_test_ready"] = True
        doc["blockers"] = []
        self.drop_snippet(doc, V.DTSI_EA8074, "qcom,mdss-dsi-bl-inverted-dbv")
        self.reject(doc, "forged ready + no evidence", "[gate.forged_evidence]")

    def test_closing_the_gate_by_editing_the_blocker_flag_is_rejected(self) -> None:
        """Neutralising every gating still_open flag must still be rejected.

        Flipping the flag of a single already-resolved blocker changes nothing,
        so the control has to neutralise *all* currently gating blockers: the
        validator must then refuse to validate the document with [gate.empty]
        instead of quietly treating the fixture as hardware-ready.
        """
        doc = self.doc()
        gating = [b for b in doc["blockers"] if b.get("still_open") is not False]
        self.assertTrue(gating, "the real fixture must have at least one open gating blocker")
        for blocker in gating:
            blocker["still_open"] = False
        self.reject(doc, "every gating still_open flipped", "[gate.empty]")

    def test_resolving_one_blocker_cannot_open_the_gate_while_others_remain(self) -> None:
        """A partially resolved blocker set must not change the verdict."""
        doc = self.doc()
        first_open = next(b for b in doc["blockers"] if b.get("still_open") is not False)
        first_open["still_open"] = False
        report = V.validate_document(doc)
        self.assertTrue(report.fixture_valid, report.errors)
        self.assertTrue(report.hardware_blockers, "the remaining open blockers must still gate")
        self.assertFalse(report.hardware_ready)

    def test_deleting_all_gates_is_rejected(self) -> None:
        doc = self.doc()
        doc["blockers"] = []
        report = V.validate_document(doc)
        self.assertFalse(report.fixture_valid, "an empty gate set must not validate silently")
        self.assertTrue(any("[gate." in e for e in report.errors), report.errors)

    def test_removing_the_not_ready_flag_alone_is_rejected(self) -> None:
        doc = self.doc()
        del doc["hardware_test_ready"]
        self.reject(doc, "flag removed", "[gate.flag]")

    def test_not_ready_reason_must_name_the_blocker(self) -> None:
        doc = self.doc()
        doc["hardware_test_ready_reason"] = "Not everything is confirmed yet."
        self.reject(doc, "vague reason", "[gate.reason]")


# ==========================================================================
# 4. Verdict plumbing (exit codes, hardware gate, JSON shape)
# ==========================================================================


class TestVerdictsAndCli(FixtureTestCase):
    def doc_with(self, mutate) -> dict:
        doc = self.doc()
        mutate(doc)
        return doc

    def test_fixture_valid_and_hardware_ready_are_independent(self) -> None:
        valid_not_ready = V.validate_document(self.doc())
        self.assertTrue(valid_not_ready.fixture_valid)
        self.assertFalse(valid_not_ready.hardware_ready)

        invalid = V.validate_document(self.doc_with(lambda d: d["panel"].update(lane_count=2)))
        self.assertFalse(invalid.fixture_valid)

    def test_exit_codes(self) -> None:
        pristine = V.validate_document(self.doc())
        self.assertEqual(V.exit_code(pristine), 0, "a consistent fixture must exit 0 by default")
        self.assertEqual(
            V.exit_code(pristine, require_hardware_ready=True), 2, "the closed hardware gate must exit 2"
        )
        invalid = V.validate_document(self.doc_with(lambda d: d["panel"].update(lane_count=2)))
        self.assertEqual(V.exit_code(invalid), 1)
        self.assertEqual(V.exit_code(invalid, require_hardware_ready=True), 1, "invalid wins over the gate")

    def test_cli_default_run_succeeds_on_the_real_fixture(self) -> None:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = V.main([str(FIXTURE_PATH)])
        self.assertEqual(code, 0)
        output = buffer.getvalue()
        self.assertIn("fixture_valid: true", output)
        self.assertIn("hardware_ready: false", output)
        self.assertIn("evidence criteria unmet: none", output)
        self.assertIn("msb_first", output)

    def test_cli_require_hardware_ready_fails_and_lists_blockers(self) -> None:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = V.main([str(FIXTURE_PATH), "--require-hardware-ready"])
        self.assertNotEqual(code, 0)
        self.assertEqual(code, 2)
        output = buffer.getvalue()
        self.assertIn("HARDWARE GATE: NOT READY", output)
        # The evidence criteria are met, so the refusal must be explained by the
        # blockers that are genuinely still open - and the packet-format
        # deviation is one of them, with both data types named.
        self.assertIn("evidence criteria unmet: none", output)
        for expected in ("B2", "B3", "B5"):
            self.assertIn(expected, output)
        self.assertIn("0x39", output)
        self.assertIn("0x15", output)
        # Non-gating blockers are still surfaced for the reader.
        self.assertIn("B4", output)
        # ... but neither the resolved rail mapping (B1) nor the low-severity
        # debugfs item (B4) may appear in the list of blockers that must be
        # resolved before hardware can be attempted.
        gating_section = output.split("must be resolved through an authorized source:", 1)[-1]
        self.assertNotIn("B1", gating_section)
        self.assertNotIn("B4", gating_section)

    def test_cli_reports_missing_fixture(self) -> None:
        buffer = io.StringIO()
        with contextlib.redirect_stderr(buffer):
            code = V.main([str(FIXTURE_PATH) + ".does-not-exist"])
        self.assertNotEqual(code, 0)

    def test_normal_evidence_checks_stay_green_despite_the_hardware_gate(self) -> None:
        """The hardware gate must not paint ordinary evidence validation red."""
        report = V.validate_document(self.doc(), path=str(FIXTURE_PATH))
        self.assertTrue(report.fixture_valid, report.errors)
        self.assertEqual(report.errors, [])
        self.assertFalse(report.hardware_ready)

    def test_report_is_json_serialisable(self) -> None:
        report = V.validate_document(self.doc(), path=str(FIXTURE_PATH))
        payload = json.dumps(report.to_dict(), sort_keys=True)
        round_tripped = json.loads(payload)
        self.assertTrue(round_tripped["fixture_valid"])
        self.assertFalse(round_tripped["hardware_ready"])
        self.assertTrue(round_tripped["hardware_blockers"])
        self.assertEqual(round_tripped["errors"], [])
        self.assertEqual(round_tripped["evidence_criteria_unmet"], [])
        self.assertTrue(round_tripped["derived"]["wire_byte_order"]["msb_first"])
        self.assertEqual(round_tripped["derived"]["power_sequence"]["enable"], ["vddio", "vci"])

    def test_cli_json_flag_emits_parseable_json_even_when_the_gate_is_closed(self) -> None:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = V.main([str(FIXTURE_PATH), "--json", "--require-hardware-ready"])
        self.assertEqual(code, 2, "the closed gate must still drive the exit code in --json mode")
        payload = json.loads(buffer.getvalue())
        self.assertTrue(payload["fixture_valid"])
        self.assertFalse(payload["hardware_ready"])
        self.assertTrue(payload["hardware_blockers"])

    def test_fixture_still_untouched_after_the_whole_suite(self) -> None:
        after = hashlib.sha256(FIXTURE_PATH.read_text(encoding="utf-8").encode("utf-8")).hexdigest()
        self.assertEqual(after, self.pristine_file_sha256)
        self.assertRegex(after, r"^[0-9a-f]{64}$")
        # The fixture currently carries no doubled-slash path, so the
        # normalisation step is a no-op here and nothing was rewritten.
        self.assertNotIn("//soc", self.raw_text)
        self.assertEqual(self.raw_text.count("//"), 2, "only the two https:// remotes carry a double slash")


if __name__ == "__main__":
    unittest.main(verbosity=2)
