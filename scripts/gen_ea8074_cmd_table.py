#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Decode the pinned EA8074 on/off command arrays out of the read-only evidence
# fixture and emit / verify the C init sequences used by
# patches/linux/0002-drm-panel-samsung-ea8074.patch.
#
# This script is deliberately dependency-free and read-only: it parses
# config/ea8074-evidence.json in memory, verifies the pinned SHA256 digests of
# the raw byte arrays, and prints the per-record decode plus the C table. It
# never writes to the fixture, the device or the kernel tree.
#
# Sources (both pinned, neither bulk-downloaded):
#   fixture  : config/ea8074-evidence.json
#              init_commands.on.bytes_hex  204 bytes / 21 records
#              init_commands.off.bytes_hex  18 bytes /  2 records
#              packet_type_deviation       the documented wire-type deviation
#   format   : downstream SDM710-Development/android_kernel_xiaomi_sdm710
#              @06a01bad75939c58be53418f5d71d9d2e25634cf, 7-byte record header
#              [dtype, last, vc, ack, wait_ms, dlen_hi, dlen_lo] + payload
#   wiresem  : sdm670-mainline/linux @75d5a9875202673b11a8eac05e6f489ba0c87a05
#              drivers/gpu/drm/drm_mipi_dsi.c
#                mipi_dsi_dcs_write_buffer() picks the DCS data type from the
#                transmit buffer length: 1 -> 0x05 short write, 2 -> 0x15 short
#                write with parameter, >= 3 -> 0x39 long write (L929-944).
#                mipi_dsi_dcs_write_seq_multi(ctx, cmd, seq...) sends
#                { cmd, seq }, so its wire length is 1 + len(seq) (header
#                L438-442); the named DCS helpers send a single command byte
#                (drm_mipi_dsi.c L1648-1660, L1698-1710).
#
# What the verifier checks, per record and in order:
#   * the data type that will actually be on the wire, not just the bytes
#   * the wire payload bytes
#   * the post-record wait
# The data type is derived from the pinned helper semantics above, never
# assumed: a driver edit that changes one record's packet type is a failure
# even when the payload bytes stay identical.
#
# Known, documented deviation (NOT an equivalence claim):
#   13 records of the on array are vendor dtype 0x39 with a 2-byte payload;
#   the length-based helper emits them as 0x15. Whether the panel accepts that
#   is unverified and is recorded as a blocker in the fixture
#   (packet_type_deviation, status "unverified_hardware_blocker").
#   --report-diff prints the record-by-record table and passes only while the
#   observed deviation is exactly the fixture-documented one; --check-c alone
#   is strict and fails on any deviation, including that one.

import argparse
import hashlib
import json
import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(REPO_ROOT, "config", "ea8074-evidence.json")
PATCH = os.path.join(REPO_ROOT, "patches", "linux",
                     "0002-drm-panel-samsung-ea8074.patch")

HEADER_BYTES = 7
DTYPE_SHORT_WRITE = 0x05
DTYPE_SHORT_WRITE_PARAM = 0x15
DTYPE_LONG_WRITE = 0x39

TYPE_NAMES = {
    DTYPE_SHORT_WRITE: "SHORT_WRITE(no param)",
    DTYPE_SHORT_WRITE_PARAM: "SHORT_WRITE_PARAM",
    DTYPE_LONG_WRITE: "LONG_WRITE",
    0x29: "GENERIC_LONG_WRITE",
}

# Allowed values of packet_type_deviation.<array>.status. The only status a
# non-empty deviation may carry is the explicit "unverified" one: a fixture edit
# must not be able to upgrade an unproven packet-format difference into an
# equivalence claim. An empty deviation must carry the "match" status.
STATUS_UNVERIFIED = "unverified_hardware_blocker"
STATUS_MATCH = "match"
ALLOWED_STATUS = (STATUS_UNVERIFIED, STATUS_MATCH)


def wire_dtype(length):
    """DCS data type mipi_dsi_dcs_write_buffer() uses for `length` bytes."""
    if length == 1:
        return DTYPE_SHORT_WRITE
    if length == 2:
        return DTYPE_SHORT_WRITE_PARAM
    if length >= 3:
        return DTYPE_LONG_WRITE
    raise SystemExit("a DCS write of 0 bytes is rejected by the helper (-EINVAL)")


class Record:
    """One vendor command-array record."""

    def __init__(self, dtype, last, vc, ack, wait_ms, payload):
        self.dtype = dtype
        self.last = last
        self.vc = vc
        self.ack = ack
        self.wait_ms = wait_ms
        self.payload = payload

    @property
    def dlen(self):
        return len(self.payload)

    @property
    def wire_payload(self):
        """Payload as it goes on the wire, as a tuple of ints.

        A vendor 0x05 record stores the DCS command in byte 0 and a 0x00 pad
        byte in byte 1; a short write without parameter carries only the
        command byte, so the pad must not be sent.
        """
        if self.dtype == DTYPE_SHORT_WRITE:
            if self.dlen != 2:
                raise SystemExit("unexpected dtype 0x05 record with dlen=%d"
                                 % self.dlen)
            if self.payload[1] != 0x00:
                raise SystemExit("dtype 0x05 padding byte is not zero")
            return (self.payload[0],)
        return tuple(self.payload)

    @property
    def wire_dtype(self):
        return self.dtype

    def __str__(self):
        name = TYPE_NAMES.get(self.dtype, "unknown")
        return ("dtype=0x%02x %-21s last=%d vc=%d ack=%d wait=%3dms dlen=%d "
                "payload=%s" % (self.dtype, name, self.last, self.vc, self.ack,
                                self.wait_ms, self.dlen,
                                self.payload.hex(" ")))


def parse_records(name, entry, header_bytes=HEADER_BYTES):
    """Parse one qcom,mdss-dsi-*-command byte array and check its digest."""
    raw = bytes.fromhex(entry["bytes_hex"])
    digest = hashlib.sha256(raw).hexdigest()
    if digest != entry["sha256"]:
        raise SystemExit("%s: sha256 mismatch, fixture is not the pinned array"
                         % name)
    records = []
    off = 0
    while off < len(raw):
        hdr = raw[off:off + header_bytes]
        if len(hdr) < header_bytes:
            raise SystemExit("%s: truncated header at offset %d" % (name, off))
        dtype, last, vc, ack, wait_ms, dlen_hi, dlen_lo = hdr
        dlen = (dlen_hi << 8) | dlen_lo
        payload = raw[off + header_bytes:off + header_bytes + dlen]
        if len(payload) != dlen:
            raise SystemExit("%s: truncated payload at offset %d" % (name, off))
        records.append(Record(dtype, last, vc, ack, wait_ms, payload))
        off += header_bytes + dlen
    if off != len(raw):
        raise SystemExit("%s: parser did not consume the array exactly" % name)
    return raw, records


def load():
    with open(FIXTURE, encoding="utf-8") as fh:
        fixture = json.load(fh)
    on_raw, on_records = parse_records("on-command",
                                       fixture["init_commands"]["on"])
    off_raw, off_records = parse_records("off-command",
                                        fixture["init_commands"]["off"])
    return fixture, (on_raw, on_records), (off_raw, off_records)


def c_args(record):
    """Payload arguments as the C helper should receive them.

    This is exactly what must be on the wire, so the emitted data type follows
    from the length of this list (see wire_dtype()).
    """
    return list(record.wire_payload)


def fixture_label(path=None):
    """Short name of the fixture for messages (relpath when on the same drive)."""
    path = path or FIXTURE
    try:
        return os.path.relpath(path, REPO_ROOT)
    except ValueError:  # e.g. the fixture was redirected to another drive
        return path


def report(fixture, on, off):
    print("fixture          : %s" % fixture_label())
    print("model            : %s / %s"
          % (fixture["device"]["model"], fixture["device"]["codename"]))
    print("pinned panel     : %s" % fixture["panel"]["fdt_path"])
    print()
    for name, (raw, records) in (("qcom,mdss-dsi-on-command", on),
                                 ("qcom,mdss-dsi-off-command", off)):
        deviating = [r for r in records
                     if r.wire_dtype != wire_dtype(len(r.wire_payload))]
        print("%s: %d bytes, %d records, total wait %d ms"
              % (name, len(raw), len(records),
                 sum(r.wait_ms for r in records)))
        print("  wire types: %s"
              % ", ".join("0x%02x->0x%02x" % (r.wire_dtype,
                                              wire_dtype(len(r.wire_payload)))
                          for r in records))
        print("  records whose emitted type differs from the vendor type: %d"
              % len(deviating))
        for index, record in enumerate(records):
            print("  %2d %s" % (index, record))
        print()
    return 0


def emit_c(on, off):
    print("/* ---- qcom,mdss-dsi-on-command (204 bytes, 21 records) ---- */")
    for index, record in enumerate(on[1]):
        args = ", ".join("0x%02x" % byte for byte in c_args(record))
        emitted = wire_dtype(len(c_args(record)))
        if record.dtype == DTYPE_SHORT_WRITE:
            note = ("   /* vendor dtype 0x05: short write, no parameter, "
                    "0x%02x pad dropped -> emitted dtype 0x%02x */"
                    % (record.payload[1], emitted))
        elif emitted != record.dtype:
            note = ("   /* record %d: vendor dtype 0x%02x dlen %d -> emitted "
                    "dtype 0x%02x short write with 1 param */"
                    % (index, record.dtype, record.dlen, emitted))
        else:
            note = ("   /* vendor dtype 0x%02x -> emitted dtype 0x%02x */"
                    % (record.dtype, emitted))
        print("\tmipi_dsi_dcs_write_seq_multi(&dsi_ctx, %s);%s" % (args, note))
        if record.wait_ms:
            print("\tmipi_dsi_msleep(&dsi_ctx, %d);" % record.wait_ms)
    return 0


# One-byte records are emitted through the named DCS helpers; the payload byte
# tells which helper the driver must use. Every one of them sends a single DCS
# command byte, i.e. data type 0x05.
NAMED_HELPERS = {
    0x10: "mipi_dsi_dcs_enter_sleep_mode_multi",
    0x11: "mipi_dsi_dcs_exit_sleep_mode_multi",
    0x28: "mipi_dsi_dcs_set_display_off_multi",
    0x29: "mipi_dsi_dcs_set_display_on_multi",
}

CALL = re.compile(
    r"(?:mipi_dsi_dcs_write_seq_multi\(\s*&\w+\s*(?P<bytes>(?:,\s*0x[0-9a-fA-F]{2})+)\s*\))"
    r"|(?P<helper>%s)\(\s*&\w+\s*\)"
    r"|(?:mipi_dsi_msleep\(\s*&\w+\s*,\s*(?P<ms>\d+)\s*\))"
    % "|".join(NAMED_HELPERS.values()))


class Emitted:
    """One (wire type, wire payload) pair the driver will actually send."""

    def __init__(self, dtype, payload):
        self.dtype = dtype
        self.payload = tuple(payload)

    def __eq__(self, other):
        return (self.dtype, self.payload) == (other.dtype, other.payload)

    def __str__(self):
        return "0x%02x %s" % (self.dtype, list(self.payload))


def driver_writes(source, function):
    """(Emitted, wait_ms) pairs of one driver function body, in order."""
    match = re.search(r"^static [^\n]*\b%s\([^\n]*\n\{" % function, source,
                      re.M)
    if not match:
        raise SystemExit("cannot find the definition of %s()" % function)
    body = source[match.end():]
    end = body.find("\n}")
    if end < 0:
        raise SystemExit("cannot find the end of %s()" % function)
    body = re.sub(r"/\*.*?\*/", "", body[:end], flags=re.S)

    writes = []
    for call in CALL.finditer(body):
        if call.group("bytes"):
            payload = [int(b, 16)
                       for b in re.findall(r"0x[0-9a-fA-F]{2}",
                                           call.group("bytes"))]
            writes.append([Emitted(wire_dtype(len(payload)), payload), 0])
        elif call.group("helper"):
            for command, helper in NAMED_HELPERS.items():
                if helper == call.group("helper"):
                    writes.append([Emitted(DTYPE_SHORT_WRITE, [command]), 0])
                    break
        else:
            if writes:
                writes[-1][1] = int(call.group("ms"))
    return [(w[0], w[1]) for w in writes]


def compare(function, records, source):
    """Per-record comparison of vendor vs emitted packet.

    Returns (rows, type_only, hard) where each row carries the vendor and
    emitted data type / payload / wait plus a verdict, `type_only` lists the
    indices whose only difference is the DCS data type, and `hard` is True when
    anything else differs (payload, wait, cardinality).
    """
    got = driver_writes(source, function)
    rows = []
    type_only = []
    hard = False
    if len(got) != len(records):
        hard = True
    for index in range(max(len(records), len(got))):
        record = records[index] if index < len(records) else None
        emit = got[index] if index < len(got) else None
        row = {
            "index": index,
            "vendor_dtype": record.wire_dtype if record else None,
            "vendor_payload": record.wire_payload if record else None,
            "vendor_wait": record.wait_ms if record else None,
            "emitted_dtype": emit[0].dtype if emit else None,
            "emitted_payload": emit[0].payload if emit else None,
            "emitted_wait": emit[1] if emit else None,
        }
        vendor = (row["vendor_dtype"], row["vendor_payload"], row["vendor_wait"])
        emitted = (row["emitted_dtype"], row["emitted_payload"],
                   row["emitted_wait"])
        if vendor == emitted:
            row["verdict"] = "match"
        elif None in (row["vendor_dtype"], row["emitted_dtype"]):
            row["verdict"] = "RECORD-COUNT"
            hard = True
        elif (row["vendor_payload"] != row["emitted_payload"]
              or row["vendor_wait"] != row["emitted_wait"]):
            row["verdict"] = "PAYLOAD/WAIT"
            hard = True
        else:
            row["verdict"] = "TYPE-DIFF"
            type_only.append(index)
        rows.append(row)
    return rows, type_only, hard


def print_rows(function, rows):
    print("%s: %d rows" % (function, len(rows)))
    print("   idx  verdict       vendor type  payload      wait   "
          "emitted type  payload      wait")
    for row in rows:
        vp = ("[%s]" % " ".join("%02x" % b for b in row["vendor_payload"])) \
            if row["vendor_payload"] is not None else "-"
        ep = ("[%s]" % " ".join("%02x" % b for b in row["emitted_payload"])) \
            if row["emitted_payload"] is not None else "-"
        print("  %4d  %-13s 0x%02x        %-12s %-6s 0x%02x (%s)  %-12s %-6s"
              % (row["index"], row["verdict"],
                 row["vendor_dtype"] if row["vendor_dtype"] is not None else 0,
                 vp,
                 ("%dms" % row["vendor_wait"])
                 if row["vendor_wait"] is not None else "-",
                 row["emitted_dtype"] if row["emitted_dtype"] is not None else 0,
                 TYPE_NAMES.get(row["emitted_dtype"], "n/a"),
                 ep,
                 ("%dms" % row["emitted_wait"])
                 if row["emitted_wait"] is not None else "-"))


def documented_deviation(fixture, key):
    dev = fixture.get("packet_type_deviation")
    if not isinstance(dev, dict):
        return None, None
    entry = dev.get(key)
    if not isinstance(entry, dict):
        return dev, None
    return dev, entry


def check_driver(path, fixture, on, off):
    """Strict check: every packet, including its data type, must match."""
    source = open(path, encoding="utf-8").read()
    rc = 0
    for function, records in (("ea8074_on", on[1]),
                              ("ea8074_off_display", off[1][:1]),
                              ("ea8074_sleep_in", off[1][1:])):
        rows, type_only, hard = compare(function, records, source)
        if not type_only and not hard:
            print("%-20s matches the fixture (%d records, packet type "
                  "included)" % (function, len(rows)))
            continue
        rc = 1
        print_rows(function, rows)
        if type_only:
            print("  %d record(s) differ in the DCS data type only: %s"
                  % (len(type_only), type_only))
        if hard:
            print("  hard mismatch (payload/wait/order/count) - not "
                  "acceptable under any mode")
    return rc


def report_type_deviation(path, fixture, on, off):
    """Print the full table and pass only if the deviation is the documented one.

    This mode never claims packet equivalence: it asserts that the observed
    data-type deviation is exactly the one recorded in the fixture together
    with its (unverified) status, so a change in either direction is caught.
    """
    source = open(path, encoding="utf-8").read()
    rc = 0
    arrays = {
        "on": ("ea8074_on", on[1]),
        "off_display": ("ea8074_off_display", off[1][:1]),
        "sleep_in": ("ea8074_sleep_in", off[1][1:]),
    }
    for key, (function, records) in arrays.items():
        rows, type_only, hard = compare(function, records, source)
        print_rows(function, rows)
        doc, entry = documented_deviation(fixture, key)
        expected = entry.get("expected_type_diff_records") if entry else None
        status = str(entry.get("status", "")).strip() if entry else ""
        print("  observed type-diff records : %s (%d)"
              % (type_only, len(type_only)))
        print("  documented type-diff records: %s (%s)"
              % (expected, status or "no entry for this array"))
        if hard:
            print("  FAIL: payload/wait/order/count mismatch at the record(s) "
                  "listed above; this is not a packet-type deviation and is "
                  "not acceptable in any mode")
            rc = 1
        elif not entry:
            print("  FAIL: no packet_type_deviation entry for this array in "
                  "%s; the deviation cannot be validated as the known one"
                  % fixture_label())
            rc = 1
        elif status not in ALLOWED_STATUS:
            print("  FAIL: packet_type_deviation.%s.status is %r, which is not "
                  "one of %s; a status is not allowed to claim packet "
                  "equivalence, that needs a vendor-comparable trace"
                  % (key, status, list(ALLOWED_STATUS)))
            rc = 1
        elif set(type_only) < set(expected or []):
            print("  FAIL: fewer type differences than the fixture documents "
                  "(observed %s, documented %s); if the driver really stopped "
                  "deviating, update the fixture deliberately"
                  % (type_only, expected))
            rc = 1
        elif set(type_only) > set(expected or []):
            print("  FAIL: undocumented type difference at record(s) %s "
                  "(documented: %s)"
                  % (sorted(set(type_only) - set(expected or [])), expected))
            rc = 1
        elif expected != type_only:
            print("  FAIL: the deviation set matches but its order changed "
                  "(observed %s, documented %s)" % (type_only, expected))
            rc = 1
        elif not type_only:
            if status != STATUS_MATCH:
                print("  FAIL: no packet-type difference was observed but the "
                      "fixture still records status %r; the fixture must be "
                      "updated deliberately" % status)
                rc = 1
            else:
                print("  every record matches exactly, data type included: no "
                      "deviation and no equivalence claim needed")
        elif status != STATUS_UNVERIFIED:
            print("  FAIL: %d record(s) still differ in the DCS data type but "
                  "the fixture records status %r instead of %r; equivalence "
                  "is not established by this check"
                  % (len(type_only), status, STATUS_UNVERIFIED))
            rc = 1
        else:
            print("  the deviation is exactly the documented one; packet-type "
                  "equivalence is NOT verified (%s)" % status)
    return rc


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--c", action="store_true",
                        help="also print the C command table")
    parser.add_argument("--check-c", metavar="FILE",
                        help="verify that FILE (panel driver source) emits "
                             "exactly the packets and waits of the fixture, "
                             "data type included (strict: any type difference "
                             "fails)")
    parser.add_argument("--report-diff", action="store_true",
                        help="with --check-c: print the record-by-record "
                             "type table and pass only while the observed "
                             "deviation equals the fixture-documented one "
                             "(never an equivalence claim)")
    args = parser.parse_args(argv)

    fixture, on, off = load()
    rc = report(fixture, on, off)
    if args.c:
        rc |= emit_c(on, off)
    if args.check_c:
        if args.report_diff:
            rc |= report_type_deviation(args.check_c, fixture, on, off)
        else:
            rc |= check_driver(args.check_c, fixture, on, off)
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
