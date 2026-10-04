#!/usr/bin/env python3
"""Wrap a DTB into a Qualcomm qcdt table mirroring the sirius stock layout.

Stock sirius qcdt: 32-byte header (BE) with tail fields (0x34,0x20,0x1000,0),
then N 32-byte entries (dt_size, dt_offset, id=0, rev=0, custom[4]=0),
then the dtb payloads.
"""
import struct
import sys

HDR_TAIL = (0x34, 0x20, 0x1000, 0x0)
ENTRY_SIZE = 32


def build(dtb, nentries):
    table_off = 32
    dtb_off = table_off + nentries * ENTRY_SIZE
    total = dtb_off + len(dtb)
    hdr = struct.pack(">8I", 0xd7b7ab1e, total, nentries, ENTRY_SIZE, *HDR_TAIL)
    ent = struct.pack(">8I", len(dtb), dtb_off, 0, 0, 0, 0, 0, 0)
    return hdr + ent * nentries + dtb


if __name__ == "__main__":
    src, out, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
    blob = build(open(src, "rb").read(), n)
    open(out, "wb").write(blob)
    print("qcdt %s entries=%d size=%d" % (out, n, len(blob)))
