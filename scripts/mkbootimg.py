#!/usr/bin/env python3
"""Packer for xiaomi-sirius boot images (header v2, matching the stock layout).

Stock sirius layout (measured from the vendor image):
  [v1-shaped header 0..1632]
    @1632 dtb_size    (u32)
    @1636 dtb_addr    (u64)  = file offset of the dtb blob
    @1644 header_size (u32) = 1660
    @1648 pad[12]
  -> 1660 bytes, padded to page_size
  then: kernel, ramdisk, dtb blob (each page-aligned)

v1 field layout (offsets): magic 0, kernel_size 8, kernel_addr 12,
ramdisk_size 16, ramdisk_addr 20, second_size 24, second_addr 28,
tags_addr 32, page_size 36, header_version 40, os_version 44,
name 48, cmdline 64, id 576 (32 bytes), extra_cmdline 608 (1024) -> 1632
"""
import hashlib
import struct
import sys

PAGE = 4096
KERNEL_ADDR = 0x00008000
RAMDISK_ADDR = 0x01000000
TAGS_ADDR = 0x00000100
NAME = b"sirius"
CMDLINE = (b"console=ttyMSM0,115200n8 earlycon=msm_geni_serial,0xA90000 "
           b"androidboot.hardware=qcom androidboot.console=ttyMSM0 loop.max_part=7 console=tty0")
HEADER_SIZE = 1660
ZERO = b"\x00"


def pad(d, page=PAGE):
    r = len(d) % page
    return d + (ZERO * (page - r) if r else b"")


def main(kernel_path, dtb_path, ramdisk_path, out_path):
    kernel = open(kernel_path, "rb").read()
    ramdisk = open(ramdisk_path, "rb").read()
    dtb = open(dtb_path, "rb").read()

    # dtb blob sits after header+kernel+ramdisk, each page aligned
    dtb_off = PAGE + len(pad(kernel)) + len(pad(ramdisk))

    digest = hashlib.sha1()
    digest.update(kernel)
    digest.update(ramdisk)
    digest.update(b"")
    img_id = digest.digest().ljust(32, ZERO)   # AOSP id[8] == 32 bytes

    hdr = struct.pack("<8sIIIIIIII", b"ANDROID!",
                      len(kernel), KERNEL_ADDR,
                      len(ramdisk), RAMDISK_ADDR,
                      0, 0, TAGS_ADDR, PAGE)
    hdr += struct.pack("<I", 2)                # header_version = 2
    hdr += struct.pack("<I", 0)                # os_version
    hdr += NAME.ljust(16, ZERO)[:16]
    hdr += CMDLINE.ljust(512, ZERO)[:512]
    hdr += img_id
    hdr += ZERO * 1024
    assert len(hdr) == 1632, len(hdr)

    hdr += struct.pack("<I", len(dtb))         # dtb_size    @1632
    hdr += struct.pack("<Q", dtb_off)          # dtb_addr    @1636
    hdr += struct.pack("<I", HEADER_SIZE)      # header_size @1644
    hdr += ZERO * 12                           # pad to 1660
    assert len(hdr) == HEADER_SIZE, len(hdr)

    img = pad(hdr) + pad(kernel) + pad(ramdisk) + pad(dtb)
    with open(out_path, "wb") as f:
        f.write(img)
    print("boot.img -> %s (%d bytes)  dtb_off=%d dtb_size=%d"
          % (out_path, len(img), dtb_off, len(dtb)))


if __name__ == "__main__":
    if len(sys.argv) != 5:
        sys.exit("usage: mkbootimg.py <Image.gz> <dtb> <initramfs.cpio.gz> <out>")
    main(*sys.argv[1:])
