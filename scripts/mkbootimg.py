#!/usr/bin/env python3
"""Packer for xiaomi-sirius boot images.

Format verified against a pmOS-generated image that the sirius ABL accepts:
  header_version = 0, no separate dtb field; the DTB is APPENDED to the kernel
  (Image.gz + dtb), i.e. the classic "Image.gz-dtb" layout.

Layout: [header, page aligned][kernel+dtb][ramdisk]
Header field offsets: magic 0, kernel_size 8, kernel_addr 12, ramdisk_size 16,
ramdisk_addr 20, second_size 24, second_addr 28, tags_addr 32, page_size 36,
header_version 40, os_version 44, name 48, cmdline 64, id 576 (32 B),
extra_cmdline 608 (1024) -> 1632 bytes.
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
           b"androidboot.hardware=qcom androidboot.console=ttyMSM0 loop.max_part=7 console=tty0 "
           b"clk_ignore_unused pd_ignore_unused")
ZERO = b"\x00"


def pad(d, page=PAGE):
    r = len(d) % page
    return d + (ZERO * (page - r) if r else b"")


def main(kernel_path, dtb_path, ramdisk_path, out_path):
    kernel = open(kernel_path, "rb").read()
    dtb = open(dtb_path, "rb").read()
    ramdisk = open(ramdisk_path, "rb").read()

    kwd = kernel + dtb            # DTB appended to the kernel

    digest = hashlib.sha1()
    digest.update(kwd)
    digest.update(ramdisk)
    digest.update(b"")
    img_id = digest.digest().ljust(32, ZERO)   # AOSP id[8] == 32 bytes

    hdr = struct.pack("<8sIIIIIIII", b"ANDROID!",
                      len(kwd), KERNEL_ADDR,
                      len(ramdisk), RAMDISK_ADDR,
                      0, 0, TAGS_ADDR, PAGE)
    hdr += struct.pack("<I", 0)                # header_version = 0
    hdr += struct.pack("<I", 0)                # os_version
    hdr += NAME.ljust(16, ZERO)[:16]
    hdr += CMDLINE.ljust(512, ZERO)[:512]
    hdr += img_id
    hdr += ZERO * 1024
    assert len(hdr) == 1632, len(hdr)

    img = pad(hdr) + pad(kwd) + pad(ramdisk)
    with open(out_path, "wb") as f:
        f.write(img)
    print("boot.img -> %s (%d bytes)  kernel(incl dtb)=%d dtb=%d"
          % (out_path, len(img), len(kwd), len(dtb)))


if __name__ == "__main__":
    if len(sys.argv) != 5:
        sys.exit("usage: mkbootimg.py <Image.gz> <dtb> <initramfs.cpio.gz> <out>")
    main(*sys.argv[1:])
