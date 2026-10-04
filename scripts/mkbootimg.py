#!/usr/bin/env python3
"""Dependency-free Android boot image (header v1) packer for xiaomi-sirius.

Header v1 layout (little-endian):
  magic[8] "ANDROID!"
  kernel_size, kernel_addr, ramdisk_size, ramdisk_addr,
  second_size, second_addr, tags_addr, page_size  (u32 each)
  header_version, os_version (u32)
  name[16], cmdline[512], id[8], extra_cmdline[1024]
  -> padded to page_size

sirius: BOARD_BOOT_HEADER_VERSION=1, BOARD_KERNEL_SEPARATED_DTBO=true.
With v1 the DTB is appended to the kernel (Image.gz + dtb).
"""
import hashlib, struct, sys

PAGE = 4096
KERNEL_ADDR = 0x00008000
RAMDISK_ADDR = 0x01000000
TAGS_ADDR = 0x00000100
NAME = b"sirius"
CMDLINE = (b"console=ttyMSM0,115200n8 earlycon=msm_geni_serial,0xA90000 "
           b"androidboot.hardware=qcom androidboot.console=ttyMSM0 loop.max_part=7")


def pad(d, page):
    r = len(d) % page
    return d + (b"\x00" * (page - r) if r else b"")


def main(kernel_path, dtb_path, ramdisk_path, out_path):
    kernel = open(kernel_path, "rb").read()
    dtb = open(dtb_path, "rb").read()
    ramdisk = open(ramdisk_path, "rb").read()

    kwd = kernel + dtb  # header v1: dtb appended to kernel

    h = hashlib.sha1()
    h.update(kwd); h.update(ramdisk); h.update(b"")
    img_id = h.digest()[:8]

    header = struct.pack("<8sIIIIIIII", b"ANDROID!",
                         len(kwd), KERNEL_ADDR,
                         len(ramdisk), RAMDISK_ADDR,
                         0, 0, TAGS_ADDR, PAGE)
    header += struct.pack("<I", 1)   # header_version
    header += struct.pack("<I", 0)   # os_version
    header += NAME.ljust(16, b"\x00")[:16]
    header += CMDLINE.ljust(512, b"\x00")[:512]
    header += img_id
    header += b"\x00" * 1024

    if len(header) > PAGE:
        sys.exit(f"header {len(header)} > page {PAGE}")

    img = pad(header, PAGE) + pad(kwd, PAGE) + pad(ramdisk, PAGE)
    open(out_path, "wb").write(img)
    print(f"boot.img -> {out_path} ({len(img)} bytes)")


if __name__ == "__main__":
    if len(sys.argv) != 5:
        sys.exit("usage: mkbootimg.py <Image.gz> <dtb> <initramfs.cpio.gz> <out/boot.img>")
    main(*sys.argv[1:])
