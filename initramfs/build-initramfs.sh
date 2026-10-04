#!/usr/bin/env bash
# Tiny initramfs that brings up a shell over USB (RNDIS/ECM).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/out"; IRD="$OUT/initramfs-root"
mkdir -p "$OUT"

# --- obtain an AArch64 static busybox ------------------------------------
# The host busybox is x86-64. An initramfs for an arm64 kernel must contain
# an arm64 executable, otherwise execve() fails with ENOEXEC (-8) and the
# kernel panics with "No working init found".
#
# Source: Ubuntu's own signed arm64 archives (busybox-static:arm64) fetched
# through apt, so the package signature is verified. The extracted binary is
# then checked for ELF class 64 / e_machine AArch64 before it is trusted, so
# a wrong-architecture file can never silently reach the initramfs again.

verify_aarch64() {
  local f="$1" cls mach
  [ -f "$f" ] || return 1
  cls=$(od -An -tx1 -j4  -N1 "$f" | tr -d ' \n')
  mach=$(od -An -tx1 -j18 -N2 "$f" | tr -d ' \n')
  if [ "$cls" != "02" ] || [ "$mach" != "b700" ]; then
    echo "  rejected $f: elfclass=$cls e_machine=$mach (need 02 / b700)" >&2
    return 1
  fi
  return 0
}

fetch_arm64_busybox() {
  local d
  d="$(mktemp -d)"
  sudo dpkg --add-architecture arm64 >/dev/null 2>&1 || true
  sudo apt-get update -qq             >/dev/null 2>&1 || true
  if ! ( cd "$d" && apt-get download busybox-static:arm64 >/dev/null 2>&1 ); then
    echo "  apt-get download busybox-static:arm64 failed" >&2
    return 1
  fi
  dpkg-deb -x "$d"/busybox-static_*arm64.deb "$d/root" >/dev/null 2>&1 || return 1
  verify_aarch64 "$d/root/bin/busybox" || return 1
  install -m 0755 "$d/root/bin/busybox" "$IRD/bin/busybox"
}

rm -rf "$IRD"
mkdir -p "$IRD"/{bin,etc,proc,sys,dev,lib,lib64}
if ! fetch_arm64_busybox; then
  echo "FATAL: could not obtain an AArch64 static busybox" >&2
  exit 1
fi
echo "initramfs busybox: $(od -An -tx1 -j18 -N2 "$IRD/bin/busybox" | tr -d ' \n') (e_machine, b700 = AArch64)"

for a in sh ls cat mount umount echo ip ifconfig udhcpd udhcpc \
         mdev sleep mkdir ln dmesg reboot poweroff; do
  ln -sf /bin/busybox "$IRD/bin/$a"
done

cat > "$IRD/init" <<'INIT_EOF'
#!/bin/busybox sh
/bin/busybox --install -s
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev 2>/dev/null || mdev -s
echo "=== sirius initramfs ==="
cat /proc/version
dmesg | tail -n 40
if [ -d /sys/kernel/config ]; then
  mount -t configfs none /sys/kernel/config 2>/dev/null || true
  G=/sys/kernel/config/usb_gadget/g1
  mkdir -p "$G" 2>/dev/null || true
  echo 0x2717 > "$G/idVendor" 2>/dev/null || true
  echo 0xff48 > "$G/idProduct" 2>/dev/null || true
  mkdir -p "$G/configs/c.1" "$G/functions/rndis.usb0" 2>/dev/null || true
  ln -sf "$G/functions/rndis.usb0" "$G/configs/c.1/" 2>/dev/null || true
  UDC=$(ls /sys/class/udc | head -1)
  echo "$UDC" > "$G/UDC" 2>/dev/null || true
fi
ifconfig usb0 172.16.42.1 netmask 255.255.0.0 up 2>/dev/null || true
echo "Listening on 172.16.42.1 (telnetd :23)"
telnetd -l /bin/sh -p 23 2>/dev/null || true
exec /bin/sh
INIT_EOF
chmod +x "$IRD/init"

( cd "$IRD" && find . | cpio -o -H newc | gzip -9 ) > "$OUT/initramfs.cpio.gz"
echo "initramfs -> $OUT/initramfs.cpio.gz ($(stat -c%s "$OUT/initramfs.cpio.gz") bytes)"
