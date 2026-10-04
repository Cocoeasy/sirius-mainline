#!/usr/bin/env bash
# Tiny initramfs that brings up a shell over USB (RNDIS/ECM).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/out"; IRD="$OUT/initramfs-root"
mkdir -p "$OUT"

BB="$(command -v busybox || true)"
if [ -z "$BB" ]; then
  sudo apt-get install -y busybox-static
  BB="$(command -v busybox)"
fi

rm -rf "$IRD"
mkdir -p "$IRD"/{bin,etc,proc,sys,dev,lib,lib64}
cp "$BB" "$IRD/bin/busybox"; chmod +x "$IRD/bin/busybox"
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
