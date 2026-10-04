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
# Every candidate is checked for ELF class 64 / e_machine AArch64 before it
# is trusted, so a wrong-architecture file cannot silently reach the
# initramfs again.

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

# Strategy 1: Ubuntu's signed arm64 archive. The runner's own apt sources are
# restricted to amd64, so add an explicitly arch-pinned source for arm64
# instead of relying on whatever the image ships.
try_apt_arm64() {
  local d codename
  d="$(mktemp -d)"
  codename="$(. /etc/os-release && echo "${VERSION_CODENAME:-noble}")"
  printf 'deb [arch=arm64] http://archive.ubuntu.com/ubuntu %s main universe\n' \
    "$codename" | sudo tee /etc/apt/sources.list.d/arm64-only.list >/dev/null
  sudo dpkg --add-architecture arm64 >/dev/null 2>&1 || true
  sudo apt-get update -qq \
    -o Dir::Etc::sourcelist="sources.list.d/arm64-only.list" \
    -o Dir::Etc::sourceparts="-" \
    -o APT::Get::List-Cleanup="0" >/dev/null 2>&1 || true
  if ! ( cd "$d" && apt-get download busybox-static:arm64 >/dev/null 2>&1 ); then
    echo "  apt-get download busybox-static:arm64 failed" >&2
    return 1
  fi
  dpkg-deb -x "$d"/busybox-static_*arm64.deb "$d/root" >/dev/null 2>&1 || return 1
  verify_aarch64 "$d/root/bin/busybox" || return 1
  install -m 0755 "$d/root/bin/busybox" "$IRD/bin/busybox"
  echo "  busybox from Ubuntu arm64 archive"
}

# Strategy 2: cross-compile upstream busybox with the toolchain the runner
# already has. Self-contained, no dependency on multiarch apt at all.
try_cross_compile() {
  local d v=1.36.1
  d="$(mktemp -d)"
  echo "  cross-compiling busybox $v for arm64"
  (
    cd "$d" \
      && curl -fsSL --max-time 300 "https://busybox.net/downloads/busybox-$v.tar.bz2" -o bb.tar.bz2 \
      && ls -l bb.tar.bz2 \
      && tar -xjf bb.tar.bz2 \
      && cd "busybox-$v" \
      && make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- defconfig >/dev/null \
      && sed -i -e 's/^# CONFIG_STATIC is not set/CONFIG_STATIC=y/' \
                -e 's/^CONFIG_STATIC=n$/CONFIG_STATIC=y/' \
                -e 's/^CONFIG_TC=y$/# CONFIG_TC is not set/' \
                -e 's/^# CONFIG_TELNETD is not set/CONFIG_TELNETD=y/' \
                -e 's/^# CONFIG_UDHCPD is not set/CONFIG_UDHCPD=y/' .config \
      && grep -q '^CONFIG_STATIC=y' .config \
      && ! grep -q '^CONFIG_TC=y' .config \
      && make -j"$(nproc)" ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- >/dev/null
  ) || return 1
  verify_aarch64 "$d/busybox-$v/busybox" || return 1
  install -m 0755 "$d/busybox-$v/busybox" "$IRD/bin/busybox"
  echo "  busybox cross-compiled from source"
}

BB_CACHE="${HOME:-/tmp}/.cache/sirius-busybox"

rm -rf "$IRD"
mkdir -p "$IRD"/{bin,etc,proc,sys,dev,lib,lib64}
# Reuse a previously fetched/compiled copy when CI restored it from cache, so
# repeated pack runs do not re-download or re-compile busybox.
if verify_aarch64 "$BB_CACHE/busybox"; then
  install -m 0755 "$BB_CACHE/busybox" "$IRD/bin/busybox"
  echo "  busybox from cache ($BB_CACHE)"
else
  try_apt_arm64 || try_cross_compile || {
    echo "FATAL: could not obtain an AArch64 static busybox" >&2; exit 1; }
  mkdir -p "$BB_CACHE"
  cp "$IRD/bin/busybox" "$BB_CACHE/busybox"
fi
echo "initramfs busybox e_machine: $(od -An -tx1 -j18 -N2 "$IRD/bin/busybox" | tr -d ' \n') (b700 = AArch64)"

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
