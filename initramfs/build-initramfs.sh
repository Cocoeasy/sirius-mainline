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
                -e 's/^# CONFIG_UDHCPD is not set/CONFIG_UDHCPD=y/' \
                -e 's/^# CONFIG_MKFS_EXT2 is not set/CONFIG_MKFS_EXT2=y/' \
                -e 's/^# CONFIG_MKE2FS is not set/CONFIG_MKE2FS=y/' \
                -e 's/^# CONFIG_SWITCH_ROOT is not set/CONFIG_SWITCH_ROOT=y/' .config \
      && grep -q '^CONFIG_STATIC=y' .config \
      && ! grep -q '^CONFIG_TC=y' .config \
      && make -j"$(nproc)" ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- >/dev/null
  ) || return 1
  verify_aarch64 "$d/busybox-$v/busybox" || return 1
  install -m 0755 "$d/busybox-$v/busybox" "$IRD/bin/busybox"
  echo "  busybox cross-compiled from source"
}

BB_CACHE="${HOME:-/tmp}/.cache/sirius-busybox"

# --- Alpine rootfs payload ------------------------------------------------
# Carried inside the initramfs and unpacked onto the eMMC on first boot, so
# no host-side network transfer is needed to get a userland onto the device.
ALPINE_URL="https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/aarch64/alpine-minirootfs-3.20.9-aarch64.tar.gz"

rm -rf "$IRD"
# sbin matters: busybox --install -s places applets such as mke2fs and
# switch_root in /sbin, and without that directory they get no command entry
# at all ("mke2fs: not found").
mkdir -p "$IRD"/{bin,sbin,etc,proc,sys,dev,lib,lib64}
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

# Alpine minirootfs payload, unpacked to the eMMC by /init on first boot.
ALPINE_CACHE="${HOME:-/tmp}/.cache/sirius-alpine"
ALPINE_TGZ="alpine-minirootfs-3.20.9-aarch64.tar.gz"
mkdir -p "$ALPINE_CACHE"
if [ -s "$ALPINE_CACHE/$ALPINE_TGZ" ] && gzip -t "$ALPINE_CACHE/$ALPINE_TGZ" 2>/dev/null; then
  echo "  alpine rootfs from cache"
else
  echo "  downloading $ALPINE_URL"
  curl -fsSL --max-time 300 "$ALPINE_URL" -o "$ALPINE_CACHE/$ALPINE_TGZ"
  gzip -t "$ALPINE_CACHE/$ALPINE_TGZ"
fi
cp "$ALPINE_CACHE/$ALPINE_TGZ" "$IRD/alpine-rootfs.tar.gz"
echo "  alpine payload: $(stat -c%s "$IRD/alpine-rootfs.tar.gz") bytes"

for a in sh ls cat mount umount echo ip ifconfig udhcpd udhcpc \
         mdev sleep mkdir ln dmesg reboot poweroff \
         readlink basename sync head tail true setsid tr; do
  ln -sf /bin/busybox "$IRD/bin/$a"
done

cat > "$IRD/init" <<'INIT_EOF'
#!/bin/busybox sh
/bin/busybox --install -s
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev 2>/dev/null || mdev -s

# Persist this boot log on the (ext4) cache partition. TWRP's own kernel
# overwrites the ramoops/pstore record, so a file here is the only log that
# survives to be read afterwards.
LOGDEV=""
mkdir -p /mnt/log
for d in /dev/block/by-name/cache /dev/block/mmcblk0p77; do
  [ -b "$d" ] || continue
  if mount -t ext4 "$d" /mnt/log 2>/dev/null; then LOGDEV="$d"; break; fi
done
LOG=""
[ -n "$LOGDEV" ] && LOG=/mnt/log/sirius-boot.log
say() { echo "$@"; [ -n "$LOG" ] && echo "$@" >> "$LOG"; }

if [ -n "$LOG" ]; then
  say "=== sirius initramfs boot log (logdev=$LOGDEV) ==="
else
  echo "=== sirius initramfs (no writable log partition) ==="
fi
say "$(cat /proc/version)"

say "--- USB topology ---"
say "udc:      $(ls /sys/class/udc 2>&1)"
say "extcon:   $(ls /sys/class/extcon 2>&1)"
say "a6f8800.usb driver:  $(basename "$(readlink -f /sys/bus/platform/devices/a6f8800.usb/driver 2>/dev/null)" 2>/dev/null)"
for p in /sys/bus/platform/devices/*usb*phy* /sys/bus/platform/devices/*hsphy*; do
  [ -e "$p" ] || continue
  say "phy $(basename "$p"): $(basename "$(readlink -f "$p/driver" 2>/dev/null)" 2>/dev/null)"
done

if [ -d /sys/kernel/config ]; then
  mount -t configfs none /sys/kernel/config 2>/dev/null || true
  G=/sys/kernel/config/usb_gadget/g1
  mkdir -p "$G" 2>/dev/null || say "gadget: cannot create $G"
  echo 0x2717 > "$G/idVendor" 2>/dev/null || true
  echo 0xff48 > "$G/idProduct" 2>/dev/null || true
  mkdir -p "$G/strings/0x409" "$G/configs/c.1/strings/0x409" 2>/dev/null || true
  echo "sirius-initramfs-0001" > "$G/strings/0x409/serialnumber" 2>/dev/null || true
  echo "sirius"                > "$G/strings/0x409/manufacturer" 2>/dev/null || true
  echo "sirius initramfs"      > "$G/strings/0x409/product"     2>/dev/null || true
  echo "acm+ncm"               > "$G/configs/c.1/strings/0x409/configuration" 2>/dev/null || true

  # CDC-ACM gives a COM port on Windows using its in-box serial driver; CDC-NCM
  # gives a network interface with the in-box NCM driver. Both install cleanly
  # where the RNDIS driver does not (CM_PROB_FAILED_INSTALL).
  for fn in acm.usb0 ncm.usb0; do
    if mkdir -p "$G/functions/$fn" 2>/dev/null; then
      ln -sf "$G/functions/$fn" "$G/configs/c.1/" 2>/dev/null || true
      say "gadget: function $fn ready"
    else
      say "gadget: function $fn unavailable"
    fi
  done

  UDC=$(ls /sys/class/udc 2>/dev/null | head -1)
  if [ -n "$UDC" ]; then
    echo "$UDC" > "$G/UDC" 2>/dev/null && say "gadget: bound to UDC $UDC" || say "gadget: bind to $UDC failed"
  else
    say "gadget: NO UDC present -> USB PHY/dwc3 did not come up"
  fi
fi

# Serial shell over the CDC-ACM port (Windows: a COMx port).
if [ -c /dev/ttyGS0 ]; then
  say "console: shell on /dev/ttyGS0 (USB CDC-ACM)"
  setsid /bin/sh -c 'exec /bin/sh </dev/ttyGS0 >/dev/ttyGS0 2>&1' &
else
  say "console: /dev/ttyGS0 missing"
fi

sleep 2
ifconfig usb0 172.16.42.1 netmask 255.255.0.0 up 2>/dev/null || true
say "network: usb0 -> 172.16.42.1 (telnetd :23)"
say "usb0 state: $(ifconfig usb0 2>&1 | tr '\n' ' ')"

dmesg | tail -n 60 >> "${LOG:-/dev/null}" 2>/dev/null
dmesg | tail -n 15
[ -n "$LOG" ] && sync && umount /mnt/log 2>/dev/null

# --- hand over to the eMMC rootfs ----------------------------------------
# The bootloader supplies its own root= (pointing at a PARTUUID that does not
# exist here), so the initramfs mounts the userdata partition itself and
# switch_roots into it. On the very first boot it formats the partition and
# unpacks the Alpine minirootfs carried inside this initramfs, so the device
# needs no host-side transfer to get a userland.
ROOTDEV=""
for d in /dev/mmcblk0p81 /dev/disk/by-name/userdata; do
  [ -b "$d" ] && { ROOTDEV="$d"; break; }
done

if [ -z "$ROOTDEV" ]; then
  say "rootfs: no eMMC userdata partition found"
else
  mkdir -p /newroot
  ROOT_MOUNTED=no
  mount -t ext4 "$ROOTDEV" /newroot 2>/dev/null && ROOT_MOUNTED=yes
  if [ "$ROOT_MOUNTED" = no ]; then
    say "rootfs: $ROOTDEV not formatted - creating ext filesystem (first boot)"
    # busybox's mke2fs has no -t option (unlike e2fsprogs); it always creates
    # an ext2 filesystem, which the kernel's ext4 driver mounts just fine.
    /bin/busybox mke2fs -F -L sirius-root "$ROOTDEV" 2>&1 | tail -n 2
    mount -t ext4 "$ROOTDEV" /newroot 2>/dev/null && ROOT_MOUNTED=yes
    if [ "$ROOT_MOUNTED" = no ]; then
      mount -t ext2 "$ROOTDEV" /newroot 2>/dev/null && ROOT_MOUNTED=yes
    fi
    [ "$ROOT_MOUNTED" = no ] && say "rootfs: mount after mkfs failed"
  fi

  if [ "$ROOT_MOUNTED" = no ]; then
    say "rootfs: cannot mount $ROOTDEV"
  else
    if [ ! -x /newroot/sbin/init ]; then
      say "rootfs: unpacking Alpine minirootfs onto $ROOTDEV"
      tar xzf /alpine-rootfs.tar.gz -C /newroot 2>&1 | tail -n 3
      [ -f /newroot/etc/inittab ] && \
        echo 'ttyGS0::respawn:/sbin/getty -L ttyGS0 115200 vt100' >> /newroot/etc/inittab
      [ -f /newroot/etc/inittab ] && \
        echo 'tty0::respawn:/sbin/getty -L tty0 115200 vt100' >> /newroot/etc/inittab
      mkdir -p /newroot/proc /newroot/sys /newroot/dev /newroot/root
      sync
      say "rootfs: unpacked $(ls /newroot | head -c 200)"
    fi
    if [ -x /newroot/sbin/init ]; then
      say "rootfs: switching to $ROOTDEV"
      exec /bin/busybox switch_root /newroot /sbin/init
    fi
    say "rootfs: no usable init on $ROOTDEV"
  fi
fi

say "falling back to initramfs debug shell"
telnetd -l /bin/sh -p 23 2>/dev/null || true
exec /bin/sh
INIT_EOF
chmod +x "$IRD/init"

( cd "$IRD" && find . | cpio -o -H newc | gzip -9 ) > "$OUT/initramfs.cpio.gz"
echo "initramfs -> $OUT/initramfs.cpio.gz ($(stat -c%s "$OUT/initramfs.cpio.gz") bytes)"
