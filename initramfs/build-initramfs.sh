#!/usr/bin/env bash
# Read-only handover to the existing Nura/pmOS image, with local ACM/NCM diagnostics.
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

# Use the existing Nura/pmOS image on userdata; never provision or replace it.

rm -rf "$IRD"
# sbin matters: busybox --install -s places applets such as mke2fs and
# switch_root in /sbin, and without that directory they get no command entry
# at all ("mke2fs: not found").
mkdir -p "$IRD"/{bin,sbin,usr/bin,usr/sbin,etc,proc,sys,dev,lib,lib64}
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

for a in sh ls cat mount umount echo ip ifconfig udhcpd udhcpc \
         mdev sleep mkdir ln dmesg reboot poweroff \
         readlink basename sync head tail true setsid tr; do
  ln -sf /bin/busybox "$IRD/bin/$a"
done

cat > "$IRD/init" <<'INIT_EOF'
#!/bin/busybox sh
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
/bin/busybox mkdir -p /bin /sbin /usr/bin /usr/sbin /proc /sys /dev /run /mnt/log /newroot
/bin/busybox --install -s
bb() { /bin/busybox "$@"; }
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null || mdev -s
mount -t tmpfs -o mode=0755,size=192m tmpfs /run
LOG=""
say() {
  echo "$@"
  for kmsg in /dev/kmsg /newroot/dev/kmsg; do
    if [ -c "$kmsg" ]; then echo "SIRIUS-EXISTING: $*" > "$kmsg" 2>/dev/null; break; fi
  done
  if [ -n "$LOG" ]; then echo "$@" >> "$LOG"; sync; fi
  return 0
}
serial_shell() {
  for tty in /dev/ttyGS0 /newroot/dev/ttyGS0; do
    if [ -c "$tty" ]; then
      setsid /bin/sh -c 'exec /bin/sh -i <"$1" >"$1" 2>&1' sh "$tty" &
      break
    fi
  done
}
fatal() {
  say "FAILED: $*; remaining in initramfs; no userdata writes"
  serial_shell
  while true; do sleep 60; done
}
say "init started"
i=0
while [ "$i" -lt 15 ]; do
  for d in /dev/mmcblk0p77 /dev/block/mmcblk0p77; do
    [ -b "$d" ] || continue
    if mount -t ext4 "$d" /mnt/log 2>/dev/null; then
      LOG=/mnt/log/sirius-existing.log
      [ -s "$LOG" ] && mv "$LOG" "$LOG.prev"
      : > "$LOG"
      break
    fi
  done
  [ -n "$LOG" ] && break
  sleep 1; i=$((i+1))
done
say "SIRIUS-EXISTING cache=$LOG"
say "$(cat /proc/version)"

# BEGIN ROOTFS_VALIDATION
# Read the bounded GPT layout used by the existing image. All reads are narrow;
# supporting another layout requires explicit validation, never guessing offsets.
read_u32() {
  _word=$(bb dd if="$1" bs=1 skip="$2" count=4 2>/dev/null | bb od -An -tu4 | bb tr -d ' \n')
  case "$_word" in ''|*[!0-9]*) return 1;; esac
  printf '%s\n' "$_word"
}
read_lba32() {
  _hi=$(read_u32 "$1" "$(($2+4))") || return 1
  [ "$_hi" = 0 ] || return 1
  read_u32 "$1" "$2"
}
read_root_layout() {
  ROOT_OFFSET=""; ROOT_SIZE=""
  _dev="$1"; _sectors="$2"
  case "$_sectors" in ''|*[!0-9]*) return 1;; esac
  [ "$_sectors" -gt 34 ] && [ "$_sectors" -le 4294967295 ] || return 1
  _sig=$(bb dd if="$_dev" bs=1 skip=512 count=8 2>/dev/null) || return 1
  [ "$_sig" = 'EFI PART' ] || return 1
  _rev=$(read_u32 "$_dev" 520) || return 1
  _hs=$(read_u32 "$_dev" 524) || return 1
  [ "$_rev" = 65536 ] && [ "$_hs" = 92 ] || return 1
  _current=$(read_lba32 "$_dev" 536) || return 1
  _backup=$(read_lba32 "$_dev" 544) || return 1
  _firstuse=$(read_lba32 "$_dev" 552) || return 1
  _lastuse=$(read_lba32 "$_dev" 560) || return 1
  _table=$(read_lba32 "$_dev" 584) || return 1
  _entries=$(read_u32 "$_dev" 592) || return 1
  _esize=$(read_u32 "$_dev" 596) || return 1
  [ "$_current" = 1 ] && [ "$_table" = 2 ] && [ "$_entries" = 128 ] && [ "$_esize" = 128 ] || return 1
  [ "$_firstuse" -ge 34 ] && [ "$_lastuse" -ge "$_firstuse" ] || return 1
  [ "$_backup" -gt "$_lastuse" ] && [ "$_backup" -lt "$_sectors" ] || return 1
  _entry=$((_table*512+128))
  _type=$(bb dd if="$_dev" bs=1 skip="$_entry" count=16 2>/dev/null | bb od -An -tx1 | bb tr -d ' \n')
  [ "$_type" = '45b021b9f01dc341af444c6f280d3fae' ] || return 1
  _first=$(read_lba32 "$_dev" "$((_entry+32))") || return 1
  _last=$(read_lba32 "$_dev" "$((_entry+40))") || return 1
  [ "$_first" -ge "$_firstuse" ] && [ "$_last" -ge "$_first" ] || return 1
  [ "$_last" -le "$_lastuse" ] && [ "$_last" -lt "$_sectors" ] || return 1
  ROOT_OFFSET=$((_first*512))
  ROOT_SIZE=$(((_last-_first+1)*512))
  return 0
}
# END ROOTFS_VALIDATION

mount -t configfs configfs /sys/kernel/config 2>/dev/null || true
G=/sys/kernel/config/usb_gadget/g1
mkdir -p "$G" || fatal "configfs unavailable"
echo 0x2717 > "$G/idVendor"
echo 0xff48 > "$G/idProduct"
mkdir -p "$G/strings/0x409" "$G/configs/c.1/strings/0x409"
echo sirius-existing-0001 > "$G/strings/0x409/serialnumber"
echo sirius > "$G/strings/0x409/manufacturer"
echo 'sirius existing rootfs diagnostic' > "$G/strings/0x409/product"
echo acm+ncm > "$G/configs/c.1/strings/0x409/configuration"
for fn in acm.usb0 ncm.usb0; do
  mkdir -p "$G/functions/$fn" || fatal "function $fn missing"
  ln -s "$G/functions/$fn" "$G/configs/c.1/$fn" || fatal "link $fn"
done
n=0
while [ -z "$(ls /sys/class/udc)" ] && [ "$n" -lt 30 ]; do sleep 1; n=$((n+1)); done
UDC=$(ls /sys/class/udc | head -1)
[ -n "$UDC" ] || fatal "UDC missing"
echo "$UDC" > "$G/UDC" || fatal "UDC bind failed"
ifconfig usb0 172.16.42.1 netmask 255.255.0.0 up || fatal "usb0 configuration"
say "USB bound=$UDC"

ROOTDEV=/dev/mmcblk0p81
i=0
while [ ! -b "$ROOTDEV" ] && [ "$i" -lt 15 ]; do sleep 1; i=$((i+1)); done
[ -b "$ROOTDEV" ] || fatal "userdata node absent"
sectors=$(cat /sys/class/block/mmcblk0p81/size)
read_root_layout "$ROOTDEV" "$sectors" || fatal "GPT validation failed"
say "GPT offset=$ROOT_OFFSET bytes=$ROOT_SIZE sectors=$sectors"
# The BusyBox loop applet has no size-limit option. The read-only backing and
# checked ext4 geometry below prevent any write or filesystem use past its end.
LOOP=$(losetup -f) || fatal "no free loop device"
losetup -r -o "$ROOT_OFFSET" "$LOOP" "$ROOTDEV" || fatal "read-only loop setup"
magic=$(read_u32 "$LOOP" 1080) || fatal "superblock read"
[ "$((magic & 65535))" = 61267 ] || fatal "rootfs is not ext4"
blocks=$(read_u32 "$LOOP" 1028) || fatal "filesystem block count"
logbs=$(read_u32 "$LOOP" 1048) || fatal "filesystem block size"
blocks_hi=$(read_u32 "$LOOP" 1360) || fatal "filesystem high block count"
[ "$blocks_hi" = 0 ] && [ "$logbs" -le 2 ] && [ "$blocks" -gt 0 ] || fatal "unsupported ext4 geometry"
[ "$((blocks*(1024<<logbs)))" -le "$ROOT_SIZE" ] || fatal "filesystem exceeds partition"
root_uuid=$(bb dd if="$LOOP" bs=1 skip=1128 count=16 2>/dev/null | bb od -An -tx1 | bb tr -d ' \n')
root_label=$(bb dd if="$LOOP" bs=1 skip=1144 count=16 2>/dev/null | bb od -An -tx1 | bb tr -d ' \n')
[ "$root_uuid" = c84b0979b794487ba2655acebece3f21 ] && [ "$root_label" = 706d4f535f726f6f7400000000000000 ] || fatal "rootfs identity mismatch"
mount -t ext4 -o ro,noload "$LOOP" /newroot || fatal "read-only root mount"
[ -x /newroot/lib/systemd/systemd ] && [ -x /newroot/sbin/apk ] || fatal "existing userspace incomplete"
for dir in etc var dev proc sys run; do
  [ -d "/newroot/$dir" ] && [ ! -L "/newroot/$dir" ] || fatal "unsafe root directory $dir"
done
( cd /newroot && sha256sum etc/os-release etc/fstab etc/shadow etc/inittab lib/systemd/systemd ) > /run/sirius-baseline.sha256 || fatal "original configuration hash failed"
[ -n "$LOG" ] && cat /run/sirius-baseline.sha256 >> "$LOG"
sync
chroot /newroot /lib/systemd/systemd --version > /run/systemd-version.log 2>&1 || fatal "systemd cannot execute"
say "$(head -1 /run/systemd-version.log)"

# Only tmpfs mounts receive configuration changes. The disk root stays read-only.
mkdir -p /run/sirius-etc
cp -a /newroot/etc/. /run/sirius-etc/ || fatal "copy existing configuration into RAM"
mount -t tmpfs -o mode=0755,size=48m tmpfs /newroot/etc || fatal "etc tmpfs"
cp -a /run/sirius-etc/. /newroot/etc/ || fatal "populate volatile etc"
rm -rf /run/sirius-etc
mount -t tmpfs -o mode=0755,size=64m tmpfs /newroot/var || fatal "var tmpfs"
mkdir -p /newroot/var/log /newroot/var/lib /newroot/var/cache /newroot/var/tmp
for dir in /newroot/etc/systemd /newroot/etc/systemd/system; do
  [ ! -L "$dir" ] || fatal "volatile unit directory symlink $dir"
  mkdir -p "$dir" || fatal "create volatile unit directory"
done
# Materialize symlink-prone files in the volatile /etc; never follow them to disk.
rm -f /newroot/etc/machine-id /newroot/etc/fstab
id=$(cat /proc/sys/kernel/random/uuid | tr -d '-')
printf '%s\n' "$id" > /newroot/etc/machine-id
printf '# Diagnostic boot: no generated disk mounts or root remounts\n' > /newroot/etc/fstab
# Avoid persistent target symlinks: these unit files are installed in RAM only.
rm -f /newroot/etc/systemd/system/sirius-diagnostic.target /newroot/etc/systemd/system/sirius-shell.service /newroot/etc/systemd/system/sirius-evidence.service
cat > /newroot/etc/systemd/system/sirius-diagnostic.target <<'TARGET_EOF'
[Unit]
Description=Sirius read-only existing rootfs diagnostic
DefaultDependencies=no
Wants=sirius-shell.service sirius-evidence.service systemd-journald.service
AllowIsolate=yes
TARGET_EOF
cat > /newroot/etc/systemd/system/sirius-shell.service <<'SHELL_EOF'
[Unit]
Description=Local USB test shell (temporary diagnostic image only)
DefaultDependencies=no
[Service]
Type=simple
ExecStart=/bin/busybox sh -i
Restart=always
RestartSec=5
StandardInput=tty
StandardOutput=tty
StandardError=tty
TTYPath=/dev/ttyGS0
TTYReset=no
TTYVHangup=no
SHELL_EOF
cat > /newroot/etc/systemd/system/sirius-evidence.service <<'EVIDENCE_EOF'
[Unit]
Description=Record existing-rootfs acceptance evidence
DefaultDependencies=no
[Service]
Type=oneshot
ExecStart=/run/sirius-evidence.sh
StandardOutput=append:/run/sirius-cache/sirius-existing.log
StandardError=append:/run/sirius-cache/sirius-existing.log
EVIDENCE_EOF
cat > /run/sirius-evidence.sh <<'SCRIPT_EOF'
#!/bin/busybox sh
export PATH=/bin:/sbin:/usr/bin:/usr/sbin
echo SYSTEMD_ACCEPTANCE_BEGIN
id
cat /proc/1/comm
readlink /proc/1/exe
cat /etc/os-release
cat /etc/alpine-release
/sbin/apk --version
/bin/busybox ifconfig usb0
cat /sys/class/udc/*/state
cat /proc/mounts
# A second RO mount exposes original files, not the tmpfs overrides.
mkdir -p /run/original-root
if /bin/busybox mount -t ext4 -o ro,noload "$SIRIUS_ROOT_LOOP" /run/original-root; then
  if ( cd /run/original-root && /bin/busybox sha256sum -c /run/sirius-baseline.sha256 ); then echo BASELINE_PASS; else echo BASELINE_FAIL; fi
  /bin/busybox umount /run/original-root
else
  echo BASELINE_MOUNT_FAIL
fi
 echo SYSTEMD_ACCEPTANCE_END
SCRIPT_EOF
chmod 0755 /run/sirius-evidence.sh
export SIRIUS_ROOT_LOOP="$LOOP"
printf 'Environment=SIRIUS_ROOT_LOOP=%s\n' "$LOOP" >> /newroot/etc/systemd/system/sirius-evidence.service
# Preserve the active configfs under sysfs and keep logs outside the old root.
mkdir -p /run/sirius-cache
if [ -n "$LOG" ]; then
  say "PRE_SWITCH_ROOT loop=$LOOP (ro); disk files preserved"
  mount --move /mnt/log /run/sirius-cache || fatal "cache mount move"
  LOG=/run/sirius-cache/sirius-existing.log
fi
# Let PID 1 log to kmsg, and retain an independent cache capture across handover.
cp /bin/busybox /run/sirius-busybox
if [ -n "$LOG" ]; then
  /run/sirius-busybox cat /dev/kmsg > /run/sirius-cache/sirius-kernel.log 2>&1 &
fi
mount --move /dev /newroot/dev || fatal "move dev"
mount --move /proc /newroot/proc || fatal "move proc"
mount --move /sys /newroot/sys || fatal "move sys"
say "exec switch_root to systemd diagnostic target"
mount --move /run /newroot/run || fatal "move run"
exec /bin/busybox switch_root /newroot /sbin/init --unit=sirius-diagnostic.target --log-target=kmsg --log-level=debug
INIT_EOF
chmod +x "$IRD/init"

( cd "$IRD" && find . | cpio -o -H newc | gzip -9 ) > "$OUT/initramfs.cpio.gz"
echo "initramfs -> $OUT/initramfs.cpio.gz ($(stat -c%s "$OUT/initramfs.cpio.gz") bytes)"
