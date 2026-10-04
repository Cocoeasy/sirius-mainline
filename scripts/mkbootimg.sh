#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
K="$ROOT/kernel"
OUT="$ROOT/out"
mkdir -p "$OUT"

KERNEL="$K/arch/arm64/boot/Image.gz"
DTB="$K/arch/arm64/boot/dts/qcom/sdm710-xiaomi-sirius.dtb"
RAMDISK="$OUT/initramfs.cpio.gz"

for f in "$KERNEL" "$DTB" "$RAMDISK"; do
  [ -f "$f" ] || { echo "missing: $f"; exit 1; }
done

cp "$KERNEL" "$OUT/Image.gz"
cp "$DTB" "$OUT/sdm710-xiaomi-sirius.dtb"

python3 "$ROOT/scripts/mkbootimg.py" \
  "$KERNEL" "$DTB" "$RAMDISK" "$OUT/boot.img"

echo "--- artifacts ---"
ls -l "$OUT"
