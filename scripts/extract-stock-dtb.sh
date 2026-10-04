#!/usr/bin/env bash
# Extract the values you MUST NOT guess, from your own device's stock dtb.
#   ./extract-stock-dtb.sh /path/to/stock_boot.img
#   ./extract-stock-dtb.sh /path/to/dtb
set -euo pipefail

SRC="${1:?usage: $0 <stock_boot.img | dtb>}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
command -v dtc >/dev/null || { echo "need dtc (device-tree-compiler)"; exit 1; }

case "$SRC" in
  *.img)
    command -v unpack_bootimg >/dev/null || { echo "install AOSP unpack_bootimg, or pass a raw dtb"; exit 1; }
    unpack_bootimg --boot_img "$SRC" --out "$TMP/unpacked"
    SRC="$TMP/unpacked/dtb"
    ;;
esac

dtc -I dtb -O dts -o "$TMP/out.dts" "$SRC"

echo "=== qcom,msm-id / board-id / pmic-id ==="
grep -E 'qcom,(msm-id|board-id|pmic-id)' "$TMP/out.dts" || true
echo
echo "=== panel / display ==="
grep -nE 'panel-name|dsi_|ea8074|sofef00|ams|samsung' "$TMP/out.dts" | head -40 || true
echo
echo "=== touchscreen ==="
grep -nE 'fts@|goodix|focaltech|novatek|touchscreen' "$TMP/out.dts" | head -20 || true
echo
echo "Full dts: $TMP/out.dts"
