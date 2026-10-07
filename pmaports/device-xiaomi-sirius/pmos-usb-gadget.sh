#!/bin/sh
# Expose the phone over USB as an ACM serial port + an NCM network interface,
# so the host can reach the device without a special boot image. This is the
# same gadget the bring-up initramfs used (0x2717:0xff48, acm+ncm), promoted to
# a normal boot service.
#
# Best effort: a failure here must never block the boot, so every step is
# tolerant and the script always exits 0.
set +e

G=/sys/kernel/config/usb_gadget/g1

modprobe libcomposite 2>/dev/null
mountpoint -q /sys/kernel/config || mount -t configfs none /sys/kernel/config 2>/dev/null
[ -d /sys/kernel/config/usb_gadget ] || exit 0

if [ ! -e "$G/idVendor" ]; then
	mkdir -p "$G"
	echo 0x2717 > "$G/idVendor" 2>/dev/null
	echo 0xff48 > "$G/idProduct" 2>/dev/null

	mkdir -p "$G/strings/0x409"
	echo sirius-pmos-0001 > "$G/strings/0x409/serialnumber" 2>/dev/null
	echo Xiaomi > "$G/strings/0x409/manufacturer" 2>/dev/null
	echo "Mi 8 SE (pmOS)" > "$G/strings/0x409/product" 2>/dev/null

	mkdir -p "$G/configs/c.1/strings/0x409"
	echo acm+ncm > "$G/configs/c.1/strings/0x409/configuration" 2>/dev/null

	mkdir -p "$G/functions/acm.usb0" "$G/functions/ncm.usb0"
	ln -sf "$G/functions/acm.usb0" "$G/configs/c.1/" 2>/dev/null
	ln -sf "$G/functions/ncm.usb0" "$G/configs/c.1/" 2>/dev/null
fi

# Wait for a UDC to appear, then bind.
i=0
while [ -z "$(ls /sys/class/udc 2>/dev/null)" ] && [ "$i" -lt 30 ]; do
	sleep 1
	i=$((i + 1))
done
UDC=$(ls /sys/class/udc 2>/dev/null | head -1)
if [ -n "$UDC" ] && [ -z "$(cat "$G/UDC" 2>/dev/null)" ]; then
	echo "$UDC" > "$G/UDC" 2>/dev/null
fi

# Give the NCM link an address the host can reach. Windows self-assigns a
# 169.254/16 link-local address on the matching adapter, so stay in that range.
i=0
while [ ! -d /sys/class/net/usb0 ] && [ "$i" -lt 30 ]; do
	sleep 1
	i=$((i + 1))
done
if [ -d /sys/class/net/usb0 ]; then
	ip addr flush dev usb0 2>/dev/null
	ip addr add 169.254.42.1/16 dev usb0 2>/dev/null
	ip link set usb0 up 2>/dev/null
fi

# A shell on the ACM port so the host's COM device is usable for commands.
if [ -c /dev/ttyGS0 ] && ! pgrep -f 'sh </dev/ttyGS0' >/dev/null 2>&1; then
	setsid /bin/sh -c 'exec /bin/sh </dev/ttyGS0 >/dev/ttyGS0 2>&1' &
fi

exit 0
