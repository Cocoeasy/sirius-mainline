#!/bin/sh
# The Samsung EA8074 panel driver registers its backlight at brightness 0 and
# the pinned vendor on-sequence already writes 0x51 00 00, so the panel stays
# dark until userspace sets a level. Bring the display up by writing a sane
# non-zero level once the backlight device appears.
#
# The panel/msm DRM driver may probe after this unit starts, so retry for a
# while. Exit as soon as a backlight device is present and set.
i=0
while [ "$i" -lt 60 ]; do
	for b in /sys/class/backlight/*/brightness; do
		[ -e "$b" ] || continue
		echo 512 > "$b" 2>/dev/null && exit 0
	done
	i=$((i + 1))
	sleep 1
done
exit 0
