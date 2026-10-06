#!/bin/sh
# Decide the DT schema gate from the two dt-validate logs.
#
# dtc/schema findings are warnings to make, and make still exits 0 for them.
# A real "te-gpios does not match any of the regexes" finding was recorded as
# a pass for exactly that reason, so the make status alone is not the
# assertion. dt-validate prefixes every report it emits for the DTB with the
# .dtb path, so count those lines and fail on one of them too. Unrelated
# noise (kconfig restarts print "Error in reading or end of file.") carries
# no such prefix and must not fail the gate.
#
# usage: schema_gate.sh <dtb-basename> <dt_binding_check.log> <dtbs_check.log> \
#                       <dt_binding_check-rc> <dtbs_check-rc>
set -u

dtb=$1
binding_log=$2
dtbs_log=$3
rc_binding=$4
rc_dtbs=$5

bind_status=pass
[ "$rc_binding" -eq 0 ] || bind_status=fail
dtbs_status=pass
[ "$rc_dtbs" -eq 0 ] || dtbs_status=fail
findings=$(grep -cE "^[^[:space:]]*${dtb}: " "$dtbs_log" || true)
[ "$findings" -eq 0 ] || dtbs_status=fail

printf 'dt_binding_check=%s\n' "$bind_status"
printf 'dtbs_check=%s\n' "$dtbs_status"
printf 'dtbs_findings=%s\n' "$findings"

if [ "$bind_status" != pass ] || [ "$dtbs_status" != pass ]; then
	printf 'DT schema gate failed: dt_binding_check=%s dtbs_check=%s (findings: %s)\n' \
		"$bind_status" "$dtbs_status" "$findings" >&2
	grep -E "^[^[:space:]]*${dtb}: " "$dtbs_log" | head -20 >&2 || true
	exit 1
fi

exit 0
