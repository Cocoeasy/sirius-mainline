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
# There is a second hole with the same shape, found by review: an empty log
# with rc 0 is indistinguishable from a clean pass. If make considers the DTB
# already up to date it prints nothing and the check never runs. So each log
# must also carry positive evidence that its check ran -- the DTC line for the
# DTB, and a schema/example marker in the binding log -- and a log without it
# fails rather than passing quietly. checkpatch_gate.sh guards the same way by
# requiring its summary line.
#
# usage: schema_gate.sh <dtb-basename> <dt_binding_check.log> <dtbs_check.log> \
#                       <dt_binding_check-rc> <dtbs_check-rc>
set -u

dtb=$1
binding_log=$2
dtbs_log=$3
rc_binding=${4:-1}
rc_dtbs=${5:-1}

bind_status=pass
[ "$rc_binding" -eq 0 ] || bind_status=fail
dtbs_status=pass
[ "$rc_dtbs" -eq 0 ] || dtbs_status=fail

# Positive evidence that each check ran at all. A missing or unreadable log
# yields 0 here (grep writes nothing), which is the correct reading: no
# evidence that it ran.
ran_binding=$(grep -cE '(SCHEMA|CHKDT|LINT|DTEX)|ea8074' "$binding_log" 2>/dev/null || true)
ran_dtbs=$(grep -cE "DTC .*${dtb}|^[^[:space:]]*${dtb}: " "$dtbs_log" 2>/dev/null || true)
ran_binding=${ran_binding:-0}
ran_dtbs=${ran_dtbs:-0}
[ "$ran_binding" -ne 0 ] || bind_status=fail
[ "$ran_dtbs" -ne 0 ] || dtbs_status=fail

findings=$(grep -cE "^[^[:space:]]*${dtb}: " "$dtbs_log" 2>/dev/null || true)
findings=${findings:-0}
[ "$findings" -eq 0 ] || dtbs_status=fail

printf 'dt_binding_check=%s\n' "$bind_status"
printf 'dtbs_check=%s\n' "$dtbs_status"
printf 'dtbs_findings=%s\n' "$findings"
printf 'dt_binding_check_ran=%s\n' "$ran_binding"
printf 'dtbs_check_ran=%s\n' "$ran_dtbs"

if [ "$bind_status" != pass ] || [ "$dtbs_status" != pass ]; then
	if [ "$ran_binding" -eq 0 ]; then
		printf 'DT schema gate failed: dt_binding_check produced no schema/example marker in %s -- it did not run\n' \
			"$binding_log" >&2
	fi
	if [ "$ran_dtbs" -eq 0 ]; then
		printf 'DT schema gate failed: dtbs_check produced no DTC line for %s -- it did not run\n' \
			"$dtb" >&2
	fi
	printf 'DT schema gate failed: dt_binding_check=%s dtbs_check=%s (findings: %s)\n' \
		"$bind_status" "$dtbs_status" "$findings" >&2
	grep -E "^[^[:space:]]*${dtb}: " "$dtbs_log" | head -20 >&2 || true
	exit 1
fi

exit 0
