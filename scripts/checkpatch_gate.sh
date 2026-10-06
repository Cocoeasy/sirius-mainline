#!/bin/sh
# Decide the upstream style gate from a checkpatch.pl log.
#
# checkpatch is advisory. A brand-new driver routinely carries CHECK lines and
# sometimes WARNINGs, and upstream does not reject a series for them, so failing
# on those would make the gate noise that everyone learns to ignore. ERROR does
# block review, so that is what this fails on.
#
# The failure mode in the other direction matters just as much: a checkpatch
# that never ran (missing perl, wrong path, crash) leaves a log with no summary,
# and an empty log read naively looks exactly like "no errors found". So a
# missing summary is a hard failure, not a pass.
#
# usage: checkpatch_gate.sh <checkpatch.log>
set -u

log=$1

# checkpatch ends every completed run with this summary line.
summary=$(grep -E '^total: [0-9]+ errors?, [0-9]+ warnings?, [0-9]+ checks?,' "$log" | tail -1)
if [ -z "$summary" ]; then
	printf 'checkpatch_verdict=fail\n'
	printf 'checkpatch gate: no summary line in %s -- checkpatch did not complete\n' "$log" >&2
	tail -20 "$log" >&2 || true
	exit 1
fi

errors=$(printf '%s\n' "$summary" | sed -E 's/^total: ([0-9]+) errors.*/\1/')
warnings=$(printf '%s\n' "$summary" | sed -E 's/^total: [0-9]+ errors?, ([0-9]+) warnings.*/\1/')
checks=$(printf '%s\n' "$summary" | sed -E 's/^total: [0-9]+ errors?, [0-9]+ warnings?, ([0-9]+) checks.*/\1/')

printf 'checkpatch_errors=%s\n' "$errors"
printf 'checkpatch_warnings=%s\n' "$warnings"
printf 'checkpatch_checks=%s\n' "$checks"

if [ "$errors" -ne 0 ]; then
	printf 'checkpatch_verdict=fail\n'
	printf 'checkpatch gate failed: %s ERROR(s) in %s\n' "$errors" "$log" >&2
	grep -E '^ERROR: ' "$log" | head -20 >&2 || true
	exit 1
fi

printf 'checkpatch_verdict=pass\n'
exit 0
