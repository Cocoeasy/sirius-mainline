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
# and an empty log read naively looks exactly like "no errors found". So the
# summary line is required and its absence fails.
#
# The summary is only emitted without --terse, which is why the workflow does
# not pass --terse: the first version of the step did, checkpatch then printed
# nothing at all for a clean file, and this gate reported that as "did not
# complete" with an empty log. The byte/line counts below exist so that the two
# cases stay distinguishable in the run log.
#
# usage: checkpatch_gate.sh <checkpatch.log>
set -u

log=$1

summary=$(grep -E '^total: [0-9]+ errors?, [0-9]+ warnings?, [0-9]+ checks?,' "$log" | tail -1)
if [ -z "$summary" ]; then
	printf 'checkpatch_verdict=fail\n'
	printf 'checkpatch gate: no summary line in %s (%s bytes, %s lines) -- checkpatch did not complete\n' \
		"$log" "$(wc -c < "$log")" "$(wc -l < "$log")" >&2
	tail -20 "$log" >&2 || true
	exit 1
fi

errors=$(printf '%s\n' "$summary" | sed -E 's/^total: ([0-9]+) errors.*/\1/')
warnings=$(printf '%s\n' "$summary" | sed -E 's/^total: [0-9]+ errors?, ([0-9]+) warnings.*/\1/')
checks=$(printf '%s\n' "$summary" | sed -E 's/^total: [0-9]+ errors?, [0-9]+ warnings?, ([0-9]+) checks.*/\1/')
lines=$(printf '%s\n' "$summary" | sed -E 's/^total: [0-9]+ errors?, [0-9]+ warnings?, [0-9]+ checks?, ([0-9]+) lines.*/\1/')

printf 'checkpatch_errors=%s\n' "$errors"
printf 'checkpatch_warnings=%s\n' "$warnings"
printf 'checkpatch_checks=%s\n' "$checks"
printf 'checkpatch_lines=%s\n' "$lines"

if [ "$errors" -ne 0 ]; then
	printf 'checkpatch_verdict=fail\n'
	printf 'checkpatch gate failed: %s ERROR(s) in %s\n' "$errors" "$log" >&2
	grep -E '^ERROR: ' "$log" | head -20 >&2 || true
	exit 1
fi

printf 'checkpatch_verdict=pass\n'
exit 0
