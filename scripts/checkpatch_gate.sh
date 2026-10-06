#!/bin/sh
# Decide the upstream style gate from a checkpatch.pl log.
#
# checkpatch is advisory. A brand-new driver routinely carries CHECK lines and
# sometimes WARNINGs, and upstream does not reject a series for them, so failing
# on those would make the gate noise that everyone learns to ignore. ERROR does
# block review, so that is what this fails on.
#
# The failure mode in the other direction matters just as much: a checkpatch
# that never ran leaves a log with no summary, and an empty log read naively
# looks exactly like "no errors found". So the summary line is required and its
# absence fails.
#
# Two things make that guard easy to get wrong, and both did:
#   * checkpatch --terse prints no summary at all for a clean file, so the
#     workflow does not pass --terse; a run then ended with an empty log.
#   * the summary has two formats. Newer checkpatch prints
#     "total: N errors, M warnings, K checks, L lines checked"; the pinned
#     tree's prints "total: N errors, M warnings, L lines checked" with no
#     checks column. Accepting only the newer one reported a clean run as
#     "did not complete".
# The byte/line counts below exist so that a genuinely empty log stays
# distinguishable from a summary this script failed to recognise.
#
# usage: checkpatch_gate.sh <checkpatch.log>
set -u

log=$1

summary=$(grep -E '^total: [0-9]+ errors?, [0-9]+ warnings?,' "$log" | tail -1)
if [ -z "$summary" ]; then
	printf 'checkpatch_verdict=fail\n'
	printf 'checkpatch gate: no summary line in %s (%s bytes, %s lines) -- checkpatch did not complete\n' \
		"$log" "$(wc -c < "$log")" "$(wc -l < "$log")" >&2
	tail -20 "$log" >&2 || true
	exit 1
fi

# sed -n ... p leaves the value empty when the field is absent, rather than
# echoing the whole line back as the value.
errors=$(printf '%s\n' "$summary" | sed -nE 's/^total: ([0-9]+) errors.*/\1/p')
warnings=$(printf '%s\n' "$summary" | sed -nE 's/^total: [0-9]+ errors?, ([0-9]+) warnings.*/\1/p')
checks=$(printf '%s\n' "$summary" | sed -nE 's/^total: [0-9]+ errors?, [0-9]+ warnings?, ([0-9]+) checks.*/\1/p')
lines=$(printf '%s\n' "$summary" | sed -nE 's/^total: .* ([0-9]+) lines checked.*/\1/p')
[ -n "$checks" ] || checks=n/a

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
