#!/usr/bin/env python3
"""Regression tests for the DT schema gate decision (scripts/schema_gate.sh).

The gate exists because make treats dtc/schema findings as warnings and still
exits 0. A real "te-gpios does not match any of the regexes" finding was
therefore recorded as dtbs_check=pass in run 37419562653. These cases pin the
decision in both directions -- the real finding must fail, and unrelated
kconfig noise must not -- and pin that the workflow still routes the decision
through the script instead of hardcoding a pass again.

Only the standard library and a POSIX shell are needed, so the suite runs
without a cross toolchain or dtschema.
"""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GATE = ROOT / "scripts" / "schema_gate.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "build.yml"
DTB = "sdm710-xiaomi-sirius.dtb"

# Verbatim from run 37419562653's dtbs_check.log: the finding the gate used to
# let through as a pass.
REAL_FINDING = (
    "arch/arm64/boot/dts/qcom/sdm710-xiaomi-sirius.dtb: panel@0 "
    "(samsung,ea8074): 'te-gpios' does not match any of the regexes: "
    "'^pinctrl-[0-9]+$'\n"
    "\tfrom schema $id: "
    "http://devicetree.org/schemas/display/panel/samsung,ea8074.yaml\n"
)

# Also verbatim from that log: kconfig restart noise. It contains the word
# "Error" but carries no .dtb prefix, so it must not fail the gate.
KCONFIG_NOISE = (
    "Use RELR relocation packing (RELR) [Y/n/?] (NEW) \n"
    "Error in reading or end of file.\n"
)

CLEAN_TAIL = "  DTC [C] arch/arm64/boot/dts/qcom/sdm710-xiaomi-sirius.dtb\n"

# Verbatim shape from run 37432217671's dt_binding_check.log: the markers that
# prove the binding check actually ran. The gate requires one of these, because
# an empty log with rc 0 is indistinguishable from a clean pass.
BINDING_OK = (
    "  SCHEMA  Documentation/devicetree/bindings/processed-schema.json\n"
    "  CHKDT   ./Documentation/devicetree/bindings\n"
    "  LINT    ./Documentation/devicetree/bindings\n"
    "  DTEX    Documentation/devicetree/bindings/display/panel/"
    "samsung,ea8074.example.dts\n"
)


class SchemaGateDecisionTest(unittest.TestCase):
    def run_gate(self, dtbs_log, rc_binding="0", rc_dtbs="0", binding_log=BINDING_OK):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            blog = tmp / "dt_binding_check.log"
            dlog = tmp / "dtbs_check.log"
            blog.write_text(binding_log, encoding="utf-8")
            dlog.write_text(dtbs_log, encoding="utf-8")
            return subprocess.run(
                ["sh", str(GATE), DTB, str(blog), str(dlog), rc_binding, rc_dtbs],
                capture_output=True,
                text=True,
            )

    def test_real_te_gpios_finding_fails(self):
        p = self.run_gate(REAL_FINDING + CLEAN_TAIL)
        self.assertEqual(p.returncode, 1, p.stderr)
        self.assertIn("dtbs_check=fail", p.stdout)
        self.assertIn("dtbs_findings=1", p.stdout)
        self.assertIn("te-gpios", p.stderr)

    def test_clean_log_passes(self):
        p = self.run_gate(KCONFIG_NOISE + CLEAN_TAIL)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("dtbs_check=pass", p.stdout)
        self.assertIn("dtbs_findings=0", p.stdout)

    # NOTE: an older case here asserted that kconfig noise *alone* passes. That
    # premise is what the review found to be wrong: noise without a DTC line
    # means the check did not run, which must fail. The original intent -- that
    # unrelated noise must not fail the gate -- is preserved by
    # test_clean_log_passes above, where the noise rides along with the DTC line.

    def test_make_status_is_still_honoured(self):
        p = self.run_gate(CLEAN_TAIL, rc_dtbs="2")
        self.assertEqual(p.returncode, 1)
        self.assertIn("dtbs_check=fail", p.stdout)
        self.assertIn("dtbs_findings=0", p.stdout)

    def test_binding_check_status_is_honoured(self):
        p = self.run_gate(CLEAN_TAIL, rc_binding="2")
        self.assertEqual(p.returncode, 1)
        self.assertIn("dt_binding_check=fail", p.stdout)

    def test_findings_for_another_dtb_are_out_of_scope(self):
        other = "arch/arm64/boot/dts/qcom/sdm845.dtb: foo: bar\n"
        p = self.run_gate(other + CLEAN_TAIL)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("dtbs_findings=0", p.stdout)

    def test_script_parses_as_posix_sh(self):
        p = subprocess.run(["sh", "-n", str(GATE)], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)

    # --- the "did it run at all" hole, found by review ---

    def test_empty_dtbs_log_does_not_pass(self):
        # make prints nothing when the DTB is already up to date, so the check
        # never runs. rc 0 plus an empty log must not read as a clean pass.
        p = self.run_gate("")
        self.assertEqual(p.returncode, 1, p.stdout)
        self.assertIn("dtbs_check=fail", p.stdout)
        self.assertIn("did not run", p.stderr)

    def test_dtbs_log_with_only_kconfig_noise_does_not_pass(self):
        p = self.run_gate(KCONFIG_NOISE)
        self.assertEqual(p.returncode, 1, p.stdout)
        self.assertIn("dtbs_check=fail", p.stdout)

    def test_empty_binding_log_does_not_pass(self):
        p = self.run_gate(KCONFIG_NOISE + CLEAN_TAIL, binding_log="")
        self.assertEqual(p.returncode, 1, p.stdout)
        self.assertIn("dt_binding_check=fail", p.stdout)
        self.assertIn("did not run", p.stderr)

    def test_run_markers_are_reported(self):
        p = self.run_gate(KCONFIG_NOISE + CLEAN_TAIL)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("dtbs_check_ran=1", p.stdout)
        self.assertIn("dt_binding_check_ran=", p.stdout)


class WorkflowWiringTest(unittest.TestCase):
    """The gate only works if the workflow actually calls it."""

    def setUp(self):
        self.text = WORKFLOW.read_text(encoding="utf-8")

    def test_workflow_calls_the_gate_script(self):
        self.assertIn("scripts/schema_gate.sh", self.text)

    def test_workflow_no_longer_hardcodes_a_pass(self):
        self.assertNotIn("printf 'dt_binding_check=pass", self.text)
        self.assertNotIn("printf 'dtbs_check=pass", self.text)

    def test_workflow_propagates_the_gate_failure(self):
        self.assertIn("DT schema gate failed", self.text)

    def test_schema_gate_step_still_prints_both_verdicts(self):
        # A bad edit once split this single line, and the runner then failed the
        # step with "out/schema.txt: Permission denied" instead of printing the
        # verdict. Keep it as one command.
        self.assertIn("cat out/checks.txt out/schema.txt", self.text)


CHECKPATCH_GATE = ROOT / "scripts" / "checkpatch_gate.sh"


def checkpatch_summary(errors, warnings, checks, lines=520):
    """The newer checkpatch summary, in the exact shape checkpatch.pl prints."""
    return "total: %d errors, %d warnings, %d checks, %d lines checked\n" % (
        errors,
        warnings,
        checks,
        lines,
    )


# Verbatim from the pinned tree's checkpatch: the summary with no checks column.
OLD_CHECKPATCH_SUMMARY = "total: 0 errors, 0 warnings, 671 lines checked\n"


class CheckpatchGateDecisionTest(unittest.TestCase):
    """The upstream style gate: ERROR fails, WARNING and CHECK do not.

    A brand-new driver routinely carries CHECK lines, and upstream does not
    reject a series for them, so failing on those would turn the gate into noise
    everyone learns to ignore. The opposite mistake is the dangerous one: a
    checkpatch that never ran leaves a log with no summary, and a naive reading
    of an empty log is "no errors found".
    """

    def run_gate(self, log_text):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "checkpatch.log"
            log.write_text(log_text, encoding="utf-8")
            return subprocess.run(
                ["sh", str(CHECKPATCH_GATE), str(log)],
                capture_output=True,
                text=True,
            )

    def test_clean_run_passes(self):
        p = self.run_gate(checkpatch_summary(0, 0, 0, lines=525))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("checkpatch_verdict=pass", p.stdout)
        self.assertIn("checkpatch_errors=0", p.stdout)
        self.assertIn("checkpatch_lines=525", p.stdout)

    def test_summary_without_the_checks_column_still_passes(self):
        # The pinned tree's checkpatch prints three fields, not four. Accepting
        # only the newer four-field form reported a clean run as "did not
        # complete", which is the bug this case pins.
        p = self.run_gate(OLD_CHECKPATCH_SUMMARY)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("checkpatch_verdict=pass", p.stdout)
        self.assertIn("checkpatch_errors=0", p.stdout)
        self.assertIn("checkpatch_lines=671", p.stdout)
        self.assertIn("checkpatch_checks=n/a", p.stdout)

    def test_old_format_with_an_error_still_fails(self):
        p = self.run_gate("total: 1 errors, 0 warnings, 671 lines checked\n")
        self.assertEqual(p.returncode, 1)
        self.assertIn("checkpatch_verdict=fail", p.stdout)
        self.assertIn("checkpatch_errors=1", p.stdout)

    def test_warnings_and_checks_do_not_fail(self):
        p = self.run_gate(
            "WARNING: line over 80 characters\n"
            "CHECK: Alignment should match open parenthesis\n"
            + checkpatch_summary(0, 3, 7)
        )
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("checkpatch_verdict=pass", p.stdout)
        self.assertIn("checkpatch_warnings=3", p.stdout)
        self.assertIn("checkpatch_checks=7", p.stdout)

    def test_a_single_error_fails_and_is_shown(self):
        p = self.run_gate(
            "ERROR: code indent should use tabs where possible\n"
            + checkpatch_summary(1, 4, 2)
        )
        self.assertEqual(p.returncode, 1)
        self.assertIn("checkpatch_verdict=fail", p.stdout)
        self.assertIn("checkpatch_errors=1", p.stdout)
        self.assertIn("code indent", p.stderr)

    def test_incomplete_run_fails_instead_of_reading_as_clean(self):
        p = self.run_gate("Can't open drivers/gpu/drm/panel/panel-samsung-ea8074.c\n")
        self.assertEqual(p.returncode, 1)
        self.assertIn("checkpatch_verdict=fail", p.stdout)
        self.assertIn("did not complete", p.stderr)
        # The size is reported so an empty log -- what checkpatch --terse
        # produced for a clean file, and what made this gate fail a good run --
        # stays distinguishable from a partially written one.
        self.assertIn("bytes", p.stderr)

    def test_empty_log_fails(self):
        p = self.run_gate("")
        self.assertEqual(p.returncode, 1)
        self.assertIn("checkpatch_verdict=fail", p.stdout)

    def test_trailing_exit_code_line_does_not_hide_the_summary(self):
        # The workflow appends checkpatch_exit= after the run; that must not
        # stop the summary from being found.
        p = self.run_gate(checkpatch_summary(0, 1, 0) + "checkpatch_exit=0\n")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("checkpatch_warnings=1", p.stdout)

    def test_script_parses_as_posix_sh(self):
        p = subprocess.run(
            ["sh", "-n", str(CHECKPATCH_GATE)], capture_output=True, text=True
        )
        self.assertEqual(p.returncode, 0, p.stderr)


class CheckpatchWorkflowWiringTest(unittest.TestCase):
    """The gate only does anything if the workflow runs checkpatch and asks it."""

    def setUp(self):
        self.text = WORKFLOW.read_text(encoding="utf-8")

    def test_workflow_runs_checkpatch_on_the_new_driver(self):
        self.assertIn("./scripts/checkpatch.pl", self.text)
        self.assertIn("drivers/gpu/drm/panel/panel-samsung-ea8074.c", self.text)

    def test_workflow_routes_the_decision_through_the_script(self):
        self.assertIn("scripts/checkpatch_gate.sh", self.text)

    def test_workflow_does_not_hardcode_a_verdict(self):
        self.assertNotIn("checkpatch_verdict=pass", self.text)

    def test_workflow_propagates_the_gate_failure(self):
        self.assertIn("checkpatch reported errors", self.text)

    def test_checkpatch_evidence_is_uploaded(self):
        # The verdict is only evidence if the artifact actually carries it.
        self.assertIn("out/checkpatch.log", self.text)
        self.assertIn("out/checkpatch.txt", self.text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
