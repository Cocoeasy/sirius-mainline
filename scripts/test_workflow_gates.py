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


class SchemaGateDecisionTest(unittest.TestCase):
    def run_gate(self, dtbs_log, rc_binding="0", rc_dtbs="0"):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            blog = tmp / "dt_binding_check.log"
            dlog = tmp / "dtbs_check.log"
            blog.write_text("", encoding="utf-8")
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

    def test_kconfig_noise_alone_does_not_fail(self):
        p = self.run_gate(KCONFIG_NOISE)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("dtbs_check=pass", p.stdout)

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
