"""
Regression tests for OPAValidator's rule_id fallback (validators/opa_validator.py).

Previously, an OPA output item missing "rule_id" fell back to a
fabricated "GOV-POLICY-DENY" — a plausible-looking rule_id using the
real GOV taxonomy prefix (see rules/taxonomy.json) that was never
actually an entry in rules/registry.yaml. That made a data anomaly
(OPA emitted a violation with no rule_id) indistinguishable, in the
evidence trail, from a real catalogued governance rule firing.

These tests mock subprocess.run so they don't depend on a real `opa`
binary being installed, and assert the fallback now produces an
unmistakable "UNRESOLVED-RULE-ID:..." marker instead.
"""
import json
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from opa_validator import OPAValidator  # noqa: E402


def _fake_opa_result(value_list):
    return json.dumps({
        "result": [{"expressions": [{"value": value_list}]}]
    })


class TestOpaValidatorRuleIdFallback(unittest.TestCase):
    def setUp(self):
        # validate() checks os.path.exists(self.spec_path) first, so we
        # point at this test file itself, which genuinely exists.
        self.validator = OPAValidator(spec_path=__file__, policy_dir="policies/")

    @patch("opa_validator.subprocess.run")
    def test_missing_rule_id_gets_unresolved_marker_not_gov_policy_deny(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=_fake_opa_result([{"message": "no rule_id here", "severity": "HIGH"}]),
            stderr="",
        )
        findings, err = self.validator.validate()
        self.assertIsNone(err)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "UNRESOLVED-RULE-ID:opa-output-missing-rule_id")
        self.assertNotEqual(findings[0]["rule_id"], "GOV-POLICY-DENY")

    @patch("opa_validator.subprocess.run")
    def test_real_rule_id_is_unaffected(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=_fake_opa_result([{"rule_id": "SEC-002-NON-HTTPS-SERVER", "severity": "HIGH",
                                       "message": "real violation"}]),
            stderr="",
        )
        findings, err = self.validator.validate()
        self.assertIsNone(err)
        self.assertEqual(findings[0]["rule_id"], "SEC-002-NON-HTTPS-SERVER")


if __name__ == "__main__":
    unittest.main()
