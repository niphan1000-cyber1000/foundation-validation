import unittest
import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BASE_DIR)

from run_all import run_all_validations

class TestGovernedAggregatorEngine(unittest.TestCase):
    def test_aggregate_empty_schema(self):
        result = run_all_validations()
        self.assertEqual(result["status"], "PASSED")
        self.assertEqual(result["summary"]["total_findings"], 0)
        self.assertIn("execution", result)
        self.assertIn("evidence", result)

    def test_aggregate_findings_contract(self):
        # NOTE (adversarial review, 2026-09): this test's mock_openapi
        # used to set "severity": "CRITICAL" (a string). Real `spectral
        # lint -f json` output uses a numeric severity code instead
        # (0=CRITICAL/error, 1=HIGH/warning, 2=MEDIUM/info, 3=LOW/hint --
        # see openapi_engine.parse_spectral_output's severity_map), so
        # that string silently fell through parse_spectral_output's
        # `severity_map.get(severity_code, "MEDIUM")` fail-safe default
        # and resolved to MEDIUM instead of CRITICAL. That was a bug in
        # this test's mock data (wrong shape for the tool being mocked),
        # not in run_all.py or openapi_engine.py -- the fail-safe default
        # that caught it is exactly the intended behavior for a
        # genuinely malformed/unexpected severity value. Fixed by using
        # the real numeric contract and asserting the actually-correct
        # outcome (one CRITICAL from spectral, one HIGH from opa) rather
        # than forcing both findings into the same bucket.
        mock_openapi = [
            {"rule_id": "oas3-schema", "code": "oas3-schema", "message": "Missing response", "severity": 0, "path": ["paths"]}
        ]
        mock_opa = {
            "result": [{"expressions": [{"value": [
                {"rule_id": "POL-001", "code": "001", "message": "Access Denied", "severity": "HIGH"}
            ]}]}]
        }

        result = run_all_validations(openapi_json_data=mock_openapi, opa_json_data=mock_opa)
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["summary"]["total_findings"], 2)
        self.assertEqual(result["summary"]["critical"], 1)
        self.assertEqual(result["summary"]["high"], 1)
        self.assertIn("hash_digest", result["evidence"])

if __name__ == "__main__":
    unittest.main()

