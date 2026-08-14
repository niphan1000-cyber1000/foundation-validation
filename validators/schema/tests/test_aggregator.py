import unittest
import os
import sys

# Dynamically resolve root project path for CI runner
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, "..", "..", ".."))
VALIDATORS_DIR = os.path.abspath(os.path.join(CURRENT_DIR, "..", ".."))

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
if VALIDATORS_DIR not in sys.path:
    sys.path.insert(0, VALIDATORS_DIR)

from run_all import run_all_validations

class TestGovernedAggregatorEngine(unittest.TestCase):
    def test_aggregate_empty_schema(self):
        result = run_all_validations()
        self.assertEqual(result["status"], "PASSED")
        self.assertEqual(result["summary"]["total_findings"], 0)
        self.assertIn("execution", result)
        self.assertIn("evidence", result)

    def test_aggregate_findings_contract(self):
        mock_openapi = [
            {"code": "oas3-schema", "message": "Missing response", "severity": 0, "path": ["paths"]}
        ]
        mock_opa = {
            "result": [{"deny": [{"code": "001", "message": "Access Denied", "severity": "HIGH"}]}]
        }

        result = run_all_validations(openapi_json_data=mock_openapi, opa_json_data=mock_opa)
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["summary"]["total_findings"], 2)
        self.assertEqual(result["summary"]["critical"], 1)
        self.assertEqual(result["summary"]["high"], 1)
        self.assertIn("hash_digest", result["evidence"])

if __name__ == '__main__':
    unittest.main()
