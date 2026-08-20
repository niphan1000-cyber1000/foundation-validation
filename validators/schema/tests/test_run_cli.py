import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))  # import run
from run import run  # noqa: E402

ROOT = Path(__file__).parent.parent.parent.parent
SCHEMAS = ROOT / "schemas"
FIXTURES = Path(__file__).parent / "fixtures"


class TestRunCli(unittest.TestCase):
    def test_valid_target_reports_passed_with_no_findings(self):
        result = run(SCHEMAS / "validation-request.schema.json", FIXTURES / "valid_request.json")
        self.assertEqual(result["status"], "PASSED")
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["evidence"], [])
        self.assertEqual(result["summary"], {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0})

    def test_invalid_target_reports_failed_with_findings_and_evidence(self):
        result = run(SCHEMAS / "validation-request.schema.json", FIXTURES / "invalid_request_missing_target.json")
        self.assertEqual(result["status"], "FAILED")
        self.assertGreater(len(result["findings"]), 0)
        # Every finding must reference at least one evidence record (Evidence Model, spec Section 5).
        evidence_ids = {e["evidence_id"] for e in result["evidence"]}
        for finding in result["findings"]:
            self.assertTrue(finding["evidence_ids"])
            for eid in finding["evidence_ids"]:
                self.assertIn(eid, evidence_ids, "every finding's evidence_id must have a matching Evidence record")

    def test_rule_ids_are_registered_sch_rules(self):
        result = run(SCHEMAS / "validation-request.schema.json", FIXTURES / "invalid_request_missing_target.json")
        for finding in result["findings"]:
            self.assertRegex(finding["rule_id"], r"^SCH-\d{3}$")
            self.assertEqual(finding["domain"], "schema")

    def test_evidence_integrity_hash_is_valid_sha256(self):
        result = run(SCHEMAS / "validation-evidence.schema.json", FIXTURES / "invalid_evidence_bad_hash.json")
        for ev in result["evidence"]:
            self.assertRegex(ev["integrity_hash"], r"^[a-f0-9]{64}$")


if __name__ == "__main__":
    unittest.main()
