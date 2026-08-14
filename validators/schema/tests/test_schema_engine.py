import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))  # import schema_engine
from schema_engine import validate  # noqa: E402

ROOT = Path(__file__).parent.parent.parent.parent  # repo root
SCHEMAS = ROOT / "schemas"
FIXTURES = Path(__file__).parent / "fixtures"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


class TestValidationRequestSchema(unittest.TestCase):
    def setUp(self):
        self.schema = load(SCHEMAS / "validation-request.schema.json")

    def test_valid_request_passes_green(self):
        instance = load(FIXTURES / "valid_request.json")
        errors = validate(instance, self.schema)
        self.assertEqual(errors, [], f"expected GREEN (no errors), got: {errors}")

    def test_missing_target_and_bad_domain_fail_red(self):
        instance = load(FIXTURES / "invalid_request_missing_target.json")
        errors = validate(instance, self.schema)
        keywords = {e.keyword for e in errors}
        self.assertIn("required", keywords, "missing 'target' should be caught by 'required'")
        self.assertIn("enum", keywords, "'not_a_real_domain' should be caught by 'enum'")

    def test_additional_property_rejected(self):
        instance = load(FIXTURES / "valid_request.json")
        instance["unexpected_field"] = "should not be allowed"
        errors = validate(instance, self.schema)
        self.assertTrue(any(e.keyword == "additionalProperties" for e in errors))


class TestValidationResultSchema(unittest.TestCase):
    def setUp(self):
        self.schema = load(SCHEMAS / "validation-result.schema.json")

    def test_valid_result_passes_green(self):
        instance = load(FIXTURES / "valid_result.json")
        errors = validate(instance, self.schema)
        self.assertEqual(errors, [], f"expected GREEN (no errors), got: {errors}")

    def test_passed_gate_with_critical_finding_fails_red(self):
        """Exit Criteria #1 (spec Section 7): a PASSED gate must have
        zero open CRITICAL findings. The if/then constraint in
        validation-result.schema.json must catch a violation."""
        instance = load(FIXTURES / "invalid_result_passed_with_critical.json")
        errors = validate(instance, self.schema)
        self.assertTrue(
            any(e.path.endswith("CRITICAL") for e in errors),
            f"expected a CRITICAL-count violation, got: {errors}",
        )

    def test_null_gate_result_allowed_for_in_progress_run(self):
        instance = load(FIXTURES / "valid_result.json")
        instance["status"] = "RUNNING"
        instance["gate_result"] = None
        errors = validate(instance, self.schema)
        self.assertEqual(errors, [], f"gate_result should be nullable while RUNNING, got: {errors}")


class TestValidationEvidenceSchema(unittest.TestCase):
    def setUp(self):
        self.schema = load(SCHEMAS / "validation-evidence.schema.json")

    def test_valid_evidence_passes_green(self):
        instance = load(FIXTURES / "valid_evidence.json")
        errors = validate(instance, self.schema)
        self.assertEqual(errors, [], f"expected GREEN (no errors), got: {errors}")

    def test_bad_hash_and_missing_content_ref_fail_red(self):
        instance = load(FIXTURES / "invalid_evidence_bad_hash.json")
        errors = validate(instance, self.schema)
        keywords = {e.keyword for e in errors}
        self.assertIn("pattern", keywords, "malformed integrity_hash should be caught by 'pattern'")
        self.assertIn("required", keywords, "missing content_ref should be caught by 'required'")

    def test_supersedes_accepts_string_or_null(self):
        instance = load(FIXTURES / "valid_evidence.json")
        instance["supersedes"] = "ev-0011"
        self.assertEqual(validate(instance, self.schema), [])
        instance["supersedes"] = None
        self.assertEqual(validate(instance, self.schema), [])
        instance["supersedes"] = 12345
        errors = validate(instance, self.schema)
        self.assertTrue(any(e.keyword == "oneOf" for e in errors))


if __name__ == "__main__":
    unittest.main()
