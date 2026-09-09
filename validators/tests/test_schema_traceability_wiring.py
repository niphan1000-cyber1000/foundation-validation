import os
import sys
import unittest

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BASE_DIR)

from run_all import run_all_validations  # noqa: E402


class TestSchemaDomainWiring(unittest.TestCase):
    def test_schema_domain_skipped_by_default(self):
        result = run_all_validations()
        self.assertEqual(result["execution"]["domains"]["schema"], "SKIPPED")

    def test_schema_domain_runs_via_injected_findings(self):
        mock_schema_findings = [
            {
                "rule_id": "SCH-001",
                "severity": "HIGH",
                "category": "schema",
                "message": "[required] at root: 'target' is a required property",
                "location": {"file": "some-payload.json", "path": "root", "line": 0},
            }
        ]
        result = run_all_validations(schema_json_data=mock_schema_findings)
        self.assertEqual(result["execution"]["domains"]["schema"], "RUN")
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["summary"]["total_findings"], 1)
        self.assertEqual(result["summary"]["high"], 1)

    def test_schema_domain_runs_a_real_check_against_a_valid_target(self):
        # Validate one of this repo's own fixtures against its own schema,
        # exercising the actual _run_schema_check() code path (no injection).
        schema_path = os.path.join(BASE_DIR, "schema", "tests", "fixtures", "valid_request.json")
        # valid_request.json is itself a fixture instance; validate it
        # against the real validation-request schema shipped in /schemas.
        real_schema = os.path.join(
            os.path.dirname(BASE_DIR), "schemas", "validation-request.schema.json"
        )
        result = run_all_validations(
            schema_checks=[{"schema": real_schema, "target": schema_path}]
        )
        self.assertEqual(result["execution"]["domains"]["schema"], "RUN")
        self.assertEqual(result["status"], "PASSED")
        self.assertEqual(result["summary"]["total_findings"], 0)

    def test_schema_domain_reports_error_not_silent_pass_on_bad_target(self):
        result = run_all_validations(
            schema_checks=[{"schema": "/no/such/schema.json", "target": "/no/such/target.json"}]
        )
        self.assertEqual(result["execution"]["domains"]["schema"], "ERROR")
        self.assertEqual(result["status"], "ERROR")
        self.assertTrue(any("schema:" in e for e in result["execution"]["system_errors"]))


class TestTraceabilityDomainWiring(unittest.TestCase):
    def test_traceability_domain_skipped_by_default(self):
        result = run_all_validations()
        self.assertEqual(result["execution"]["domains"]["traceability"], "SKIPPED")

    def test_traceability_domain_runs_via_injected_findings(self):
        mock_trc_findings = [
            {
                "rule_id": "TRC-001",
                "severity": "HIGH",
                "category": "traceability",
                "message": "Mandatory rule 'OAS-001-path-kebab-case' has no requirement_id mapped.",
                "location": {"file": "rules/registry.yaml", "path": "OAS-001-path-kebab-case", "line": 0},
            }
        ]
        result = run_all_validations(traceability_json_data=mock_trc_findings)
        self.assertEqual(result["execution"]["domains"]["traceability"], "RUN")
        self.assertEqual(result["status"], "FAILED")
        self.assertEqual(result["summary"]["high"], 1)

    def test_traceability_domain_flags_unmapped_mandatory_rule_against_real_registry(self):
        # Every rule in this repo's own rules/registry.yaml currently has
        # requirement_id: null (see that file's header comments), so
        # enabling the domain against the real registry with an empty
        # requirement catalogue must surface at least one TRC-001 --
        # this is the documented, expected gap, not a bug.
        result = run_all_validations(enable_traceability=True)
        self.assertEqual(result["execution"]["domains"]["traceability"], "RUN")
        trc_findings = [f for f in result["findings"] if f["category"] == "traceability"]
        self.assertTrue(any(f["rule_id"] == "TRC-001" for f in trc_findings))
        self.assertEqual(result["status"], "FAILED")


if __name__ == "__main__":
    unittest.main()
