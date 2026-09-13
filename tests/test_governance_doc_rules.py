"""Tests for repository/document-level governance rules (GOV-DOC-*).

These rules are owned by validators/governance/governance_engine.py and
must use the GOV-DOC-* namespace so they never collide with the
API/spec-level GOV-* rules owned by policies/governance.rego.
"""
import os
import tempfile
import unittest

from validators.governance.governance_engine import run_governance_scan
from validators.run_all import load_registry, _resolve_finding


class TestGovernanceDocRules(unittest.TestCase):
    def test_emits_concrete_gov_doc_rule_ids_per_missing_field(self):
        """Engine must emit one concrete GOV-DOC-* rule_id per missing field,
        never the generic bare 'GOV-001'."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Minimal YAML missing all three required fields
            path = os.path.join(tmpdir, "manifest.yaml")
            with open(path, "w", encoding="utf-8") as f:
                f.write("name: sample-service\n")

            findings = run_governance_scan(tmpdir)
            rule_ids = {f["rule_id"] for f in findings}

            self.assertIn("GOV-DOC-001-MISSING-OWNER", rule_ids)
            self.assertIn("GOV-DOC-001-MISSING-CLASSIFICATION", rule_ids)
            self.assertIn("GOV-DOC-001-MISSING-VERSION", rule_ids)
            self.assertNotIn("GOV-001", rule_ids)
            self.assertEqual(len(findings), 3)

    def test_no_finding_when_all_fields_present(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "good.yaml")
            with open(path, "w", encoding="utf-8") as f:
                f.write(
                    "info:\n"
                    "  owner: platform-team\n"
                    "  classification: internal\n"
                    "  version: '1.0.0'\n"
                )

            findings = run_governance_scan(tmpdir)
            self.assertEqual(findings, [])

    def test_severity_resolves_from_registry_to_HIGH(self):
        """After registration, severity must come from the registry (HIGH),
        not fall through to any fail-safe default."""
        registry = load_registry("rules/registry.yaml,registry/rules.yaml")
        self.assertIn("GOV-DOC-001-MISSING-OWNER", registry)
        self.assertEqual(registry["GOV-DOC-001-MISSING-OWNER"]["severity"], "HIGH")

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "bad.yaml")
            with open(path, "w", encoding="utf-8") as f:
                f.write("name: missing-everything\n")

            findings = run_governance_scan(tmpdir)
            self.assertTrue(findings)

            for f in findings:
                resolved = _resolve_finding(f, registry, environment="ci")
                self.assertEqual(
                    resolved["severity"],
                    "HIGH",
                    msg=f"Expected HIGH for {f['rule_id']}, got {resolved['severity']}",
                )
                self.assertEqual(resolved["rule_id"], f["rule_id"])
                self.assertNotEqual(resolved["rule_id"], "GOV-001")


if __name__ == "__main__":
    unittest.main()