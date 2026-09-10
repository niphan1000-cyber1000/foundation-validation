"""
test_adversarial_matrix.py — Adversarial Validation Phase, test matrix.

Each test below corresponds to one row of the expected-outcome matrix:

    Scenario                Expected
    ------------------------------------------
    valid spec               PASS
    bad Spectral finding      BLOCK
    bad OPA finding           BLOCK
    OPA compile err           BLOCK
    Spectral missing          BLOCK
    OPA missing               BLOCK
    unknown CRITICAL rule_id  BLOCK
    unknown HIGH rule_id      BLOCK
    unknown MEDIUM rule_id    WARN (not BLOCK)
    validator crash           BLOCK
    validator timeout         BLOCK
    malformed JSON            BLOCK
    empty output              BLOCK
    missing registry          BLOCK / explicit fail-safe (not silent PASS)
    tampered rules            BLOCK (a registry entry cannot downgrade CRITICAL)
    missing schema domain     SKIPPED (see note on SKIPPED vs NOT_APPLICABLE below)

"BLOCK" here means run_all_validations()'s status is "FAILED" or "ERROR"
(both are non-zero-exit at the CLI and both feed GateDecisionEngine.BLOCK
-- see tests/test_gate_cannot_be_cheated.py for the end-to-end version of
that claim). "WARN" means status stays "PASSED" but the finding is present
with effective_gate_behavior == "WARN".

A note on SKIPPED vs NOT_APPLICABLE (raised during adversarial review):
these are deliberately different states, not two names for the same
thing. NOT_APPLICABLE means the *target itself* structurally lacks the
thing being checked (e.g. policy_dir doesn't exist on disk -- discovered
automatically, nothing to check). SKIPPED means the *caller* didn't ask
for that domain to run at all. The schema domain has no auto-discoverable
single "the schema" the way openapi has a single spec_path or policy has
a single policy_dir -- schema_checks is a list the caller must supply
explicitly, exactly like spec_path is for the openapi domain. So "no
schema_checks given" is SKIPPED (caller didn't ask), matching openapi's
own SKIPPED-when-no-spec_path convention, not NOT_APPLICABLE. See
test_missing_schema_checks_is_skipped_not_not_applicable below, which
locks in and documents this choice explicitly rather than leaving it
ambiguous.
"""
import io
import json
import os
import sys
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest.mock import patch

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, BASE_DIR)

import run_all  # noqa: E402
from run_all import run_all_validations  # noqa: E402


def _spectral_item(code="TEST-RULE", severity=0, message="test finding"):
    """severity: 0=CRITICAL, 1=HIGH, 2=MEDIUM, 3=LOW (Spectral's own coding)."""
    return {"code": code, "message": message, "severity": severity, "path": ["paths"]}


def _opa_result(violations):
    return {"result": [{"expressions": [{"value": violations}]}]}


class TestAdversarialMatrix(unittest.TestCase):

    # 1. valid spec -> PASS
    def test_valid_spec_passes(self):
        result = run_all_validations(openapi_json_data=[], opa_json_data=_opa_result([]))
        self.assertEqual(result["status"], "PASSED")
        self.assertEqual(result["summary"]["total_findings"], 0)

    # 2. bad Spectral -> BLOCK
    def test_bad_spectral_finding_blocks(self):
        result = run_all_validations(openapi_json_data=[_spectral_item(severity=0)])
        self.assertEqual(result["status"], "FAILED")

    # 3. bad OPA -> BLOCK
    def test_bad_opa_finding_blocks(self):
        result = run_all_validations(opa_json_data=_opa_result(
            [{"message": "no auth", "severity": "HIGH", "rule_id": "SEC-001-MISSING-SECURITY"}]
        ))
        self.assertEqual(result["status"], "FAILED")

    # 4. OPA compile err -> BLOCK (PolicyOutputError fix)
    def test_opa_compile_error_blocks(self):
        result = run_all_validations(opa_json_data={
            "errors": [{"message": "rego_parse_error: unexpected eof", "location": {"file": "x.rego", "row": 1}}]
        })
        self.assertEqual(result["status"], "ERROR")
        self.assertEqual(result["execution"]["domains"]["policy"], "ERROR")

    # 5. Spectral missing -> BLOCK
    def test_spectral_missing_blocks(self):
        with patch.object(run_all, "_resolve_executable", return_value=None):
            result = run_all_validations(spec_path="openapi-good-example.json")
        self.assertEqual(result["status"], "ERROR")
        self.assertEqual(result["execution"]["domains"]["openapi"], "ERROR")

    # 6. OPA missing -> BLOCK
    def test_opa_missing_blocks(self):
        with patch.object(run_all, "_resolve_executable", side_effect=lambda name: None if name == "opa" else "/usr/bin/true"):
            result = run_all_validations(spec_path="openapi-good-example.json", openapi_json_data=[], policy_dir="policies")
        self.assertEqual(result["execution"]["domains"]["policy"], "ERROR")
        self.assertEqual(result["status"], "ERROR")

    # 7. unknown CRITICAL rule_id -> BLOCK
    def test_unknown_critical_rule_blocks(self):
        result = run_all_validations(openapi_json_data=[_spectral_item(code="totally-unregistered-rule", severity=0)])
        finding = result["findings"][0]
        self.assertEqual(finding["severity"], "CRITICAL")
        self.assertEqual(finding["effective_gate_behavior"], "FAIL")
        self.assertEqual(result["status"], "FAILED")

    # 8. unknown HIGH rule_id -> BLOCK
    def test_unknown_high_rule_blocks(self):
        result = run_all_validations(openapi_json_data=[_spectral_item(code="totally-unregistered-rule", severity=1)])
        finding = result["findings"][0]
        self.assertEqual(finding["severity"], "HIGH")
        self.assertEqual(finding["effective_gate_behavior"], "FAIL")
        self.assertEqual(result["status"], "FAILED")

    # 9. unknown MEDIUM rule_id -> WARN, not BLOCK
    def test_unknown_medium_rule_warns_not_blocks(self):
        result = run_all_validations(openapi_json_data=[_spectral_item(code="totally-unregistered-rule", severity=2)])
        finding = result["findings"][0]
        self.assertEqual(finding["severity"], "MEDIUM")
        self.assertEqual(finding["effective_gate_behavior"], "WARN")
        self.assertEqual(result["status"], "PASSED", "a MEDIUM-only finding must not block the gate")
        self.assertEqual(result["summary"]["medium"], 1)

    # 10. validator crash -> BLOCK (broadened except Exception fix)
    def test_validator_crash_blocks_not_propagates(self):
        # A malformed item inside an otherwise well-formed JSON array
        # (AttributeError: 'str' object has no attribute 'get') used to
        # propagate as an uncaught exception. It must now resolve to a
        # graceful domain ERROR instead.
        result = run_all_validations(openapi_json_data=["not-a-dict-entry"])
        self.assertEqual(result["status"], "ERROR")
        self.assertEqual(result["execution"]["domains"]["openapi"], "ERROR")

    # 11. validator timeout -> BLOCK
    def test_validator_timeout_blocks(self):
        import subprocess
        with patch.object(run_all, "_resolve_executable", return_value="/usr/bin/npx"), \
             patch.object(run_all.subprocess, "run", side_effect=subprocess.TimeoutExpired(cmd="npx", timeout=120)):
            result = run_all_validations(spec_path="openapi-good-example.json")
        self.assertEqual(result["status"], "ERROR")
        self.assertEqual(result["execution"]["domains"]["openapi"], "ERROR")

    # 12. malformed JSON -> BLOCK
    def test_malformed_json_string_blocks(self):
        result = run_all_validations(openapi_json_data="{not valid json")
        self.assertEqual(result["status"], "ERROR")
        self.assertEqual(result["execution"]["domains"]["openapi"], "ERROR")

    # 13. empty output -> BLOCK
    def test_empty_tool_output_blocks(self):
        with patch.object(run_all, "_resolve_executable", return_value="/usr/bin/npx"):
            import subprocess as sp
            fake_proc = type("P", (), {"stdout": "", "stderr": "", "returncode": 1})()
            with patch.object(run_all.subprocess, "run", return_value=fake_proc):
                result = run_all_validations(spec_path="openapi-good-example.json")
        self.assertEqual(result["status"], "ERROR")
        self.assertEqual(result["execution"]["domains"]["openapi"], "ERROR")

    # 14. missing registry -> BLOCK / explicit fail-safe (never a silent PASS)
    def test_missing_registry_is_explicit_not_silent(self):
        stderr_capture = io.StringIO()
        with redirect_stderr(stderr_capture):
            result = run_all_validations(
                openapi_json_data=[_spectral_item(code="oas3-schema", severity=0)],
                registry_path="__no_such_registry_file__.yaml",
            )
        # Fail-safe default for CRITICAL still applies even with an empty registry.
        self.assertEqual(result["status"], "FAILED")
        # And it must have been a LOGGED event, not a silent fallback.
        self.assertIn("registry file not found", stderr_capture.getvalue())

    # 15. tampered rules -> BLOCK (registry cannot downgrade CRITICAL; the
    # "Gate Cannot Be Cheated" invariant added to _resolve_finding)
    def test_tampered_registry_cannot_downgrade_critical(self):
        tampered_registry = {
            "SEC-999-tampered": {"severity": "CRITICAL", "gate_behavior": "WARN", "version": "1.0.0"}
        }
        result = run_all_validations(
            openapi_json_data=[{"code": "SEC-999-tampered", "message": "m", "severity": 0, "path": []}],
        )
        # (Uses the real bundled registry above; this variant proves the
        # invariant directly against _resolve_finding, bypassing
        # run_all_validations()'s own file-based registry loading, since
        # that's the unit under test here -- see
        # tests/test_gate_cannot_be_cheated.py for the registry-file-based
        # end-to-end version of the same claim.)
        from run_all import _resolve_finding
        finding = {"rule_id": "SEC-999-tampered", "severity": "CRITICAL", "category": "policy", "message": "m"}
        resolved = _resolve_finding(finding, tampered_registry, "production")
        self.assertEqual(
            resolved["effective_gate_behavior"], "FAIL",
            "a registry entry downgraded a CRITICAL finding to non-blocking -- "
            "the gate was cheated",
        )

    # 16. missing schema domain -> SKIPPED (documented distinction from NOT_APPLICABLE)
    def test_missing_schema_checks_is_skipped_not_not_applicable(self):
        result = run_all_validations()
        self.assertEqual(result["execution"]["domains"]["schema"], "SKIPPED")
        # Contrast with the policy domain, which DOES use NOT_APPLICABLE --
        # because policy_dir's absence is discovered from the target, not
        # from the caller declining to ask. This test exists specifically
        # so the SKIPPED-vs-NOT_APPLICABLE distinction is enforced by CI,
        # not just documented in a comment someone can drift away from.
        result2 = run_all_validations(spec_path="openapi-good-example.json", openapi_json_data=[], policy_dir="__no_such_policy_dir__")
        self.assertEqual(result2["execution"]["domains"]["policy"], "NOT_APPLICABLE")


if __name__ == "__main__":
    unittest.main()
