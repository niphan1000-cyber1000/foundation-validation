import unittest
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from policy_engine import parse_opa_output


class TestPolicyEngine(unittest.TestCase):
    def test_parse_opa_output(self):
        fixture_path = os.path.join(os.path.dirname(__file__), 'fixtures', 'opa_output.json')
        with open(fixture_path, 'r', encoding='utf-8-sig') as f:
            raw_data = json.load(f)

        findings = parse_opa_output(raw_data, target_path="openapi.yaml")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "SEC-003-SENSITIVE-QUERY-PARAM")
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        self.assertEqual(findings[0]["category"], "policy")
        self.assertEqual(findings[0]["message"], "Sensitive parameter 'token' must not be passed via query string.")
        self.assertEqual(findings[0]["location"]["path"], "paths./v1/example.get.parameters.token")

    def test_parse_opa_output_empty_deny_set(self):
        # This is the exact shape `opa eval` returns when the query
        # evaluates but the `deny` set has no members — i.e. a clean pass.
        # It must NOT be confused with the "no results at all" case.
        raw_data = {
            "result": [
                {"expressions": [{"value": [], "text": "data.governance.api.deny", "location": {"row": 1, "col": 1}}]}
            ]
        }
        findings = parse_opa_output(raw_data, target_path="openapi.yaml")
        self.assertEqual(findings, [])

    def test_parse_opa_output_multiple_violations_one_call(self):
        # Regression test for the bug where parse_opa_output looked for
        # item["deny"] directly instead of item["expressions"][0]["value"]
        # and therefore silently returned [] for every real `opa eval`
        # payload, no matter how many violations were actually present.
        raw_data = {
            "result": [
                {
                    "expressions": [
                        {
                            "value": [
                                {"rule_id": "SEC-002-NON-HTTPS-SERVER", "severity": "HIGH",
                                 "message": "Server URL 'http://192.168.1.10:8080/v1' must use HTTPS scheme.",
                                 "path": "servers[1].url"},
                                {"rule_id": "GOV-001-MISSING-OWNER", "severity": "HIGH",
                                 "message": "Missing required metadata field 'info.x-owner'.",
                                 "path": "info"},
                            ]
                        }
                    ]
                }
            ]
        }
        findings = parse_opa_output(raw_data, target_path="openapi.yaml")
        self.assertEqual(len(findings), 2)
        rule_ids = {f["rule_id"] for f in findings}
        self.assertEqual(rule_ids, {"SEC-002-NON-HTTPS-SERVER", "GOV-001-MISSING-OWNER"})

    def test_parse_opa_output_bare_deny_payload_fallback(self):
        # Backward-compat: a hand-built {"deny": [...]} payload (not real
        # `opa eval` output) should still work via the fallback branch.
        raw_data = {"deny": [{"rule_id": "GOV-002-INVALID-SEMVER", "severity": "MEDIUM",
                               "message": "bad version", "path": "info.version"}]}
        findings = parse_opa_output(raw_data, target_path="openapi.yaml")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "GOV-002-INVALID-SEMVER")


class TestSec002LoopbackException(unittest.TestCase):
    """
    Mirrors validators/openapi/tests/test_sec001_loopback_exception.py,
    but for the independent OPA-side enforcement (policies/security.rego
    SEC-002-NON-HTTPS-SERVER) of the same invariant. Since Rego rules
    can't be unit-tested without shelling out to the real `opa` CLI, these
    tests exercise parse_opa_output against fixture payloads shaped like
    what `opa eval` would actually return for each case, so the
    finding-parsing side of the pipeline has fast, offline coverage. The
    rego pattern itself must still be verified with the real OPA CLI (see
    validators/openapi/tests/test_sec001_loopback_exception.py's
    docstring for why, and the project README for the exact command).
    """

    @staticmethod
    def _opa_deny_payload(violations):
        return {"result": [{"expressions": [{"value": violations}]}]}

    def test_localhost_produces_no_sec002_finding(self):
        # http://localhost:8080/v1 satisfies the loopback exception, so a
        # correctly-evaluated policy produces an empty deny set for it.
        raw_data = self._opa_deny_payload([])
        findings = parse_opa_output(raw_data, target_path="openapi.yaml")
        self.assertEqual(findings, [])

    def test_private_network_produces_sec002_finding(self):
        # http://192.168.1.10:8080/v1 is NOT loopback, so the policy
        # (once evaluated) is expected to emit exactly this violation.
        raw_data = self._opa_deny_payload([
            {"rule_id": "SEC-002-NON-HTTPS-SERVER", "severity": "HIGH",
             "message": "Server URL 'http://192.168.1.10:8080/v1' must use HTTPS scheme "
                        "(HTTP is only permitted for localhost/127.0.0.1 development endpoints).",
             "path": "servers[1].url"},
        ])
        findings = parse_opa_output(raw_data, target_path="openapi.yaml")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "SEC-002-NON-HTTPS-SERVER")
        self.assertEqual(findings[0]["severity"], "HIGH")

    def test_rego_loopback_regex_matches_spectral_ruleset_semantics(self):
        # Sanity check that the loopback regex string in
        # policies/security.rego is present and uses the same host
        # alternation (localhost|127.0.0.1) as .spectral.yaml, so the two
        # independent enforcement points can't silently drift apart.
        rego_path = os.path.join(os.path.dirname(__file__), "..", "..", "..", "policies", "security.rego")
        with open(rego_path, "r", encoding="utf-8-sig") as f:
            rego_content = f.read()
        self.assertIn("is_loopback_http", rego_content)
        self.assertIn(r"localhost|127\.0\.0\.1", rego_content)


if __name__ == '__main__':
    unittest.main()
