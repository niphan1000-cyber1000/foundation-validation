"""
tests/test_gate_cannot_be_cheated.py — Adversarial Validation Phase.

validators/tests/test_adversarial_matrix.py answers "does bad input
produce BLOCK" at the aggregator layer (validators/run_all.py). This file
answers a harder question, at the layer that actually decides CI's exit
code:

    attacker/bug touches validation logic or its inputs
                    v
            trusted guard
    (run_all.py resolution + src/cli.py wiring + GateDecisionEngine)
                    v
      modification cannot weaken enforcement
                    v
                 BLOCK

Each test names one specific point in the pipeline and proves a violation
detected upstream cannot be laundered into a non-blocking outcome as it
flows downstream to decision.action, the value CI actually acts on.

Three concrete gaps were found and fixed during this review (see the
class docstrings below for the mechanism of each):
  1. schema/traceability domain findings never reached GateDecisionEngine
     at all (src/cli.py's _DOMAINS tuple only listed spectral/opa).
  2. A registry entry could declare severity: CRITICAL with
     gate_behavior: WARN and silently downgrade enforcement
     (validators/run_all.py::_resolve_finding trusted gate_behavior
     verbatim with no severity floor).
  3. An OPA compile-error payload ({"errors": [...]}), if it reached
     parse_opa_output() by any path other than _invoke_opa's own
     pre-check, was silently read as zero violations.

This file also statically audits the CI workflow YAML and the Spectral
ruleset for the same class of problem outside Python: a gate step quietly
marked continue-on-error, or a registry rule whose severity has drifted
out of sync with the ruleset that's supposed to enforce it.
"""
import re
import subprocess
import sys
import unittest
import yaml
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "validators"))

import src.cli as cli_mod  # noqa: E402
from src.cli import run_gate_check  # noqa: E402
import run_all as run_all_mod  # noqa: E402


def _fake_result(domains, findings, system_errors=None):
    return {
        "execution": {
            "execution_id": "fake-run",
            "domains": domains,
            "system_errors": system_errors or [],
        },
        "status": "FAILED" if findings else "PASSED",
        "summary": {"total_findings": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0},
        "findings": findings,
        "evidence": {"artifacts": [], "hash_digest": "fake"},
    }


class TestSchemaAndTraceabilityReachTheRealDecision(unittest.TestCase):
    """
    FIXED GAP #1: wiring a domain into validators/run_all.py's aggregator
    is necessary but not sufficient -- src/cli.py's _DOMAINS tuple (which
    feeds GateDecisionEngine, the thing that actually produces
    ALLOW/WARN/BLOCK) has to list it too. Before this fix, a schema/TRC
    finding could make run_all_validations()["status"] == "FAILED" while
    run_gate_check() -- the real CI entrypoint -- still returned exit
    code 0, because those findings never became a ValidatorResult.
    """

    def test_run_gate_check_accepts_schema_and_traceability_params(self):
        import inspect
        sig = inspect.signature(run_gate_check)
        self.assertIn("schema_checks", sig.parameters)
        self.assertIn("enable_traceability", sig.parameters)

    def test_schema_only_failure_flips_decision_to_block(self):
        """Deterministic, network-independent proof: with every other
        domain SKIPPED and only schema FAILED, the real gate must BLOCK."""
        finding = {
            "rule_id": "SCH-001", "severity": "HIGH", "category": "schema",
            "message": "fake violation", "gate_behavior": "FAIL", "effective_gate_behavior": "FAIL",
            "location": {"file": "x", "path": "root", "line": 0},
        }
        fake = _fake_result(
            {"openapi": "SKIPPED", "policy": "SKIPPED", "schema": "RUN", "traceability": "SKIPPED"},
            [finding],
        )
        with patch.object(cli_mod, "run_all_validations", return_value=fake):
            rc = run_gate_check(evidence_dir="/tmp/test_gate_cheat_schema")
        self.assertEqual(rc, 1, "a FAILED schema domain did not block the real CI gate")

    def test_traceability_only_failure_flips_decision_to_block(self):
        finding = {
            "rule_id": "TRC-001", "severity": "HIGH", "category": "traceability",
            "message": "fake violation", "gate_behavior": "FAIL", "effective_gate_behavior": "FAIL",
            "location": {"file": "rules/registry.yaml", "path": "X", "line": 0},
        }
        fake = _fake_result(
            {"openapi": "SKIPPED", "policy": "SKIPPED", "schema": "SKIPPED", "traceability": "RUN"},
            [finding],
        )
        with patch.object(cli_mod, "run_all_validations", return_value=fake):
            rc = run_gate_check(evidence_dir="/tmp/test_gate_cheat_trc")
        self.assertEqual(rc, 1, "a FAILED traceability domain did not block the real CI gate")

    def test_regression_pre_fix_domains_tuple_would_have_allowed(self):
        """Documents the bug this fix closed: with the OLD (2-domain)
        _DOMAINS tuple, the exact same schema failure above would have
        been silently dropped and the gate would have ALLOWed. This test
        pins the old tuple's behavior so nobody mistakes today's fix for
        a no-op, and so a future accidental revert of _DOMAINS is caught
        immediately."""
        finding = {
            "rule_id": "SCH-001", "severity": "HIGH", "category": "schema",
            "message": "fake violation", "gate_behavior": "FAIL", "effective_gate_behavior": "FAIL",
            "location": {},
        }
        fake = _fake_result(
            {"openapi": "SKIPPED", "policy": "SKIPPED", "schema": "RUN", "traceability": "SKIPPED"},
            [finding],
        )
        old_domains = (("spectral", "openapi"), ("opa", "policy"))
        with patch.object(cli_mod, "run_all_validations", return_value=fake), \
             patch.object(cli_mod, "_DOMAINS", old_domains):
            rc = run_gate_check(evidence_dir="/tmp/test_gate_cheat_regression")
        self.assertEqual(rc, 0, "sanity check on the OLD behavior failed -- test itself may be wrong")

    def test_schema_violation_actually_blocks_via_real_cli_subprocess(self):
        """Best-effort end-to-end: invoke `python -m src.cli` as CI would,
        pointed at a fixture known to violate a real schema. Non-zero exit
        is required either way (a genuinely offline environment will also
        fail spectral/opa for unrelated network reasons, which is still a
        correct BLOCK) -- the deterministic, isolated proof is the
        monkeypatched test above; this one guards against the wiring
        being correct in isolation but broken in real argument-parsing/
        subprocess plumbing."""
        result = subprocess.run(
            [
                sys.executable, "-m", "src.cli",
                "--spec", "openapi-good-example.json",
                "--opa-policy-dir", "__no_such_policy_dir__",
                "--schema-check",
                "schemas/validation-request.schema.json=validators/schema/tests/fixtures/invalid_request_missing_target.json",
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}")


class TestCriticalSeverityCannotBeDowngraded(unittest.TestCase):
    """
    FIXED GAP #2: validators/run_all.py::_resolve_finding trusted a
    registered rule's gate_behavior verbatim, with no floor tied to
    severity. A registry entry declaring severity: CRITICAL,
    gate_behavior: WARN -- whether from a careless edit or a genuinely
    tampered SSOT -- resolved to effective_gate_behavior "WARN", i.e. a
    CRITICAL finding that would NOT block. This is the literal "attacker
    modifies validation logic (the registry, which drives resolution) ->
    trusted guard (_resolve_finding) -> cannot weaken enforcement" case
    from the adversarial review brief.
    """

    def test_tampered_registry_entry_cannot_downgrade_critical_end_to_end(self):
        """End-to-end through the REAL GateDecisionEngine: a tampered
        registry entry for a CRITICAL rule must still BLOCK."""
        tampered_registry = {
            "SEC-999-tampered": {"severity": "CRITICAL", "gate_behavior": "WARN", "version": "1.0.0"}
        }
        finding = run_all_mod._resolve_finding(
            {"rule_id": "SEC-999-tampered", "severity": "CRITICAL", "category": "policy", "message": "m"},
            tampered_registry,
            "production",
        )
        self.assertEqual(finding["effective_gate_behavior"], "FAIL")

        fake = _fake_result(
            {"openapi": "SKIPPED", "policy": "RUN", "schema": "SKIPPED", "traceability": "SKIPPED"},
            [finding],
        )
        with patch.object(cli_mod, "run_all_validations", return_value=fake):
            rc = run_gate_check(evidence_dir="/tmp/test_gate_cheat_critical")
        self.assertEqual(rc, 1, "a tampered registry entry downgraded a CRITICAL finding past the real gate")

    def test_legitimate_high_plus_warn_authoring_choice_is_still_respected(self):
        """Negative control: the fix must be scoped to CRITICAL only. A
        registry owner legitimately choosing gate_behavior: WARN for a
        HIGH-severity rule (a real, intentional authoring decision, not a
        cheat) must NOT be clamped -- otherwise the fix would remove
        legitimate flexibility the registry is designed to provide."""
        registry = {"X": {"severity": "HIGH", "gate_behavior": "WARN", "version": "1.0"}}
        finding = run_all_mod._resolve_finding(
            {"rule_id": "X", "severity": "HIGH", "category": "policy", "message": "m"}, registry, "production"
        )
        self.assertEqual(finding["effective_gate_behavior"], "WARN")


class TestOpaCompileErrorCannotBeLaunderedIntoAPass(unittest.TestCase):
    """
    FIXED GAP #3: parse_opa_output() had no check for the
    {"errors": [...]} shape `opa eval` produces on a compile/parse
    failure -- only _invoke_opa (one specific caller) checked for it
    before calling parse_opa_output. Any other path that reaches
    parse_opa_output with raw `opa eval` JSON (run_all_validations's own
    opa_json_data injection parameter, used by this engine's tests and
    any future caching layer) silently read zero violations from a
    policy that never actually ran.
    """

    def test_opa_compile_error_end_to_end_blocks(self):
        from run_all import run_all_validations
        result = run_all_validations(opa_json_data={
            "errors": [{"message": "rego_parse_error: unexpected eof", "location": {"file": "x.rego", "row": 1}}]
        })
        self.assertEqual(result["status"], "ERROR")

        fake = _fake_result(
            {"openapi": "SKIPPED", "policy": "ERROR", "schema": "SKIPPED", "traceability": "SKIPPED"},
            [],
            system_errors=["policy: OPA policy failed to compile/evaluate at x.rego:1: rego_parse_error: unexpected eof"],
        )
        with patch.object(cli_mod, "run_all_validations", return_value=fake):
            rc = run_gate_check(evidence_dir="/tmp/test_gate_cheat_opa_compile")
        self.assertEqual(rc, 1, "an OPA compile error did not block the real CI gate")


class TestWorkflowCannotBeQuietlyDefanged(unittest.TestCase):
    """
    Static audit of the CI workflow YAML itself: proves nobody can
    silently make the gate cosmetic by adding continue-on-error: true (or
    an unconditional success) to the step that actually runs the gate,
    without a reviewer noticing it as a code change to the workflow file.
    This can't be caught by any Python unit test above, because those all
    run gate logic directly -- this is the layer ABOVE that logic (does
    CI even respect its exit code).
    """

    def _load_workflow(self, name):
        path = REPO_ROOT / ".github" / "workflows" / name
        with open(path, "r", encoding="utf-8-sig") as f:
            return yaml.safe_load(f), path.read_text(encoding="utf-8-sig")

    def test_governance_workflow_gate_step_has_no_continue_on_error(self):
        data, raw = self._load_workflow("governance.yml")
        for job_name, job in data.get("jobs", {}).items():
            for step in job.get("steps", []):
                self.assertNotEqual(
                    step.get("continue-on-error"), True,
                    f"job '{job_name}' step '{step.get('name')}' has continue-on-error: true -- "
                    f"this would make its result cosmetic regardless of what the gate logic decides",
                )

    def test_reusable_gate_workflow_gate_step_has_no_continue_on_error(self):
        data, raw = self._load_workflow("reusable-gate.yml")
        for job_name, job in data.get("jobs", {}).items():
            for step in job.get("steps", []):
                self.assertNotEqual(step.get("continue-on-error"), True)

    def test_governance_workflow_gate_step_does_not_swallow_exit_code(self):
        """A `run:` step ending in `|| true` (or similar) defeats the
        gate just as effectively as continue-on-error: true, without
        needing that explicit YAML key at all -- check the shell itself,
        not just the step metadata."""
        data, _ = self._load_workflow("governance.yml")
        for job in data.get("jobs", {}).values():
            for step in job.get("steps", []):
                run_cmd = step.get("run", "")
                if "run_all.py" in run_cmd or "src.cli" in run_cmd:
                    self.assertNotRegex(
                        run_cmd, r"\|\|\s*true\b",
                        f"gate-invoking step '{step.get('name')}' pipes its exit code to `|| true`, "
                        f"silently discarding a non-zero (BLOCK) result",
                    )


class TestRuleRegistryCannotDriftAheadOfTheRulesetEnforcingIt(unittest.TestCase):
    """
    Static consistency check between rules/registry.yaml (documentation +
    severity/gate_behavior source of truth) and .spectral.yaml (what
    actually runs). If someone deletes or downgrades a custom rule in
    .spectral.yaml without updating the registry, the registry keeps
    claiming a protection that no longer exists at runtime -- a silent
    drift that looks identical to "everything's fine" until the specific
    violation it used to catch slips through. This doesn't test run_all.py
    at all; it tests that the two source files describing the same rules
    haven't quietly diverged.
    """

    def test_every_registered_openapi_custom_rule_exists_in_spectral_ruleset_at_error_severity(self):
        registry_path = REPO_ROOT / "rules" / "registry.yaml"
        ruleset_path = REPO_ROOT / ".spectral.yaml"
        with open(registry_path, "r", encoding="utf-8-sig") as f:
            registry_data = yaml.safe_load(f)
        with open(ruleset_path, "r", encoding="utf-8-sig") as f:
            ruleset_data = yaml.safe_load(f)

        ruleset_rules = ruleset_data.get("rules", {})

        for rule in registry_data.get("rules", []):
            rule_id = rule.get("rule_id")
            # Only rule_ids that look like this repo's own custom Spectral
            # rules (not built-in spectral:oas rule names like
            # "oas3-schema", which never appear as keys in .spectral.yaml's
            # own `rules:` section) are in scope here.
            if rule.get("domain") != "openapi" or not re.match(r"^(OAS|SEC)-\d", rule_id):
                continue
            if rule.get("status") != "active":
                continue

            self.assertIn(
                rule_id, ruleset_rules,
                f"registry.yaml documents '{rule_id}' as an active openapi rule, but "
                f".spectral.yaml no longer defines it -- the registry is claiming a "
                f"protection that doesn't run",
            )
            declared_severity = str(ruleset_rules[rule_id].get("severity", "")).lower()
            if rule.get("severity") in ("CRITICAL", "HIGH"):
                self.assertEqual(
                    declared_severity, "error",
                    f"'{rule_id}' is registered as {rule.get('severity')} (should block) but "
                    f".spectral.yaml declares it as severity: {declared_severity!r} -- Spectral "
                    f"will not treat this as blockable at the tool level",
                )


if __name__ == "__main__":
    unittest.main()
