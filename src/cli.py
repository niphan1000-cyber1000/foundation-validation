"""
src/cli.py — CI gate check entrypoint.

Runs the real multi-domain validation engine (validators/run_all.py, which
aggregates Spectral/OpenAPI and OPA/policy findings against
rules/registry.yaml) and feeds its per-domain results into
src.core.engine.GateDecisionEngine, which applies gate_policy.yaml
(on_fail / on_error per validator) to produce the final ALLOW/WARN/BLOCK
decision.

This replaces the previous placeholder that always evaluated a hardcoded
[spectral: PASS, opa: PASS] result regardless of what the validators
actually found.
"""

import argparse
import sys
from pathlib import Path

import yaml

from src.core.models import ValidatorResult, ValidationState, GateAction
from src.core.engine import GateDecisionEngine
from src.core.evidence import EvidenceCollector, hash_paths, hash_file, hash_directory

# validators/run_all.py is a standalone module (not a package import path),
# so it needs its directory on sys.path the same way validators/run_all.py
# itself adds validators/openapi and validators/policy.
_VALIDATORS_DIR = Path(__file__).resolve().parent.parent / "validators"
if str(_VALIDATORS_DIR) not in sys.path:
    sys.path.insert(0, str(_VALIDATORS_DIR))

from run_all import run_all_validations  # noqa: E402

# Maps a GateDecisionEngine validator_name -> the "category" tag that
# validators/run_all.py attaches to each finding, and the domains_status
# key it reports execution state under. Both currently use the same string.
_DOMAINS = (("spectral", "openapi"), ("opa", "policy"))


def _domain_result(domain_status, findings, category, system_errors):
    """Turn one domain's raw execution status + findings into a ValidatorResult state."""
    if domain_status == "ERROR":
        message = "; ".join(e for e in system_errors if e.startswith(f"{category}:")) or "Unknown error"
        return ValidationState.ERROR, 0, message
    if domain_status == "SKIPPED":
        return ValidationState.SKIPPED, 0, None
    if domain_status == "NOT_APPLICABLE":
        return ValidationState.NOT_APPLICABLE, 0, None

    blocking = [f for f in findings if f.get("category") == category and f.get("effective_gate_behavior") == "FAIL"]
    if blocking:
        return ValidationState.FAIL, len(blocking), None
    return ValidationState.PASS, 0, None


def run_gate_check(
    spec_path: str = "openapi.yaml",
    policy_path: str = "gate_policy.yaml",
    registry_path: str = "rules/registry.yaml",
    environment: str = "production",
    opa_policy_dir: str = "policies",
    ruleset_path: str = None,
    evidence_dir: str = "evidence_output",
    foundation_sha: str = None,
) -> int:
    print(f"[*] Loading gate policy from {policy_path}...")
    try:
        with open(policy_path, "r", encoding="utf-8-sig") as f:
            policy_data = yaml.safe_load(f)
    except Exception as e:
        print(f"[!] ERROR: Failed to load policy file: {e}")
        return 1

    print(f"[*] Running validators against {spec_path}...")
    validation_result = run_all_validations(
        spec_path=Path(spec_path),
        registry_path=registry_path,
        policy_dir=opa_policy_dir,
        ruleset_path=ruleset_path,
        environment=environment,
    )

    domains = validation_result["execution"]["domains"]
    system_errors = validation_result["execution"]["system_errors"]
    findings = validation_result["findings"]

    results = []
    domain_findings = {}
    for validator_name, category in _DOMAINS:
        status = domains.get(category, "SKIPPED")
        state, count, error_message = _domain_result(status, findings, category, system_errors)
        results.append(ValidatorResult(
            validator_name=validator_name,
            state=state,
            findings_count=count,
            error_message=error_message,
        ))
        # Keep every finding for this domain (not just the blocking ones)
        # so the evidence chain can answer "what exactly did opa/spectral
        # find" without anyone having to re-run the gate — a raw pass/fail
        # count alone (the previous evidence shape) told you a domain
        # BLOCKed but nothing about which rule_id(s) caused it.
        domain_findings[validator_name] = [
            {
                "rule_id": f.get("rule_id"),
                "message": f.get("message"),
                "severity": f.get("severity"),
                "gate_behavior": f.get("gate_behavior"),
                "effective_gate_behavior": f.get("effective_gate_behavior"),
                "rule_version": f.get("rule_version"),
            }
            for f in findings
            if f.get("category") == category
        ]

    engine = GateDecisionEngine(policy_data)
    decision = engine.evaluate(run_id=validation_result["execution"]["execution_id"], results=results)

    # Evidence chain: record what was actually checked (inputs) and what
    # came out (per-domain results + final decision), then hash it so the
    # decision has a short, verifiable fingerprint independent of shipping
    # the full evidence file around (e.g. as a workflow_call output).
    evidence = EvidenceCollector(run_id=decision.run_id, output_dir=evidence_dir)
    evidence.add_evidence("inputs", {
        "spec_path": str(spec_path),
        "spec_hash": hash_file(spec_path),
        "registry_path": str(registry_path),
        # Content hash per registry path, not just the path string — a
        # path proves nothing once the checkout that produced it is gone;
        # this is what a reviewer actually verifies the decision against.
        "registry_hashes": hash_paths(registry_path),
        "opa_policy_dir": str(opa_policy_dir),
        "opa_policy_dir_hash": hash_directory(opa_policy_dir),
        "ruleset_path": str(ruleset_path) if ruleset_path else None,
        "ruleset_hash": hash_file(ruleset_path) if ruleset_path else None,
        # Commit SHA of the Foundation checkout this run validated against
        # (passed in by the caller, e.g. reusable-gate.yml's "Checkout
        # Foundation" step) — ties the decision to an exact, re-checkoutable
        # point in Foundation's history, not just "whatever main was at
        # checkout time."
        "foundation_commit_sha": foundation_sha,
        "environment": environment,
    })
    evidence.add_evidence("domain_results", [
        {
            "validator_name": r.validator_name,
            "state": r.state.value,
            "findings_count": r.findings_count,
            "error_message": r.error_message,
            "findings": domain_findings.get(r.validator_name, []),
        }
        for r in results
    ])
    evidence.add_evidence("gate_decision", {
        "action": decision.action.value,
        "reasons": decision.reasons,
    })
    evidence_path = evidence.save_chain()
    evidence_hash = evidence.compute_hash()

    print(f"[*] Run ID: {decision.run_id}")
    print(f"[*] Gate Action Result: {decision.action.value}")
    for reason in decision.reasons:
        print(f"    - {reason}")
    print(f"[*] Evidence saved to {evidence_path}")
    print(f"[*] Evidence hash (sha256): {evidence_hash}")

    # Machine-readable outputs for callers like GitHub Actions'
    # workflow_call outputs (`steps.<id>.outputs.<name>`), which read from
    # $GITHUB_OUTPUT rather than parsing this function's stdout log lines.
    import os
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        blocking_count = sum(r.findings_count for r in results)
        with open(github_output, "a", encoding="utf-8") as f:
            f.write(f"gate-result={decision.action.value}\n")
            f.write(f"findings-count={blocking_count}\n")
            f.write(f"evidence-hash={evidence_hash}\n")

    if decision.action == GateAction.BLOCK:
        print("[!] CI HARD GATE FAILED: Action is BLOCK.")
        return 1

    print("[+] CI HARD GATE PASSED.")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Foundation Validation Engine — CI gate check")
    parser.add_argument("--spec", default="openapi.yaml", help="Path to the OpenAPI spec to validate")
    parser.add_argument("--policy", default="gate_policy.yaml", help="Path to the gate policy YAML")
    parser.add_argument("--registry", default="rules/registry.yaml", help="Path to the rule registry YAML, or a comma-separated list of registry YAML paths to merge (later paths win on rule_id conflicts)")
    parser.add_argument("--env", default="production", help="Gate policy environment")
    parser.add_argument("--opa-policy-dir", default="policies", help="Path to the OPA policy directory (default: this repo's own policies/)")
    parser.add_argument("--ruleset", default=None, help="Path to an external Spectral ruleset (.spectral.yaml); defaults to Spectral's own auto-discovery")
    parser.add_argument("--evidence-dir", default="evidence_output", help="Directory to write the evidence chain JSON to")
    parser.add_argument("--foundation-sha", default=None, help="Commit SHA of the checked-out Foundation repo this run validated against, recorded into the evidence chain for traceability")
    args = parser.parse_args()
    sys.exit(run_gate_check(
        spec_path=args.spec,
        policy_path=args.policy,
        registry_path=args.registry,
        environment=args.env,
        opa_policy_dir=args.opa_policy_dir,
        ruleset_path=args.ruleset,
        evidence_dir=args.evidence_dir,
        foundation_sha=args.foundation_sha,
    ))


if __name__ == "__main__":
    main()
