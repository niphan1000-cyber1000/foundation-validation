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
        environment=environment,
    )

    domains = validation_result["execution"]["domains"]
    system_errors = validation_result["execution"]["system_errors"]
    findings = validation_result["findings"]

    results = []
    for validator_name, category in _DOMAINS:
        status = domains.get(category, "SKIPPED")
        state, count, error_message = _domain_result(status, findings, category, system_errors)
        results.append(ValidatorResult(
            validator_name=validator_name,
            state=state,
            findings_count=count,
            error_message=error_message,
        ))

    engine = GateDecisionEngine(policy_data)
    decision = engine.evaluate(run_id=validation_result["execution"]["execution_id"], results=results)

    print(f"[*] Run ID: {decision.run_id}")
    print(f"[*] Gate Action Result: {decision.action.value}")
    for reason in decision.reasons:
        print(f"    - {reason}")

    if decision.action == GateAction.BLOCK:
        print("[!] CI HARD GATE FAILED: Action is BLOCK.")
        return 1

    print("[+] CI HARD GATE PASSED.")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Foundation Validation Engine — CI gate check")
    parser.add_argument("--spec", default="openapi.yaml", help="Path to the OpenAPI spec to validate")
    parser.add_argument("--policy", default="gate_policy.yaml", help="Path to the gate policy YAML")
    parser.add_argument("--registry", default="rules/registry.yaml", help="Path to the rule registry YAML")
    parser.add_argument("--env", default="production", help="Gate policy environment")
    args = parser.parse_args()
    sys.exit(run_gate_check(
        spec_path=args.spec,
        policy_path=args.policy,
        registry_path=args.registry,
        environment=args.env,
    ))


if __name__ == "__main__":
    main()
