"""
run_all.py — repository-root CI / pre-commit entrypoint.

This is a thin wrapper: the actual multi-domain aggregation engine lives in
validators/run_all.py (Spectral + OPA aggregation against
rules/registry.yaml), and the gate-policy decision layer lives in
src/core/engine.py (GateDecisionEngine over gate_policy.yaml). src/cli.py
wires the two together. This file just gives CI and the pre-commit hook a
stable `python run_all.py` entrypoint at the repo root, matching what
scripts/install-hooks.sh / install-hooks.ps1 invoke.

--test-failure-injection is a negative control used by
validators/tests/test_process_boundary.py and
.github/workflows/governance.yml's "Verify Gate Blocks on Errors" step. It
builds one synthetic ERROR-state ValidatorResult and runs it through the
REAL GateDecisionEngine — not just `sys.exit(1)` — so a passing run here is
actual evidence that ERROR -> GateDecisionEngine -> BLOCK -> non-zero exit
code holds end-to-end, not just that "some process can return non-zero".
"""

import argparse
import sys


def _run_failure_injection() -> int:
    print("Running Failure Injection test simulation...")
    try:
        from src.core.models import ValidatorResult, ValidationState, GateAction
        from src.core.engine import GateDecisionEngine
    except ImportError as e:
        print(f"[!] CRITICAL: could not load the gate engine for failure injection: {e}")
        return 1

    # Deliberately on_error: WARN — NOT BLOCK. GateDecisionEngine's
    # fail-safe branch (src/core/engine.py) must force BLOCK for an ERROR
    # state regardless of what policy says, so this is a live invariant
    # check, not just a smoke test: if a future change to engine.py ever
    # starts honoring on_error for ERROR states, this WARN would leak
    # through as ALLOW/WARN and the assertion below would catch it.
    policy = {"rules": {"injected-validator": {"on_fail": "BLOCK", "on_error": "WARN"}}}
    results = [ValidatorResult(
        validator_name="injected-validator",
        state=ValidationState.ERROR,
        error_message="Simulated failure injection (CI negative control)",
    )]

    engine = GateDecisionEngine(policy)
    decision = engine.evaluate(run_id="failure-injection", results=results)

    print("[*] Injected result: injected-validator -> ERROR (policy on_error: WARN)")
    print(f"[*] Gate Action Result: {decision.action.value}")
    for reason in decision.reasons:
        print(f"    - {reason}")

    if decision.action != GateAction.BLOCK:
        print(
            "[!] CRITICAL: fail-safe invariant broken — an ERROR state did "
            "NOT resolve to BLOCK, even with an on_error: WARN policy "
            "entry present. This is a regression in GateDecisionEngine "
            "itself (src/core/engine.py), not just a test failure."
        )
        return 2

    print("[+] Failure injection correctly produced GateAction.BLOCK (fail-safe holds).")
    return 1  # Negative control: this run is EXPECTED to block (non-zero).


def main():
    parser = argparse.ArgumentParser(description="Foundation Validation Engine — root gate entrypoint")
    parser.add_argument("--spec", default="openapi.yaml", help="Path to the OpenAPI spec to validate")
    parser.add_argument("--policy", default="gate_policy.yaml", help="Path to the gate policy YAML")
    parser.add_argument("--registry", default="rules/registry.yaml", help="Path to the rule registry YAML")
    parser.add_argument("--env", default="production", help="Gate policy environment")
    parser.add_argument(
        "--test-failure-injection",
        action="store_true",
        help="Negative control: run a synthetic ERROR result through the real GateDecisionEngine",
    )
    args = parser.parse_args()

    if args.test_failure_injection:
        sys.exit(_run_failure_injection())

    from src.cli import run_gate_check

    sys.exit(run_gate_check(
        spec_path=args.spec,
        policy_path=args.policy,
        registry_path=args.registry,
        environment=args.env,
    ))


if __name__ == "__main__":
    main()
