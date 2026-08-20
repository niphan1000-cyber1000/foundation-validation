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
validators/tests/test_process_boundary.py and Invoke-GateCheck.ps1 -InputType
ERROR/BAD: it deliberately exits non-zero WITHOUT running any real
validators, to prove the gate fails closed rather than silently passing.
"""

import argparse
import sys


def main():
    parser = argparse.ArgumentParser(description="Foundation Validation Engine — root gate entrypoint")
    parser.add_argument("--spec", default="openapi.yaml", help="Path to the OpenAPI spec to validate")
    parser.add_argument("--policy", default="gate_policy.yaml", help="Path to the gate policy YAML")
    parser.add_argument("--registry", default="rules/registry.yaml", help="Path to the rule registry YAML")
    parser.add_argument("--env", default="production", help="Gate policy environment")
    parser.add_argument(
        "--test-failure-injection",
        action="store_true",
        help="Negative control: simulate a blocked gate without running real validators",
    )
    args = parser.parse_args()

    if args.test_failure_injection:
        # Deliberately does NOT import src.cli — this path must stay usable
        # as a pure negative control even if the real engine's dependencies
        # (pydantic, pyyaml) aren't installed.
        print("Running Failure Injection test simulation...")
        sys.exit(1)

    # Imported lazily so the --test-failure-injection path above never
    # requires pydantic/pyyaml to be installed.
    from src.cli import run_gate_check

    sys.exit(run_gate_check(
        spec_path=args.spec,
        policy_path=args.policy,
        registry_path=args.registry,
        environment=args.env,
    ))


if __name__ == "__main__":
    main()
