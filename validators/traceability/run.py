#!/usr/bin/env python3
"""
run.py — Traceability domain validator CLI.

Cross-references rules/registry.yaml against a requirement catalogue
(rules/requirements.json) and prints a JSON object shaped like a partial
GateResult: a list of `Finding` records (see
schemas/validation-result.schema.json). This is the traceability-domain
implementation described as "Not yet implemented" in this folder's
README — it is now implemented for the TRC- rule set. See
traceability_engine.py for the check logic and its documented
limitations.

Usage:
    python3 run.py --registry ../../rules/registry.yaml \\
                    --requirements ../../rules/requirements.json

Exit code is 0 if the check passes (zero findings), 1 if it fails, 2 on
a usage/loading error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

from traceability_engine import check_traceability


def _load_registry(path: Path) -> dict:
    if not yaml:
        raise RuntimeError("PyYAML is required to load the rule registry (pip install pyyaml)")
    data = yaml.safe_load(path.read_text(encoding="utf-8-sig")) or {}
    return {(r.get("rule_id") or r.get("id")): r for r in data.get("rules", [])}


def _load_requirements(path: Path) -> dict:
    if not path.exists():
        # Fail-safe: no catalogue yet is a valid (if incomplete) state,
        # not a usage error — see traceability_engine.py's module docstring.
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {r["requirement_id"]: r for r in data.get("requirements", [])}


def run(registry_path: Path, requirements_path: Path) -> dict:
    registry = _load_registry(registry_path)
    requirements = _load_requirements(requirements_path)
    findings = check_traceability(registry, requirements)

    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1

    status = "PASSED" if not findings else "FAILED"
    return {
        "registry": str(registry_path),
        "requirements": str(requirements_path),
        "status": status,
        "summary": summary,
        "findings": findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Traceability domain validator (TRC- rules).")
    parser.add_argument("--registry", required=True, type=Path, help="Path to rules/registry.yaml")
    parser.add_argument("--requirements", required=True, type=Path,
                         help="Path to the requirement catalogue JSON (rules/requirements.json)")
    args = parser.parse_args()

    try:
        result = run(args.registry, args.requirements)
    except (FileNotFoundError, json.JSONDecodeError, RuntimeError) as e:
        print(json.dumps({"error": "load_error", "message": str(e)}, indent=2))
        return 2

    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "PASSED" else 1


if __name__ == "__main__":
    sys.exit(main())
