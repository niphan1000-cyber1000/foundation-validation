#!/usr/bin/env python3
"""
run.py — Schema domain validator CLI.

Validates a target JSON/YAML document against one of the schemas in
/schemas, and prints a JSON object shaped like a partial GateResult
(see schemas/validation-result.schema.json): a list of `Finding`
records, each carrying its `Evidence`. This is the schema-domain
implementation described as "not yet implemented" in this folder's
README — it is now implemented for the SCH- rule set.

Usage:
    python3 run.py --schema ../../schemas/validation-request.schema.json --target path/to/file.json
    python3 run.py --schema ../../schemas/validation-result.schema.json --target path/to/file.yaml

Exit code is 0 if the target passes (zero findings with status=fail),
1 if it fails, 2 on a usage/loading error.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from schema_engine import validate, SchemaError

RULES_PATH = Path(__file__).parent / "rules.json"

# Map the engine's error keyword to a SCH- rule id, per README's severity table.
_KEYWORD_TO_RULE = {
    "required": "SCH-001",
    "type": "SCH-002",
    "enum": "SCH-002",
    "const": "SCH-002",
    "pattern": "SCH-003",
    "format": "SCH-003",
    "minLength": "SCH-003",
    "minimum": "SCH-003",
    "minItems": "SCH-003",
    "uniqueItems": "SCH-003",
    "additionalProperties": "SCH-004",
    "oneOf": "SCH-005",
    "allOf": "SCH-005",
}


def _load_document(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    if path.suffix in (".yaml", ".yml"):
        import yaml  # local import: only needed for YAML targets
        return yaml.safe_load(text)
    return json.loads(text)


def _load_rules() -> dict[str, dict]:
    rules = json.loads(RULES_PATH.read_text(encoding="utf-8"))
    return {r["rule_id"]: r for r in rules}


def _finding_from_error(index: int, err: SchemaError, rules: dict[str, dict]) -> dict:
    rule_id = _KEYWORD_TO_RULE.get(err.keyword, "SCH-003")
    rule = rules[rule_id]
    finding_id = f"fnd-sch-{index:04d}"
    evidence_id = f"ev-sch-{index:04d}"
    message = f"[{err.keyword}] at {err.path}: {err.message}"
    integrity_hash = hashlib.sha256(message.encode("utf-8")).hexdigest()
    return {
        "finding_id": finding_id,
        "rule_id": rule_id,
        "domain": "schema",
        "severity": rule["severity"],
        "status": "fail",
        "message": message,
        "evidence_ids": [evidence_id],
        "_evidence": {
            "evidence_id": evidence_id,
            "finding_id": finding_id,
            "type": "log",
            "content_ref": f"inline://schema-engine/{finding_id}",
            "captured_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "integrity_hash": integrity_hash,
            "producer": {"name": "validators/schema", "version": "0.1.0"},
            "supersedes": None,
        },
    }


def run(schema_path: Path, target_path: Path) -> dict:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    instance = _load_document(target_path)
    rules = _load_rules()

    errors = validate(instance, schema)
    findings = [_finding_from_error(i, e, rules) for i, e in enumerate(errors, start=1)]
    evidence = [f.pop("_evidence") for f in findings]

    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        summary[f["severity"]] += 1

    status = "PASSED" if not findings else "FAILED"
    return {
        "target": str(target_path),
        "schema": str(schema_path),
        "status": status,
        "summary": summary,
        "findings": findings,
        "evidence": evidence,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Schema domain validator (SCH- rules).")
    parser.add_argument("--schema", required=True, type=Path, help="Path to a schema in /schemas")
    parser.add_argument("--target", required=True, type=Path, help="Path to the JSON/YAML document to validate")
    args = parser.parse_args()

    try:
        result = run(args.schema, args.target)
    except NotImplementedError as e:
        print(json.dumps({"error": "schema_engine_gap", "message": str(e)}, indent=2))
        return 2
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(json.dumps({"error": "load_error", "message": str(e)}, indent=2))
        return 2

    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "PASSED" else 1


if __name__ == "__main__":
    sys.exit(main())
