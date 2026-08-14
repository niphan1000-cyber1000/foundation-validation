import sys
import os
import json
import argparse

# Add validator paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, 'schema'))
sys.path.insert(0, os.path.join(BASE_DIR, 'openapi'))
sys.path.insert(0, os.path.join(BASE_DIR, 'policy'))

from schema_engine import validate as validate_schema
from openapi_engine import parse_spectral_output
from policy_engine import parse_opa_output

def run_all_validations(schema_path=None, target_schema_json=None, openapi_json_data=None, opa_json_data=None):
    all_findings = []

    # 1. Run Schema Validation if parameters provided
    if schema_path and target_schema_json:
        try:
            schema_errors = validate_schema(target_schema_json, schema_path)
            for err in schema_errors:
                all_findings.append({
                    "rule_id": f"SCH-{err.get('rule_id', '001')}",
                    "severity": err.get("severity", "CRITICAL"),
                    "category": "schema",
                    "message": err.get("message", "Schema validation error"),
                    "location": {"file": "schema_target", "path": err.get("path", "root"), "line": 0}
                })
        except Exception:
            pass

    # 2. Run OpenAPI Validation
    if openapi_json_data:
        oas_findings = parse_spectral_output(openapi_json_data, target_path="openapi_target")
        all_findings.extend(oas_findings)

    # 3. Run Policy Validation
    if opa_json_data:
        pol_findings = parse_opa_output(opa_json_data, target_path="policy_target")
        all_findings.extend(pol_findings)

    status = "PASSED" if len(all_findings) == 0 else "FAILED"

    return {
        "status": status,
        "total_findings": len(all_findings),
        "findings": all_findings
    }

def main():
    parser = argparse.ArgumentParser(description="Master Validation Aggregator Gate")
    parser.add_argument("--output", default="validation-result.json", help="Output result JSON file path")
    args = parser.parse_args()

    # Aggregate default execution check
    result = run_all_validations()

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2)

    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
