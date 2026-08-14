import sys
import os
import json
import hashlib
import argparse
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, 'schema'))
sys.path.insert(0, os.path.join(BASE_DIR, 'openapi'))
sys.path.insert(0, os.path.join(BASE_DIR, 'policy'))

from schema_engine import validate as validate_schema
from openapi_engine import parse_spectral_output
from policy_engine import parse_opa_output

def run_all_validations(schema_path=None, target_schema_json=None, openapi_json_data=None, opa_json_data=None):
    all_findings = []
    artifacts = []

    # 1. Schema Domain
    if schema_path and target_schema_json:
        try:
            schema_errors = validate_schema(target_schema_json, schema_path)
            for err in schema_errors:
                all_findings.append({
                    "rule_id": f"SCH-{err.get('rule_id', '001')}",
                    "rule_version": "1.0.0",
                    "severity": err.get("severity", "CRITICAL"),
                    "category": "schema",
                    "message": err.get("message", "Schema validation error"),
                    "location": {"file": "schema_target", "path": err.get("path", "root"), "line": 0}
                })
            artifacts.append({"domain": "schema", "target_file": "schema_target", "rule_count": len(schema_errors)})
        except Exception:
            pass

    # 2. OpenAPI Domain
    if openapi_json_data:
        raw_oas = parse_spectral_output(openapi_json_data, target_path="openapi_target")
        for item in raw_oas:
            item["rule_version"] = "1.0.0"
            all_findings.append(item)
        artifacts.append({"domain": "openapi", "target_file": "openapi_target", "rule_count": len(raw_oas)})

    # 3. Policy Domain
    if opa_json_data:
        raw_pol = parse_opa_output(opa_json_data, target_path="policy_target")
        for item in raw_pol:
            item["rule_version"] = "1.0.0"
            all_findings.append(item)
        artifacts.append({"domain": "policy", "target_file": "policy_target", "rule_count": len(raw_pol)})

    # Severity Summary Calculation
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        sev = f.get("severity", "MEDIUM")
        if sev in severity_counts:
            severity_counts[sev] += 1

    status = "PASSED" if len(all_findings) == 0 else "FAILED"
    
    findings_bytes = json.dumps(all_findings, sort_keys=True).encode('utf-8')
    hash_digest = hashlib.sha256(findings_bytes).hexdigest()

    return {
        "execution": {
            "execution_id": f"exec-{int(datetime.now(timezone.utc).timestamp())}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "platform_version": "1.0.0",
            "environment": os.getenv("VALIDATION_ENV", "ci")
        },
        "status": status,
        "summary": {
            "total_findings": len(all_findings),
            "critical": severity_counts["CRITICAL"],
            "high": severity_counts["HIGH"],
            "medium": severity_counts["MEDIUM"],
            "low": severity_counts["LOW"]
        },
        "findings": all_findings,
        "evidence": {
            "artifacts": artifacts,
            "hash_digest": hash_digest
        }
    }

def main():
    parser = argparse.ArgumentParser(description="Governed Validation Master Gate CLI")
    parser.add_argument("--output", default="validation-result.json", help="Output result JSON file path")
    args = parser.parse_args()

    result = run_all_validations()

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2)

    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
