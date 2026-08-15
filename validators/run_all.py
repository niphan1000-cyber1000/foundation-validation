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

def normalize_finding(item, default_prefix="SEC"):
    rule_id = str(item.get("rule_id", "001"))
    if not rule_id.startswith(("SCH-", "OAS-", "POL-", "SEC-")):
        # Strip any existing prefix if present but non-standard
        clean_code = rule_id.split("-")[-1] if "-" in rule_id else rule_id
        rule_id = f"{default_prefix}-{clean_code}"

    sev = str(item.get("severity", "MEDIUM")).upper()
    if sev not in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        sev = "MEDIUM"

    cat = str(item.get("category", "schema")).lower()
    if cat not in ["schema", "openapi", "policy", "security"]:
        cat = "schema"

    loc = item.get("location", {})
    if not isinstance(loc, dict):
        loc = {"file": "unknown", "path": "root", "line": 0}

    return {
        "rule_id": rule_id,
        "rule_version": str(item.get("rule_version", "1.0.0")),
        "severity": sev,
        "category": cat,
        "message": str(item.get("message", "Validation finding detected")),
        "location": {
            "file": str(loc.get("file", "unknown")),
            "path": str(loc.get("path", "root")),
            "line": int(loc.get("line", 0)) if isinstance(loc.get("line"), int) else 0
        }
    }

def run_all_validations(schema_path=None, target_schema_json=None, openapi_json_data=None, opa_json_data=None):
    all_findings = []
    artifacts = []

    # 1. Schema Domain
    if schema_path and target_schema_json:
        try:
            schema_errors = validate_schema(target_schema_json, schema_path)
            for err in schema_errors:
                f = normalize_finding({
                    "rule_id": err.get("rule_id", "001"),
                    "severity": err.get("severity", "CRITICAL"),
                    "category": "schema",
                    "message": err.get("message", "Schema error"),
                    "location": {"file": "schema_target", "path": err.get("path", "root"), "line": 0}
                }, default_prefix="SCH")
                all_findings.append(f)
            artifacts.append({"domain": "schema", "target_file": "schema_target", "rule_count": len(schema_errors)})
        except Exception:
            pass

    # 2. OpenAPI Domain
    if openapi_json_data:
        raw_oas = parse_spectral_output(openapi_json_data, target_path="openapi_target")
        for item in raw_oas:
            all_findings.append(normalize_finding(item, default_prefix="OAS"))
        artifacts.append({"domain": "openapi", "target_file": "openapi_target", "rule_count": len(raw_oas)})

    # 3. Policy Domain
    if opa_json_data:
        raw_pol = parse_opa_output(opa_json_data, target_path="policy_target")
        for item in raw_pol:
            all_findings.append(normalize_finding(item, default_prefix="POL"))
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
    parser.add_argument("--spec", default=None, help="Path to OpenAPI spec JSON file")
    parser.add_argument("--sarif", default=None, help="Path to write SARIF output")
    parser.add_argument("--output", default="validation-result.json", help="Output result JSON file path")
    args = parser.parse_args()

    openapi_data = None
    if args.spec:
        with open(args.spec, 'r', encoding='utf-8-sig') as f:
            openapi_data = json.load(f)

    result = run_all_validations(openapi_json_data=openapi_data)

    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2)

    print(json.dumps(result, indent=2))

    if args.sarif:
        sarif = {
            'version': '2.1.0',
            'runs': [{
                'tool': {'driver': {'name': 'GovernedValidation', 'rules': []}},
                'results': [
                    {
                        'ruleId': f.get('rule_id', 'unknown'),
                        'level': 'error' if f.get('severity') in ('CRITICAL', 'HIGH') else 'warning',
                        'message': {'text': f.get('message', '')},
                        'locations': [{'physicalLocation': {'artifactLocation': {'uri': f.get('location', {}).get('file', 'unknown')}}}]
                    } for f in result.get('findings', [])
                ]
            }]
        }
        with open(args.sarif, 'w', encoding='utf-8') as f:
            json.dump(sarif, f, indent=2)
        print(f'SARIF written to {args.sarif}')

if __name__ == "__main__":
    main()
