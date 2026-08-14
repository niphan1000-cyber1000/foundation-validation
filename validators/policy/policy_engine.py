import json

def parse_opa_output(opa_data, target_path=""):
    """
    Parses OPA evaluation output/dict and maps violations into Unified Finding format.
    """
    findings = []
    
    if isinstance(opa_data, str):
        try:
            results = json.loads(opa_data)
        except json.JSONDecodeError:
            return findings
    elif isinstance(opa_data, (dict, list)):
        results = opa_data
    else:
        return findings

    # Normalize OPA result wrapper: {"result": [...]} or raw list
    eval_items = []
    if isinstance(results, dict):
        eval_items = results.get("result", [results])
    elif isinstance(results, list):
        eval_items = results

    for item in eval_items:
        if not isinstance(item, dict):
            continue

        violations = item.get("deny", []) or item.get("violations", [])
        for v in violations:
            msg = v if isinstance(v, str) else v.get("message", "Policy violation detected")
            rule_code = v.get("code", "001") if isinstance(v, dict) else "001"
            severity = v.get("severity", "HIGH") if isinstance(v, dict) else "HIGH"

            finding = {
                "rule_id": f"POL-{rule_code}",
                "severity": severity,
                "category": "policy",
                "message": msg,
                "location": {
                    "file": target_path,
                    "path": v.get("path", "policy.deny") if isinstance(v, dict) else "policy.deny",
                    "line": 0
                }
            }
            findings.append(finding)

    return findings
