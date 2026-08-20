import json


def parse_opa_output(opa_data, target_path=""):
    """
    Parses `opa eval --format json <query>` output and maps every
    violation object in the query's result set into the Unified Finding
    format.

    IMPORTANT: `opa eval --format json` wraps the query result as:
        {"result": [{"expressions": [{"value": <query_value>, ...}], ...}]}
    For a query like `data.governance.api.deny`, <query_value> is the
    deny set itself: a JSON array of violation objects (each produced by
    a `msg := {...}` in the .rego policy). It is NOT `{"deny": [...]}` —
    a previous version of this function looked for that shape directly
    and silently found zero violations on every real `opa eval` run,
    regardless of what the policy actually detected.
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

    violations = []

    if isinstance(results, dict) and "result" in results:
        # Real `opa eval --format json` shape.
        for item in results.get("result", []) or []:
            if not isinstance(item, dict):
                continue
            for expr in item.get("expressions", []) or []:
                if not isinstance(expr, dict):
                    continue
                value = expr.get("value")
                if isinstance(value, list):
                    violations.extend(value)
                elif isinstance(value, dict):
                    # A rule that yields a single object rather than a set.
                    violations.append(value)
    elif isinstance(results, list):
        # Already-unwrapped list of violation objects.
        violations = results
    elif isinstance(results, dict):
        # Fallback for a bare {"deny": [...]} / {"violations": [...]}
        # payload (e.g. a hand-built dict passed directly, not real
        # `opa eval` output).
        violations = results.get("deny", []) or results.get("violations", [])

    for v in violations:
        if isinstance(v, str):
            msg, rule_id, severity, path = v, "POL-001", "HIGH", "policy.deny"
        elif isinstance(v, dict):
            msg = v.get("message", "Policy violation detected")
            # Rego violation objects (see policies/*.rego) set "rule_id"
            # directly, e.g. "SEC-002-NON-HTTPS-SERVER". Fall back to the
            # POL-{code} convention only for payloads that use the older
            # "code" field instead.
            rule_id = v.get("rule_id") or f"POL-{v.get('code', '001')}"
            severity = v.get("severity", "HIGH")
            path = v.get("path", "policy.deny")
        else:
            continue

        findings.append({
            "rule_id": rule_id,
            "severity": severity,
            "category": "policy",
            "message": msg,
            "location": {
                "file": target_path,
                "path": path,
                "line": 0
            }
        })

    return findings
