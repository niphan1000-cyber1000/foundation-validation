import json

def parse_spectral_output(spectral_json_data, target_path=""):
    """
    Parses Spectral JSON output and maps it into Unified Finding format.
    """
    findings = []
    
    if isinstance(spectral_json_data, str):
        try:
            results = json.loads(spectral_json_data)
        except json.JSONDecodeError:
            return findings
    elif isinstance(spectral_json_data, list):
        results = spectral_json_data
    else:
        return findings

    if not isinstance(results, list):
        return findings

    _KNOWN_PREFIXES = ("SCH-", "OAS-", "POL-", "SEC-", "GOV-", "TRC-")

    for item in results:
        severity_code = item.get("severity", 1)
        # Spectral severity: 0=Error, 1=Warning, 2=Info, 3=Hint
        severity_map = {0: "CRITICAL", 1: "HIGH", 2: "MEDIUM", 3: "LOW"}
        severity = severity_map.get(severity_code, "MEDIUM")

        path_list = item.get("path", [])
        path_str = ".".join(str(p) for p in path_list) if path_list else "root"

        code = item.get("code", "GENERIC")
        # Custom rules (defined in .spectral.yaml, catalogued in
        # rules/registry.yaml) are already named like "OAS-002-...".
        # Built-in Spectral rules (e.g. "oas3-schema") are not, and need
        # the "OAS-" prefix added so every openapi-domain rule_id is
        # consistently namespaced. Prepending unconditionally used to
        # double the prefix on custom rules ("OAS-OAS-002-..."), which
        # made them invisible to the registry lookup in run_all.py.
        rule_id = code if code.startswith(_KNOWN_PREFIXES) else f"OAS-{code}"

        finding = {
            "rule_id": rule_id,
            "severity": severity,
            "category": "openapi",
            "message": item.get("message", "Spectral validation error"),
            "location": {
                "file": target_path,
                "path": path_str,
                "line": item.get("range", {}).get("start", {}).get("line", 0)
            }
        }
        findings.append(finding)

    return findings
