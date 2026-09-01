import json

class SpectralOutputError(ValueError):
    """Raised when Spectral's JSON output isn't shaped as expected.

    Deliberately a hard failure, not a silent []: a Spectral CLI that
    ran successfully (non-empty stdout, exit handled upstream) but
    produced output in an unexpected shape (wrapped under a key,
    version-format change, etc.) must not be silently treated as "zero
    findings" -- that would make the entire OpenAPI/Spectral domain a
    silent no-op pass, indistinguishable from a genuinely clean spec.
    """


def parse_spectral_output(spectral_json_data, target_path=""):
    """
    Parses Spectral JSON output and maps it into Unified Finding format.

    Raises SpectralOutputError (not a silent []) if spectral_json_data
    isn't shaped as Spectral's `-f json` reporter actually produces: a
    bare JSON array of finding objects. An empty array ([]) is a valid,
    legitimate "zero findings" result and is NOT an error.
    """
    if isinstance(spectral_json_data, str):
        try:
            results = json.loads(spectral_json_data)
        except json.JSONDecodeError as e:
            raise SpectralOutputError(
                f"Spectral output was not valid JSON: {e}"
            ) from e
    else:
        results = spectral_json_data

    if not isinstance(results, list):
        raise SpectralOutputError(
            "Spectral output was not a JSON array as expected "
            f"(got {type(results).__name__}: {str(results)[:200]!r}). "
            "Treating this as zero findings would silently disable the "
            "entire OpenAPI/Spectral validation domain."
        )

    findings = []
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
