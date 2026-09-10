import json


class PolicyOutputError(ValueError):
    """Raised when opa_data is shaped like an `opa eval` compile/parse
    error payload ({"errors": [...]}) rather than a real result set.

    ADVERSARIAL REVIEW FINDING (fixed): `_invoke_opa` in run_all.py
    already checks for this shape and raises before parse_opa_output ever
    sees it -- but only for the one call path that goes through
    `_invoke_opa` itself. Any other caller that already has raw `opa
    eval` JSON (e.g. run_all_validations(opa_json_data=...), used by this
    engine's own tests and any future caching/injection layer) reached
    parse_opa_output directly, which had no such check: the `elif
    isinstance(results, dict):` fallback branch below silently read
    `results.get("deny", []) or results.get("violations", [])` on a
    payload that has neither key, producing an empty violations list --
    i.e. a broken/uncompilable Rego policy was silently reported as
    "zero violations found" (a PASS) at this layer, regardless of what
    _invoke_opa's own guard does elsewhere. The check now lives in the
    parsing function itself, not just one caller of it, so it can't be
    bypassed by a different call path.
    """


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

    Raises PolicyOutputError (not a silent []) if opa_data is a
    {"errors": [...]} payload -- `opa eval`'s shape for a policy that
    failed to compile/evaluate. See PolicyOutputError's docstring.
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

    if isinstance(results, dict) and results.get("errors"):
        first_err = results["errors"][0] if results["errors"] else {}
        loc = first_err.get("location", {}) if isinstance(first_err, dict) else {}
        where = f"{loc.get('file', target_path or 'policy')}:{loc.get('row', '?')}" if loc else (target_path or "policy")
        message = first_err.get("message", "unknown error") if isinstance(first_err, dict) else str(first_err)
        raise PolicyOutputError(f"OPA policy failed to compile/evaluate at {where}: {message}")

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
            # FIX: A bare string violation has no rule_id at all. The old
            # hardcoded "POL-001" used a real taxonomy prefix (POL) but was
            # never registered in rules/registry.yaml, so it looked like a
            # catalogued rule in the evidence trail when it was actually
            # just "we got a plain string with no structured rule_id".
            # Use an explicit, unmistakable error marker instead.
            msg, rule_id, severity, path = v, "UNRESOLVED-RULE-ID:bare-string-violation-no-rule_id", "HIGH", "policy.deny"
        elif isinstance(v, dict):
            msg = v.get("message", "Policy violation detected")
            # Rego violation objects (see policies/*.rego) set "rule_id"
            # directly, e.g. "SEC-002-NON-HTTPS-SERVER". Older payloads may
            # use a "code" field instead of "rule_id" entirely.
            #
            # FIX: previously this fell back to f"POL-{code}" (e.g.
            # "POL-001"), which fabricates a plausible-looking, real-prefix
            # rule_id that is NOT in rules/registry.yaml. That silently
            # disguises "this payload never had a real rule_id" as if it
            # were a specific, catalogued policy rule. Use an explicit
            # error marker instead, preserving the raw code (if any) for
            # debugging without pretending it's a registered rule.
            raw_rule_id = v.get("rule_id")
            if raw_rule_id:
                rule_id = raw_rule_id
            else:
                code = v.get("code")
                rule_id = (
                    f"UNRESOLVED-RULE-ID:missing-rule_id(code={code})"
                    if code is not None
                    else "UNRESOLVED-RULE-ID:missing-rule_id"
                )
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
