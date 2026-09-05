def test_resolve_finding_unknown_rule_uses_severity_based_fallback():
    """An unregistered rule_id must never be silently ignored, but it also
    must not be blanket-escalated to CRITICAL/FAIL regardless of what the
    tool itself reported — that makes an unregistered LOW finding
    indistinguishable from a registered CRITICAL one, which defeats the
    point of severity. The fail-safe default is severity-based (see
    _DEFAULT_GATE_BEHAVIOR_BY_SEVERITY): a reported LOW finding stays LOW
    and gets the LOW-tier gate_behavior (INFO), not an escalated BLOCK."""
    from validators.run_all import _resolve_finding

    raw_finding = {
        "rule_id": "SEC-999-UNKNOWN",
        "message": "Some custom violation",
        "severity": "LOW"
    }
    registry = {}
    environment = "production"

    resolved = _resolve_finding(raw_finding, registry, environment)

    assert resolved["severity"] == "LOW"
    assert resolved["gate_behavior"] == "INFO"
    assert resolved["effective_gate_behavior"] == "INFO"
    assert resolved["rule_version"] == "unknown"


def test_resolve_finding_unknown_rule_critical_still_blocks():
    """The other side of the same fallback: an unregistered rule that the
    tool itself reported as CRITICAL must still BLOCK. Severity-based
    fallback must not become a way to quietly downgrade real critical
    findings just because they aren't catalogued yet."""
    from validators.run_all import _resolve_finding

    raw_finding = {
        "rule_id": "SEC-998-UNKNOWN",
        "message": "Some other custom violation",
        "severity": "CRITICAL"
    }
    resolved = _resolve_finding(raw_finding, {}, "production")

    assert resolved["severity"] == "CRITICAL"
    assert resolved["gate_behavior"] == "FAIL"
    assert resolved["effective_gate_behavior"] == "FAIL"
    assert resolved["rule_version"] == "unknown"


def test_resolve_finding_unknown_rule_missing_severity_defaults_medium():
    """A finding with no severity field at all (malformed tool output)
    falls back to MEDIUM/WARN rather than crashing or silently becoming
    CRITICAL."""
    from validators.run_all import _resolve_finding

    raw_finding = {"rule_id": "OAS-UNKNOWN-CODE", "message": "no severity field"}
    resolved = _resolve_finding(raw_finding, {}, "production")

    assert resolved["severity"] == "MEDIUM"
    assert resolved["gate_behavior"] == "WARN"
    assert resolved["effective_gate_behavior"] == "WARN"

