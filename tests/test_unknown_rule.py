def test_resolve_finding_unknown_rule_blocks_by_default():
    from validators.run_all import _resolve_finding
    
    raw_finding = {
        "rule_id": "SEC-999-UNKNOWN",
        "message": "Some custom violation",
        "severity": "LOW"
    }
    registry = {}
    environment = "production"
    
    resolved = _resolve_finding(raw_finding, registry, environment)
    
    assert resolved["severity"] == "CRITICAL"
    assert resolved["gate_behavior"] == "FAIL"
    assert resolved["effective_gate_behavior"] == "FAIL"
    assert resolved["rule_version"] == "unknown"

