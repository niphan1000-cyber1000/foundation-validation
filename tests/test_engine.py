import pytest
import yaml
import json
from src.core.models import ValidatorResult, ValidationState, GateAction
from src.core.engine import GateDecisionEngine
from src.core.normalizer import ControlledNormalizer
from src.core.evidence import EvidenceCollector

def test_engine_all_pass():
    policy = {
        "rules": {
            "spectral": {"on_fail": "BLOCK", "on_error": "BLOCK"},
            "opa": {"on_fail": "BLOCK", "on_error": "BLOCK"}
        }
    }
    engine = GateDecisionEngine(policy)
    results = [
        ValidatorResult(validator_name="spectral", state=ValidationState.PASS),
        ValidatorResult(validator_name="opa", state=ValidationState.PASS)
    ]
    
    decision = engine.evaluate("run-001", results)
    assert decision.action == GateAction.ALLOW
    assert decision.run_id == "run-001"

def test_engine_fail_results_in_block():
    policy = {
        "rules": {
            "spectral": {"on_fail": "BLOCK", "on_error": "BLOCK"}
        }
    }
    engine = GateDecisionEngine(policy)
    results = [
        ValidatorResult(validator_name="spectral", state=ValidationState.FAIL, findings_count=2)
    ]
    
    decision = engine.evaluate("run-002", results)
    assert decision.action == GateAction.BLOCK

def test_engine_error_triggers_failsafe_block():
    """INVARIANT: ERROR must ALWAYS result in BLOCK (Fail-Safe)"""
    policy = {
        "rules": {
            "opa": {"on_fail": "WARN", "on_error": "BLOCK"}
        }
    }
    engine = GateDecisionEngine(policy)
    results = [
        ValidatorResult(validator_name="opa", state=ValidationState.ERROR, error_message="binary missing")
    ]
    
    decision = engine.evaluate("run-003", results)
    assert decision.action == GateAction.BLOCK
    assert any("ERROR" in reason for reason in decision.reasons)

def test_engine_error_with_on_error_warn_still_forces_block():
    """
    INVARIANT (regression): ERROR must force BLOCK even when the
    validator's own policy entry explicitly sets on_error: WARN.

    test_engine_error_triggers_failsafe_block above only ever exercises
    on_error: BLOCK, so it can't distinguish "the engine correctly forces
    BLOCK on ERROR" from "the engine just happened to read on_error and
    it was BLOCK anyway". This test sets on_error: WARN specifically to
    prove GateDecisionEngine's fail-safe branch ignores policy for ERROR
    states rather than honoring a (dangerously permissive) WARN override.
    """
    policy = {
        "rules": {
            "injected-validator": {"on_fail": "BLOCK", "on_error": "WARN"}
        }
    }
    engine = GateDecisionEngine(policy)
    results = [
        ValidatorResult(
            validator_name="injected-validator",
            state=ValidationState.ERROR,
            error_message="Simulated failure injection (CI negative control)",
        )
    ]

    decision = engine.evaluate("run-failsafe-warn-override", results)
    assert decision.action == GateAction.BLOCK, (
        "on_error: WARN leaked through — an ERROR state must ALWAYS force "
        "BLOCK regardless of policy configuration"
    )

def test_engine_with_yaml_policy():
    with open("gate_policy.yaml", "r", encoding="utf-8") as f:
        policy_data = yaml.safe_load(f)
        
    engine = GateDecisionEngine(policy_data)
    results = [
        ValidatorResult(validator_name="trivy", state=ValidationState.FAIL, findings_count=1)
    ]
    
    decision = engine.evaluate("run-yaml-01", results)
    assert decision.action == GateAction.WARN

def test_failure_injection_process_boundary():
    """P0-6: Test failure injection at process boundary (e.g. validator crashes or times out)"""
    policy = {
        "rules": {
            "fragile_validator": {"on_fail": "WARN", "on_error": "BLOCK"}
        }
    }
    engine = GateDecisionEngine(policy)
    results = [
        ValidatorResult(
            validator_name="fragile_validator",
            state=ValidationState.ERROR,
            error_message="Process crashed with exit code 137 (OOM Killed)"
        )
    ]
    
    decision = engine.evaluate("run-inject-01", results)
    assert decision.action == GateAction.BLOCK
    assert any("CRASHED" in reason.upper() or "ERROR" in reason.upper() for reason in decision.reasons)

def test_controlled_normalization_preserves_refs():
    """P0-7: Test that normalization keeps $ref intact without flatten-all"""
    normalizer = ControlledNormalizer()
    input_schema = {
        "type": "object",
        "properties": {
            "user": {
                "$ref": "#/definitions/User"
            }
        }
    }
    
    result = normalizer.normalize_refs(input_schema)
    assert "properties" in result
    assert result["properties"]["user"]["$ref"] == "#/definitions/User"

def test_evidence_chain_with_run_id():
    """P0-8: Test evidence chain collection tied to a run_id"""
    run_id = "test-run-evidence-001"
    collector = EvidenceCollector(run_id=run_id)
    
    collector.add_evidence("validator_spectral", {"status": "PASS", "findings": 0})
    collector.add_evidence("gate_engine", {"action": "ALLOW"})
    
    saved_path = collector.save_chain()
    assert saved_path.exists()
    
    with open(saved_path, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    assert len(data) == 2
    assert data[0]["run_id"] == run_id
    assert data[0]["step"] == "validator_spectral"
    assert data[1]["payload"]["action"] == "ALLOW"
    
    saved_path.unlink()
from src.core.sarif import SarifGenerator

def test_sarif_generation():
    """P0-9: Test SARIF report generation from failed results"""
    generator = SarifGenerator()
    results = [
        ValidatorResult(validator_name="spectral", state=ValidationState.FAIL, findings_count=3)
    ]
    
    report = generator.generate_report(results)
    assert report["version"] == "2.1.0"
    assert len(report["runs"][0]["results"]) == 1
    assert report["runs"][0]["results"][0]["ruleId"] == "spectral"
    
    # ทดสอบการเซฟไฟล์จริง
    saved_path = generator.save_report(results, "test_sarif.json")
    assert saved_path.exists()
    saved_path.unlink()
from src.core.ownership import RuleOwnershipManager

def test_rule_ownership_separation():
    """P0-10: Test rule ownership separation between Spectral and OPA"""
    manager = RuleOwnershipManager()
    
    # ตรวจสอบเจ้าของกฎ
    assert manager.get_owner("openapi-structure") == "spectral"
    assert manager.get_owner("security-compliance") == "opa"
    
    # ตรวจสอบการตรวจสอบสิทธิ์การรันกฎ (Ownership Validation)
    assert manager.validate_ownership("spectral", "openapi-structure") is True
    assert manager.validate_ownership("opa", "openapi-structure") is False