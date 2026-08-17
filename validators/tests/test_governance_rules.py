import sys
import os

# บังคับให้เพิ่ม path ไปยัง root directory ของปรเจกต
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from run_all import evaluate_gate_decision

def test_evaluate_gate_decision_pass():
    findings = [{"rule": "test", "severity": "info", "message": "all good"}]
    policy = {"block_on": ["error", "warning"]}
    result = evaluate_gate_decision(findings, policy)
    assert result["passed"] is True
    assert result["status"] == "PASS"

def test_evaluate_gate_decision_block():
    findings = [{"rule": "test", "severity": "error", "message": "violation found"}]
    policy = {"block_on": ["error", "warning"]}
    result = evaluate_gate_decision(findings, policy)
    assert result["passed"] is False
    assert result["status"] == "BLOCK"
