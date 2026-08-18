import sys
import yaml
from pathlib import Path
from typing import List
from src.core.models import ValidatorResult, ValidationState, GateAction
from src.core.engine import GateDecisionEngine

def run_gate_check(policy_path: str = "gate_policy.yaml") -> int:
    print(f"[*] Loading policy from {policy_path}...")
    try:
        with open(policy_path, "r", encoding="utf-8") as f:
            policy_data = yaml.safe_load(f)
    except Exception as e:
        print(f"[!] ERROR: Failed to load policy file: {e}")
        return 1

    engine = GateDecisionEngine(policy_data)

    # จำลองตัวอย่างผลลัพธ์จาก Validator (ในระบบจริงจะรับค่าจาก aggregator)
    # ทดสอบกรณีปกติ (หรือจำลองสถานการณ์)
    results = [
        ValidatorResult(validator_name="spectral", state=ValidationState.PASS),
        ValidatorResult(validator_name="opa", state=ValidationState.PASS)
    ]

    decision = engine.evaluate(run_id="run-cli-001", results=results)
    
    print(f"[*] Run ID: {decision.run_id}")
    print(f"[*] Gate Action Result: {decision.action.value}")
    for reason in decision.reasons:
        print(f"    - {reason}")

    # CI Hard Gate Enforcement: ถ้าเป็น BLOCK สั่ง Exit Code 1 (Fail CI)
    if decision.action == GateAction.BLOCK:
        print("[!] CI HARD GATE FAILED: Action is BLOCK.")
        return 1
    
    print("[+] CI HARD GATE PASSED.")
    return 0

if __name__ == "__main__":
    sys.exit(run_gate_check())