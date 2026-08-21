import subprocess
import sys

def test_run_all_success_or_block():
    # ทดสอบรัน run_all.py แบบปกติ (Positive Control)
    result = subprocess.run([sys.executable, "run_all.py"], capture_output=True, text=True)
    # ตรวจสอบว่า script รันจบกระบวนการ (ไม่ crash แบบพังทางเทคนิค)
    assert result.returncode in [0, 1], f"Unexpected crash: {result.stderr}"

def test_failure_injection_flag():
    # ทดสอบรันด้วย Failure Injection Flag (Negative Control)
    result = subprocess.run([sys.executable, "run_all.py", "--test-failure-injection"], capture_output=True, text=True)
    # ต้องคืนค่า Exit Code ไม่ใช่ 0 (เพื่อจำลองการบลอกของ Gate)
    assert result.returncode != 0, "Failure injection test failed to trigger a block/error exit code!"

def test_failure_injection_actually_routes_through_gate_decision_engine():
    """
    Process-boundary integration test (the piece flagged as missing in
    review): proves --test-failure-injection doesn't just call
    sys.exit(1) directly, but genuinely constructs an ERROR-state
    ValidatorResult, sends it through the real GateDecisionEngine, and
    the engine's own BLOCK decision is what drives the process exit code.

    A bare `sys.exit(1)` in run_all.py would satisfy
    test_failure_injection_flag above (non-zero exit) without ever
    touching src/core/engine.py — this test reads run_all.py's own
    stdout to confirm the engine's decision output ("Gate Action Result:
    BLOCK") is actually present, and expects exit code 1 specifically
    (not the exit code 2 reserved for "the engine itself is broken").
    """
    result = subprocess.run(
        [sys.executable, "run_all.py", "--test-failure-injection"],
        capture_output=True, text=True,
    )
    assert result.returncode == 1, (
        f"Expected exit code 1 (GateDecisionEngine correctly forced BLOCK), "
        f"got {result.returncode}. stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    assert "Gate Action Result: BLOCK" in result.stdout, (
        "run_all.py --test-failure-injection did not print a "
        "GateDecisionEngine decision — it may be bypassing the engine "
        f"entirely again. stdout={result.stdout!r}"
    )
    assert "injected-validator" in result.stdout
    assert "ERROR" in result.stdout
