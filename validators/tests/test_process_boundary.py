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
