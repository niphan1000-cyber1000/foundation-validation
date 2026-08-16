import subprocess
import sys
import os
import pytest

def run_cli(spec_path=None, output_path=None):
    cmd = [sys.executable, os.path.abspath("validators/run_all.py")]
    if spec_path:
        cmd.extend(["--spec", os.path.abspath(spec_path)])
    if output_path:
        cmd.extend(["--output", os.path.abspath(output_path)])
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr

def test_process_success_good_example():
    """Test that a valid spec exits with 0 (PASSED)."""
    code, stdout, stderr = run_cli(
        spec_path="openapi-good-example.json",
        output_path="test_good_out.json"
    )
    assert code == 0, f"Expected exit code 0, got {code}. Stderr: {stderr}"
    if os.path.exists("test_good_out.json"):
        os.remove("test_good_out.json")

def test_process_failure_bad_example():
    """Test that a non-compliant spec triggers gate block and exits with 1."""
    code, stdout, stderr = run_cli(
        spec_path="openapi-bad-example.json",
        output_path="test_bad_out.json"
    )
    assert code == 1, f"Expected exit code 1 (blocked), got {code}. Stderr: {stderr}"
    if os.path.exists("test_bad_out.json"):
        os.remove("test_bad_out.json")

def test_process_error_missing_file():
    """Test that providing a non-existent spec file exits gracefully with 2 (ERROR)."""
    code, stdout, stderr = run_cli(
        spec_path="non-existent-file.json",
        output_path="test_error_out.json"
    )
    assert code == 2, f"Expected exit code 2 (system error), got {code}."
    if os.path.exists("test_error_out.json"):
        os.remove("test_error_out.json")