"""
P0-3: Failure injection / process-boundary tests for the real gate.

These invoke validators/run_all.py exactly the way CI and the pre-commit
hook do (as a subprocess, exercising the real CLI argument parsing and
exit-code contract) rather than testing the removed root-level stub.

Exit code contract (see validators/run_all.py main()):
    0 -> PASSED
    1 -> FAILED (blocking findings)
    2 -> ERROR / hard error (missing spec file, tool couldn't be invoked)

Some of these tests (good/bad spec) require Spectral (via npx) and OPA to
be reachable, which is true in CI but may not be true in a fully offline
sandbox. Those are marked and will skip cleanly rather than fail noisily
if the tools aren't on PATH, so this file behaves correctly both locally
and in CI.
"""
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
RUN_ALL = REPO_ROOT / "validators" / "run_all.py"

TOOLS_AVAILABLE = shutil.which("npx") is not None and shutil.which("opa") is not None


def _run(*args):
    return subprocess.run(
        [sys.executable, str(RUN_ALL), *args],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
        timeout=180,
    )


def test_missing_spec_file_is_a_hard_error():
    """Negative control: a spec path that doesn't exist must hard-error
    (exit 2), never silently PASS. Doesn't require npx/opa - main()
    checks file existence before invoking any tool."""
    result = _run("--spec", "nonexistent_spec_that_does_not_exist.json")
    assert result.returncode == 2, (
        f"Expected exit 2 for a missing spec file, got {result.returncode}. "
        f"stderr: {result.stderr}"
    )
    assert "not found" in result.stderr.lower()


@pytest.mark.skipif(not TOOLS_AVAILABLE, reason="requires npx (Spectral) and opa on PATH")
def test_known_bad_spec_blocks_the_gate():
    """Positive-for-blocking control: openapi-bad-example.json violates
    SEC-001-https-only (http:// server URL) and OAS-002-error-responses
    (no 4xx/5xx responses defined). The gate must FAIL (exit 1), not
    silently pass."""
    result = _run("--spec", "openapi-bad-example.json")
    assert result.returncode == 1, (
        f"Expected exit 1 (FAILED) for a known-bad spec, got "
        f"{result.returncode}. This means the gate is not actually "
        f"blocking anything. stdout: {result.stdout[:2000]}"
    )
    assert '"status": "FAILED"' in result.stdout


@pytest.mark.skipif(not TOOLS_AVAILABLE, reason="requires npx (Spectral) and opa on PATH")
def test_known_good_spec_passes_the_gate():
    """Positive control: a spec written to satisfy every custom rule
    should PASS (exit 0)."""
    result = _run("--spec", "openapi-good-example.json")
    assert result.returncode == 0, (
        f"Expected exit 0 (PASSED) for the known-good spec, got "
        f"{result.returncode}. stdout: {result.stdout[:2000]}"
    )
    assert '"status": "PASSED"' in result.stdout
