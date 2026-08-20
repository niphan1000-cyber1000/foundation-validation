import os
import sys
import unittest
from unittest import mock

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, BASE_DIR)

from run_all import _invoke_opa  # noqa: E402


class TestInvokeOpaErrorHandling(unittest.TestCase):
    """
    Regression coverage for a fail-safe gap: `opa eval` reports a Rego
    compile/parse error as a 0-exit-code JSON payload shaped
    {"errors": [...]}, not {"result": [...]}. Before this fix,
    _invoke_opa returned that payload as if it were a normal (empty)
    result, which parse_opa_output then read as "zero violations" — i.e.
    a broken/uncompilable policy file silently looked like a clean PASS
    instead of blocking the gate the way a missing OPA binary already
    correctly does.
    """

    def _run_with_fake_opa_output(self, stdout_json_text, returncode=0):
        with mock.patch("run_all._resolve_executable", return_value="opa"), \
             mock.patch("run_all.Path.exists", return_value=True), \
             mock.patch("run_all.subprocess.run") as mock_run:
            mock_run.return_value = mock.Mock(stdout=stdout_json_text, stderr="", returncode=returncode)
            return _invoke_opa("openapi.yaml", policy_dir="policies")

    def test_compile_error_payload_raises_runtime_error(self):
        error_json = (
            '{"errors": [{"message": "unexpected identifier token", '
            '"code": "rego_parse_error", '
            '"location": {"file": "policies/security.rego", "row": 67, "col": 13}}]}'
        )
        with self.assertRaises(RuntimeError) as ctx:
            self._run_with_fake_opa_output(error_json)
        self.assertIn("policies/security.rego:67", str(ctx.exception))
        self.assertIn("unexpected identifier token", str(ctx.exception))

    def test_clean_empty_result_does_not_raise(self):
        clean_json = '{"result": [{"expressions": [{"value": [], "text": "data.governance.api.deny"}]}]}'
        result = self._run_with_fake_opa_output(clean_json)
        self.assertEqual(result, {"result": [{"expressions": [{"value": [], "text": "data.governance.api.deny"}]}]})

    def test_clean_result_with_violations_does_not_raise(self):
        violation_json = (
            '{"result": [{"expressions": [{"value": '
            '[{"rule_id": "SEC-002-NON-HTTPS-SERVER", "severity": "HIGH", '
            '"message": "bad url", "path": "servers[1].url"}]}]}]}'
        )
        result = self._run_with_fake_opa_output(violation_json)
        self.assertIn("result", result)


if __name__ == '__main__':
    unittest.main()
