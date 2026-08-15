import json
import os
import subprocess
from datetime import datetime, timezone

class OPAValidator:
    """
    Standardized Governance Policy Validator wrapping OPA Engine.
    Enforces Contract Standard: Returns tuple (findings_list, system_error)
    """

    def __init__(self, spec_path, policy_dir="policies/"):
        self.spec_path = spec_path
        self.policy_dir = policy_dir
        self.validator_name = "opa"
        self.version = "1.0.0"

    def validate(self):
        findings = []

        if not os.path.exists(self.spec_path):
            return None, f"[{self.validator_name}] Target spec file not found: {self.spec_path}"

        # Detect local opa.exe or fallback to system 'opa'
        opa_bin = ".\\opa.exe" if os.path.exists(".\\opa.exe") else "opa"
        cmd = f"{opa_bin} eval --data {self.policy_dir} --input {self.spec_path} \"data.governance.api.deny\" --format json"

        try:
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if res.returncode != 0 and not res.stdout:
                return None, f"[{self.validator_name}] CLI Execution Error: {res.stderr.strip()}"

            if not res.stdout:
                return findings, None

            data = json.loads(res.stdout)
            results = data.get("result", [])

            for r in results:
                expressions = r.get("expressions", [])
                for expr in expressions:
                    value = expr.get("value", [])
                    for item in value:
                        if isinstance(item, dict):
                            rule_id = str(item.get("rule_id", "GOV-POLICY-DENY"))
                            severity = str(item.get("severity", "HIGH")).upper()
                            message = str(item.get("message", "Policy violation detected"))
                            path_str = str(item.get("path", ""))

                            finding = {
                                "rule_id": rule_id,
                                "rule_version": self.version,
                                "severity": severity,
                                "category": "GOVERNANCE_POLICY",
                                "message": message,
                                "location": {
                                    "file": self.spec_path,
                                    "path": path_str,
                                    "line": 1
                                },
                                "evidence": {
                                    "tool": self.validator_name,
                                    "raw_output": item,
                                    "timestamp": datetime.now(timezone.utc).isoformat()
                                }
                            }
                            findings.append(finding)

            return findings, None

        except Exception as e:
            return None, f"[{self.validator_name}] Execution Exception: {str(e)}"