import json
import os
import sys
from datetime import datetime, timezone

class SchemaValidator:
    """
    Reference Implementation for all Validators in the Foundation platform.
    Contract Standard:
    - Return tuple: (findings_list, system_error_message)
    - Every finding MUST contain the standardized 'evidence' object.
    - Errors during execution MUST NOT be ignored (Fail-Safe: No silent failures).
    """

    def __init__(self, spec_path):
        self.spec_path = spec_path
        self.validator_name = "schema_validator"
        self.version = "1.0.0"

    def validate(self):
        findings = []

        # 1. Check File Existence
        if not os.path.exists(self.spec_path):
            return None, f"[{self.validator_name}] Target spec file not found: {self.spec_path}"

        # 2. Syntax Validation
        try:
            with open(self.spec_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            finding = self._create_finding(
                rule_id="SCHEMA-001-INVALID-JSON",
                severity="CRITICAL",
                category="SYNTAX_ERROR",
                message=f"JSON Syntax Error: {e.msg}",
                line=e.lineno,
                path="",
                raw_output={"error": str(e), "line": e.lineno, "col": e.colno}
            )
            findings.append(finding)
            return findings, None
        except Exception as e:
            return None, f"[{self.validator_name}] File read failure: {str(e)}"

        # 3. Structural OpenAPI Standard Checks
        try:
            if "openapi" not in data and "swagger" not in data:
                findings.append(self._create_finding(
                    rule_id="SCHEMA-002-MISSING-VERSION",
                    severity="HIGH",
                    category="SCHEMA_COMPLIANCE",
                    message="Missing required top-level 'openapi' or 'swagger' version indicator.",
                    line=1,
                    path="root",
                    raw_output={"keys_found": list(data.keys())}
                ))

            if "info" not in data or not isinstance(data.get("info"), dict):
                findings.append(self._create_finding(
                    rule_id="SCHEMA-003-MISSING-INFO",
                    severity="HIGH",
                    category="SCHEMA_COMPLIANCE",
                    message="Missing or invalid top-level 'info' object.",
                    line=1,
                    path="info",
                    raw_output={"has_info": "info" in data}
                ))

            if "paths" not in data or not isinstance(data.get("paths"), dict):
                findings.append(self._create_finding(
                    rule_id="SCHEMA-004-MISSING-PATHS",
                    severity="HIGH",
                    category="SCHEMA_COMPLIANCE",
                    message="Missing or invalid top-level 'paths' object.",
                    line=1,
                    path="paths",
                    raw_output={"has_paths": "paths" in data}
                ))

            return findings, None

        except Exception as e:
            return None, f"[{self.validator_name}] Unexpected validation crash: {str(e)}"

    def _create_finding(self, rule_id, severity, category, message, line, path, raw_output):
        return {
            "rule_id": rule_id,
            "rule_version": self.version,
            "severity": severity,
            "category": category,
            "message": message,
            "location": {
                "file": self.spec_path,
                "path": path,
                "line": line
            },
            "evidence": {
                "tool": self.validator_name,
                "raw_output": raw_output,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        }