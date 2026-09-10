import re
import yaml
from pathlib import Path

def run_security_scan(target_file: str) -> dict:
    findings = []
    path = Path(target_file)
    if not path.exists():
        return {"status": "ERROR", "message": f"File not found: {target_file}", "findings": []}

    try:
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
            data = yaml.safe_load(content) or {}
    except Exception as e:
        return {"status": "ERROR", "message": str(e), "findings": []}

    # ตัวอย่างการตรวจสอบรปแบบความเสี่ยงเบื้องต้น (เช่น Secret patterns)
    secret_patterns = [
        r"api[_-]?key\s*[:=]\s*['\"].*?['\"]",
        r"password\s*[:=]\s*['\"].*?['\"]",
        r"secret\s*[:=]\s*['\"].*?['\"]"
    ]

    for idx, line in enumerate(content.splitlines(), start=1):
        for pattern in secret_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "rule_id": "SEC-001",
                    "severity": "CRITICAL",
                    "message": f"Potential hardcoded secret or credential found at line {idx}.",
                    "file": target_file,
                    "line": idx
                })

    return {
        "domain": "security",
        "status": "FAIL" if findings else "PASS",
        "findings": findings,
        "rule_count": len(findings)
    }
