import os

def run_security_scan(target_path: str) -> list:
    findings = []
    keywords = ['api_key', 'apikey', 'secret', 'password', 'bearer']
    
    target = target_path if os.path.exists(target_path) else '.'
    for root, dirs, files in os.walk(target):
        # ข้ามฟลเดอร validators/security และ venv, .git ออกจากการสแกน
        dirs[:] = [d for d in dirs if not d.startswith('.') and d != 'venv' and 'security' not in d]
        for file in files:
            if file.endswith(('.py', '.yaml', '.yml', '.json', '.env', '.md')):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line_idx, line in enumerate(f, start=1):
                            lower_line = line.lower()
                            for kw in keywords:
                                if kw in lower_line and ('=' in line or ':' in line):
                                    findings.append({
                                        "rule_id": "SEC-001",
                                        "severity": "HIGH",
                                        "message": f"Potential secret keyword '{kw}' found in {file_path}:{line_idx}",
                                        "file": file_path,
                                        "line": line_idx
                                    })
                except Exception:
                    pass
    return findings
