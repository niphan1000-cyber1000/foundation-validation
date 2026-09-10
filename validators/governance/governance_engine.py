import os
import json
import yaml

def run_governance_scan(target_path: str) -> list:
    findings = []
    required_fields = ['owner', 'classification', 'version']
    
    target = target_path if os.path.exists(target_path) else '.'
    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if not d.startswith('.') and d != 'venv' and 'governance' not in d]
        for file in files:
            if file.endswith(('.yaml', '.yml')):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = yaml.safe_load(f)
                        if isinstance(data, dict):
                            metadata = data.get('info', data.get('metadata', data))
                            for field in required_fields:
                                if field not in metadata:
                                    findings.append({
                                        "rule_id": "GOV-001",
                                        "severity": "MEDIUM",
                                        "message": f"Missing required governance field '{field}' in {file_path}",
                                        "file": file_path,
                                        "line": 1
                                    })
                except Exception:
                    pass
    return findings
