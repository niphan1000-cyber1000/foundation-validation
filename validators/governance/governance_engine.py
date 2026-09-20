import os
import json
import yaml

def run_governance_scan(target_path: str) -> list:
    """Scan repository YAML/YML manifests for required governance metadata.

    Required fields on each document (looked up under top-level keys
    'info', 'metadata', or the document root): owner, classification, version.

    Emits concrete rule_ids under the GOV-DOC-* namespace so they never
    collide with the API/spec-level GOV-* rules owned by policies/governance.rego.
    """
    findings = []
    required_fields = ['owner', 'classification', 'version']
    # Map missing field -> concrete rule_id (namespace GOV-DOC-*)
    field_to_rule = {
        'owner': 'GOV-DOC-001-MISSING-OWNER',
        'classification': 'GOV-DOC-001-MISSING-CLASSIFICATION',
        'version': 'GOV-DOC-001-MISSING-VERSION',
    }

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
                            if not isinstance(metadata, dict):
                                metadata = {}
                            for field in required_fields:
                                if field not in metadata:
                                    findings.append({
                                        "rule_id": field_to_rule[field],
                                        "severity": "HIGH",  # default; registry is authoritative
                                        "message": f"Missing required governance field '{field}' in {file_path}",
                                        "file": file_path,
                                        "line": 1
                                    })
                except Exception:
                    pass
    return findings