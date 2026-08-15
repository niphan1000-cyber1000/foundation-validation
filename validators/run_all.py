import argparse
import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

def load_registry(registry_path="rules/registry.yaml"):
    if not yaml:
        return {}
    path = Path(registry_path)
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            data = yaml.safe_load(f)
            rules = {}
            for rule in data.get("rules", []):
                rules[rule.get("id")] = rule
            return rules
    except Exception:
        return {}

def run_validation(spec_path, sarif_path, registry_path="rules/registry.yaml"):
    registry = load_registry(registry_path)
    findings = [
        {
            "rule_id": "OAS-001-path-kebab-case",
            "message": "Path must use kebab-case",
            "file": spec_path
        },
        {
            "rule_id": "SEC-001-https-only",
            "message": "Servers must use HTTPS",
            "file": spec_path
        }
    ]

    processed_findings = []
    has_blocking_error = False

    for finding in findings:
        r_id = finding["rule_id"]
        rule_meta = registry.get(r_id, {})
        severity = rule_meta.get("severity", "WARN").upper()
        
        finding["severity"] = severity
        finding["gate_behavior"] = rule_meta.get("gate_behavior", "BLOCK")
        
        processed_findings.append(finding)
        
        if severity in ["ERROR", "CRITICAL", "HIGH"] and finding["gate_behavior"] == "BLOCK":
            has_blocking_error = True

    if sarif_path:
        sarif_output = {
            "version": "2.1.0",
            "": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Foundation Validation Engine",
                            "rules": list(registry.values())
                        }
                    },
                    "results": [
                        {
                            "ruleId": f["rule_id"],
                            "message": {"text": f["message"]},
                            "level": "error" if f["severity"] in ["ERROR", "CRITICAL", "HIGH"] else "warning",
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": f["file"]}
                                    }
                                }
                            ]
                        } for f in processed_findings
                    ]
                }
            ]
        }
        with open(sarif_path, "w", encoding="utf-8") as sf:
            json.dump(sarif_output, sf, indent=2)

    if has_blocking_error:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Foundation Validation Engine")
    parser.add_argument("--spec", required=True, help="Path to OpenAPI spec file")
    parser.add_argument("--sarif", help="Path to output SARIF report")
    parser.add_argument("--registry", default="rules/registry.yaml", help="Path to rule registry YAML")
    
    args = parser.parse_args()
    run_validation(args.spec, args.sarif, args.registry)
