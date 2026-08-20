import sys
import os
import json
import argparse
from policy_engine import parse_opa_output

def main():
    parser = argparse.ArgumentParser(description="Policy Validator (OPA Engine Wrapper)")
    parser.add_argument("--rules", required=False, help="Path to rules.json")
    parser.add_argument("--target", required=True, help="Path to OPA evaluation result JSON file")
    args = parser.parse_args()

    target_file = args.target
    if not os.path.exists(target_file):
        print(json.dumps({"error": "load_error", "message": f"Target file not found: {target_file}"}))
        sys.exit(1)

    try:
        with open(target_file, 'r', encoding='utf-8-sig') as f:
            raw_data = json.load(f)
    except Exception as e:
        print(json.dumps({"error": "load_error", "message": str(e)}))
        sys.exit(1)

    findings = parse_opa_output(raw_data, target_path=target_file)
    status = "PASSED" if len(findings) == 0 else "FAILED"

    result = {
        "status": status,
        "target": target_file,
        "findings": findings
    }
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
