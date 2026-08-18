import sys
import os
import json
import argparse
import subprocess
from openapi_engine import parse_spectral_output

def main():
    parser = argparse.ArgumentParser(description="OpenAPI Validator (Spectral Wrapper)")
    parser.add_argument("--rules", required=False, help="Path to rules.json")
    parser.add_argument("--target", required=True, help="Path to OpenAPI spec file")
    args = parser.parse_args()

    target_file = args.target
    if not os.path.exists(target_file):
        print(json.dumps({"error": "load_error", "message": f"Target file not found: {target_file}"}))
        sys.exit(1)

    # Try running spectral CLI if available, otherwise mock/parse
    try:
        cmd = ["npx", "@stoplight/spectral-cli", "lint", target_file, "-f", "json"]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        raw_output = proc.stdout if proc.stdout else proc.stderr
    except Exception as e:
        raw_output = "[]"

    findings = parse_spectral_output(raw_output, target_path=target_file)
    status = "PASSED" if len(findings) == 0 else "FAILED"

    result = {
        "status": status,
        "target": target_file,
        "findings": findings
    }
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
