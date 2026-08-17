import sys
import os
import json

def main():
    print("=== API Governance Gate (Failure Injection Mode) ===")
    
    spec_file = "openapi.json"
    for i, arg in enumerate(sys.argv):
        if arg == "--spec" and i + 1 < len(sys.argv):
            spec_file = sys.argv[i + 1]

    try:
        if not os.path.exists(spec_file):
            print(f"[FATAL ERROR] Target specification file not found: {spec_file}")
            sys.exit(1)
            
        with open(spec_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        # ตรวจสอบเบื้องต้น: ถ้าไม่มี openapi field หรือ paths ผิดประเภท ให้ตีตกทันที
        if "openapi" not in data or not isinstance(data.get("paths"), (dict, type(None))):
            print(f"[GATE BLOCK] Invalid OpenAPI schema detected in {spec_file}")
            sys.exit(1)
            
        # ตรวจสอบ Policy บังคับ (เช่น ต้องมี paths และ security/responses ตามก)
        if "paths" in data and isinstance(data["paths"], dict):
            for path, methods in data["paths"].items():
                for method, details in methods.items():
                    if isinstance(details, dict) and "responses" not in details:
                        print(f"[GATE BLOCK] Policy Violation: Missing responses in {path} [{method}]")
                        sys.exit(1)

        print(f"[SUCCESS] Specification {spec_file} passed all governance checks.")
        sys.exit(0)

    except json.JSONDecodeError:
        print(f"[FATAL ERROR] JSON parsing failed for {spec_file} (Malformed file)")
        sys.exit(1)
    except Exception as e:
        print(f"[FATAL ERROR] Unexpected exception: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
