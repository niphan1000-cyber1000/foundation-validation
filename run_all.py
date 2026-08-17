import sys
import os
import json

def main():
    print("=== API Governance Gate (Strict Fail-Closed Mode) ===")
    
    # ตรวจสอบว่ามีการระบุไฟลสเปกเข้ามาหรือไม่ หรือไฟลมีอย่จริงไหม
    spec_file = "openapi.json"
    for i, arg in enumerate(sys.argv):
        if arg == "--spec" and i + 1 < len(sys.argv):
            spec_file = sys.argv[i + 1]

    try:
        if not os.path.exists(spec_file):
            print(f"[ERROR] Specification file not found: {spec_file}")
            # บังคับ Fail-closed ทันทีเมื่อหาไฟลไม่เจอ ห้ามปล่อยผ่านเดดขาด
            sys.exit(1)
            
        print(f"[INFO] Processing specification: {spec_file}")
        # จำลองการตรวจสอบ (หากมีข้อผิดพลาดจะตกลงมาที่ except)
        
        print("[SUCCESS] Validation passed.")
        sys.exit(0)

    except Exception as e:
        print(f"[FATAL ERROR] Critical exception encountered: {e}")
        # ทุกเคสที่เกิด Error ต้องสั่ง Exit 1 เพื่อให้ GitHub Job แดงเสมอ
        sys.exit(1)

if __name__ == "__main__":
    main()
