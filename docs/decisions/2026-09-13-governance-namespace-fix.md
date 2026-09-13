บริบทงาน: Foundation Validation Engine — Governance Rule Identity Investigation
สถานะ: ปิดงานสมบูรณ์แล้ว (CLOSED)
อัปเดตล่าสุด: 2026-09-13

Repo: C:\Users\pc\Documents\foundation-validation-latest
(clone จาก https://github.com/niphan1000-cyber1000/foundation-validation.git, branch main)

=== สรุปสถานะสุดท้าย ===

PR #1 (P0) — MERGED เข้า main:
- แก้ load_registry() ใน validators/run_all.py ให้ raise ValueError
  เมื่อสอง registry path มี rule_id ซ้ำกันแบบ conflicting definition
- เพิ่ม tests/test_registry_conflict.py (3 test cases)
- Branch fix/registry-duplicate-detection ถูกลบไปแล้วหลัง merge

PR #31 "fix(governance): separate document-level rules into GOV-DOC-*
namespace" — MERGED เข้า main:
- เปลี่ยน governance_engine.py ให้ emit rule_id แบบ concrete ตาม field
  ที่ขาดจริง: GOV-DOC-001-MISSING-OWNER / -CLASSIFICATION / -VERSION
  (เดิมส่งแค่ "GOV-001" hardcode generic)
- เพิ่ม entries ใหม่ใน rules/registry.yaml สำหรับ GOV-DOC-001-* ทั้งหมด
  severity = HIGH
- เพิ่ม tests/test_governance_doc_rules.py (3 test cases)
- Branch fix/governance-concrete-rule-ids ถูกลบไปแล้วหลัง merge

PR #32 "fix(registry): enforce GOV-/GOV-DOC- namespace convention for
governance domain" — MERGED เข้า main:
- เพิ่ม validation ใน load_registry() ให้ reject governance-domain rule
  ที่ไม่มี prefix ถูกต้อง (ต้องขึ้นต้นด้วย GOV- หรือ GOV-DOC- เท่านั้น)
- เพิ่ม test cases ใน tests/test_registry_conflict.py:
  test_load_registry_rejects_governance_rule_without_gov_prefix
  test_load_registry_accepts_gov_and_gov_doc_prefixes
- Branch fix/registry-namespace-convention ถูกลบไปแล้วหลัง merge

=== การตรวจสอบยืนยันหลัง merge ทั้งสอง PR ===

1. Full test suite บน main: 111 passed (8.29s) — ไม่มี regression
2. Targeted regression check เฉพาะไฟล์ที่ PR #31/#32 แก้ร่วมกัน
   (validators/run_all.py, tests/test_registry_conflict.py):
   8 passed (0.11s) ครอบคลุม:
   - test_load_registry_rejects_governance_rule_without_gov_prefix: PASS
   - test_load_registry_accepts_gov_and_gov_doc_prefixes: PASS
   - test_severity_resolves_from_registry_to_HIGH: PASS
3. git fetch --prune ยืนยัน remote branches ทั้งหมดที่เกี่ยวข้อง
   (fix/governance-concrete-rule-ids, fix/registry-namespace-convention)
   ถูกลบออกจาก GitHub จริง ไม่ใช่แค่ local cache ค้าง

=== Architecture หลัง fix (final state) ===

                    Rule Registry (rules/registry.yaml)
                         │
             ┌───────────┴───────────┐
             │                       │
        API Governance          Document Governance
             │                       │
       GOV-001..003            GOV-DOC-001..003
             │                       │
       governance.rego       governance_engine.py
             │                       │
            OPA                repo manifests

Namespace convention (locked, enforced by code):
  GOV-*      = API/spec governance      (เจ้าของ: governance.rego)
  GOV-DOC-*  = repository/document governance (เจ้าของ: governance_engine.py)

load_registry() บังคับ convention นี้แบบ automated guardrail แล้ว —
ถ้ามีใครเพิ่ม governance-domain rule ใหม่โดยไม่ใส่ prefix ถูกต้อง
จะ fail ทันทีตอน load registry (ไม่ต้องรอไปเจอ collision ตอน runtime)

=== Decision Gate ที่เคยค้างไว้ — ตอบครบแล้ว ===

คำถาม: มี consumer (code/test/CI) ที่ผูกกับ bare "GOV-001" จาก
governance domain โดยเฉพาะหรือไม่?
ผลการตรวจสอบ: ไม่พบ consumer ดังกล่าว → ปลอดภัยที่จะ rename เป็น
GOV-DOC-* ตามแผน (ไม่ต้องทำ backward-compat migration/alias)

=== ข้อควรระวังที่ยังต้องจำไว้ (ไม่ใช่ action item เร่งด่วน) ===

1. Breaking change ด้าน identifier: หากมี external tooling นอก repo นี้
   ที่เคย parse "GOV-001" จาก governance domain โดยเฉพาะ (นอกเหนือจากที่
   grep เจอใน repo) จะต้องอัปเดตเป็น GOV-DOC-001-* เอง — ควรระบุไว้ใน
   PR #32 description หรือ CHANGELOG ให้ทีมอื่นเห็นชัด
2. Maintenance overhead: ต้องดูแล 2 namespace ใน registry ให้ไม่ปะปนกัน
   ในอนาคต — บรรเทาไปมากแล้วด้วย automated guardrail ใน load_registry()
   ที่เพิ่มใน PR #32

=== หลักการสำคัญที่ยึดตลอดงานนี้ ===

- One Rule -> One Owner -> One Authoritative Enforcement Path
- อย่า patch ก่อนเข้าใจ scope ของปัญหาให้ครบ (ทำ semantic comparison
  และ consumer check ก่อนแตะโค้ดจริง)
- Namespace ต้องมี convention ชัดเจนที่ป้องกัน collision ในอนาคต
  ไม่ใช่แค่แก้ปัญหาเฉพาะหน้าตัวเดียว
- Registry เป็น single source of truth ของทั้งสอง namespace
  (GOV-* และ GOV-DOC-*) ยืนยันด้วย automated test + guardrail แล้ว

=== หมายเหตุ housekeeping ===

- Local branches เก่าที่ไม่เกี่ยวกับงานนี้ยังค้างอยู่ (ไม่กระทบ):
  fix/registry-duplicate-detection, fix/wire-governance-registry,
  fix/wire-security-registry — cleanup ได้ทีหลังถ้าต้องการ
- ไม่มี pending decision หรือ task ค้างสำหรับงานนี้อีกแล้ว
  หากมีงานต่อยอดในอนาคต (เช่น เพิ่ม rule ใหม่ในฝั่งใดฝั่งหนึ่ง)
  ให้เริ่มจากอ่านไฟล์นี้เพื่อเข้าใจ context และ convention ที่ล็อกไว้แล้ว
