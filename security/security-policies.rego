package policies.security

import rego.v1

default allow := false

# ข้อ 1: ตรวจสอบ Authorization Header ต้องขึ้นต้นด้วย "Bearer "
allow if {
	input.headers.authorization
	startswith(input.headers.authorization, "Bearer ")
}

# ข้อ 2: ปฏิเสธ password ที่สั้นกว่า 8 ตัวอักษร
deny_weak_password if {
	input.body.password
	count(input.body.password) < 8
}
