package policies.security

import rego.v1

# Test 1: อนุญาตเมื่อมี Bearer Token ที่ถูกต้อง
test_allow_with_valid_bearer if {
	allow with input as {"headers": {"authorization": "Bearer valid-jwt-token-123"}}
}

# Test 2: ปฏิเสธเมื่อไม่มี Authorization Header เลย
test_deny_without_auth if {
	not allow with input as {"headers": {}}
}

# Test 3: ปฏิเสธเมื่อใช้ Basic Auth แทน Bearer
test_deny_basic_auth if {
	not allow with input as {"headers": {"authorization": "Basic dXNlcjpwYXNz"}}
}

# Test 4: ปฏิเสธ password ที่สั้นเกินไป
test_deny_weak_password if {
	deny_weak_password with input as {"body": {"password": "123"}}
}

# Test 5: อนุญาต password ที่แข็งแรงพอ
test_allow_strong_password if {
	not deny_weak_password with input as {"body": {"password": "StrongPass123!"}}
}
