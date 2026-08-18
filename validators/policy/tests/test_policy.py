import unittest
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from policy_engine import parse_opa_output

class TestPolicyEngine(unittest.TestCase):
    def test_parse_opa_output(self):
        fixture_path = os.path.join(os.path.dirname(__file__), 'fixtures', 'opa_output.json')
        with open(fixture_path, 'r', encoding='utf-8-sig') as f:
            raw_data = json.load(f)
        
        findings = parse_opa_output(raw_data, target_path="policy_eval.json")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "POL-001")
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        self.assertEqual(findings[0]["category"], "policy")

if __name__ == '__main__':
    unittest.main()
