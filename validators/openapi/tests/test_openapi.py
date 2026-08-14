import unittest
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from openapi_engine import parse_spectral_output

class TestOpenAPIEngine(unittest.TestCase):
    def test_parse_spectral_output(self):
        fixture_path = os.path.join(os.path.dirname(__file__), 'fixtures', 'spectral_output.json')
        with open(fixture_path, 'r', encoding='utf-8-sig') as f:
            raw_data = json.load(f)
        
        findings = parse_spectral_output(raw_data, target_path="api.yaml")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "OAS-oas3-schema")
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        self.assertEqual(findings[0]["location"]["path"], "paths./users.get")

if __name__ == '__main__':
    unittest.main()
