import unittest
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from openapi_engine import parse_spectral_output, SpectralOutputError

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

    def test_valid_empty_list_is_zero_findings_not_an_error(self):
        """A clean spec genuinely produces []. This must NOT raise -
        only non-list shapes should."""
        findings = parse_spectral_output([], target_path="api.yaml")
        self.assertEqual(findings, [])

    def test_dict_wrapped_output_raises_instead_of_silent_pass(self):
        """Regression test (Spectral validator bypass finding): if
        Spectral's output is wrapped under a key (version/format change,
        reporter change, etc.) instead of being a bare array, this must
        raise SpectralOutputError - NOT silently return [] and let a
        real violation disappear as a clean pass."""
        malformed = {
            "results": [
                {"code": "SEC-001-https-only", "severity": 0,
                 "message": "insecure", "path": ["servers", 0, "url"]}
            ]
        }
        with self.assertRaises(SpectralOutputError):
            parse_spectral_output(malformed, target_path="api.yaml")

    def test_non_json_string_raises_instead_of_silent_pass(self):
        """A string that fails to parse as JSON must raise, not
        silently return []."""
        with self.assertRaises(SpectralOutputError):
            parse_spectral_output("not valid json {{{", target_path="api.yaml")

    def test_scalar_output_raises_instead_of_silent_pass(self):
        """Any other unexpected top-level shape (e.g. a bare number or
        string that IS valid JSON but isn't a findings array) must
        raise, not silently return []."""
        with self.assertRaises(SpectralOutputError):
            parse_spectral_output(42, target_path="api.yaml")

if __name__ == '__main__':
    unittest.main()
