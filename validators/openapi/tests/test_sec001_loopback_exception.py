import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from server_url_policy import is_allowed_server_url, SEC_001_PATTERN


class TestSec001LoopbackException(unittest.TestCase):
    """
    SEC-001-https-only invariant:
    HTTPS is mandatory for non-loopback endpoints. Plain HTTP is permitted
    ONLY for localhost/127.0.0.1 development endpoints — never for private
    network ranges or internal DNS names, since those can be reachable
    over a real network.
    """

    # --- positive cases: must be ALLOWED -----------------------------

    def test_https_any_host_allowed(self):
        self.assertTrue(is_allowed_server_url("https://foundation-validation.cloudforge.internal/v1"))

    def test_http_localhost_with_port_and_path_allowed(self):
        self.assertTrue(is_allowed_server_url("http://localhost:8080/v1"))

    def test_http_localhost_no_port_allowed(self):
        self.assertTrue(is_allowed_server_url("http://localhost/v1"))

    def test_http_localhost_bare_allowed(self):
        self.assertTrue(is_allowed_server_url("http://localhost"))

    def test_http_loopback_ip_allowed(self):
        self.assertTrue(is_allowed_server_url("http://127.0.0.1/v1"))

    def test_http_loopback_ip_with_port_allowed(self):
        self.assertTrue(is_allowed_server_url("http://127.0.0.1:8080/v1"))

    # --- negative cases: must FAIL (this is the important part —-----
    # --- the exception must NOT widen to "any private network") -----

    def test_http_private_network_192_blocked(self):
        # e.g. an office/VPN LAN address — a real, reachable network endpoint.
        self.assertFalse(is_allowed_server_url("http://192.168.1.10:8080/v1"))

    def test_http_private_network_10_blocked(self):
        self.assertFalse(is_allowed_server_url("http://10.0.0.1"))

    def test_http_private_network_172_blocked(self):
        self.assertFalse(is_allowed_server_url("http://172.16.0.5"))

    def test_http_internal_dns_name_blocked(self):
        self.assertFalse(is_allowed_server_url("http://example.internal"))

    def test_http_public_host_blocked(self):
        self.assertFalse(is_allowed_server_url("http://api.example.com"))

    def test_lookalike_hostname_not_treated_as_loopback(self):
        # Guards against a naive "startswith localhost" check being tricked
        # by a hostname that merely starts with the loopback name.
        self.assertFalse(is_allowed_server_url("http://localhost.evil.com"))
        self.assertFalse(is_allowed_server_url("http://127.0.0.1.evil.com"))

    def test_pattern_matches_spectral_ruleset(self):
        # Sanity check that the pattern documented here is the exact
        # string that must also appear in .spectral.yaml's
        # SEC-001-https-only rule functionOptions.match.
        spectral_yaml_path = os.path.join(
            os.path.dirname(__file__), "..", "..", "..", ".spectral.yaml"
        )
        with open(spectral_yaml_path, "r", encoding="utf-8-sig") as f:
            content = f.read()
        self.assertIn(
            SEC_001_PATTERN.replace("\\", "\\\\"),
            content,
            "SEC_001_PATTERN in server_url_policy.py has drifted from the "
            "SEC-001-https-only pattern in .spectral.yaml — update both.",
        )


if __name__ == "__main__":
    unittest.main()
