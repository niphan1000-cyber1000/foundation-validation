"""
server_url_policy.py — SEC-001-https-only invariant, mirrored for testing.

The actual enforcement of this rule against a real OpenAPI spec happens in
the Spectral CLI, driven by the custom rule "SEC-001-https-only" in
.spectral.yaml at the repo root (see rules/registry.yaml for the full
rule definition). Spectral rules are YAML + a regex, so they can't be
unit-tested directly with pytest/unittest without shelling out to `npx
spectral` (which requires network/npm access and isn't available in every
environment, e.g. CI sandboxes without registry access).

This module re-states the exact same regex as a small, pure-Python
predicate so the invariant itself — "HTTPS is mandatory for non-loopback
server endpoints; plain HTTP is permitted only for localhost/127.0.0.1" —
has fast, deterministic, offline test coverage (see
validators/openapi/tests/test_sec001_loopback_exception.py).

IMPORTANT: if you change the pattern here, you MUST make the identical
change to the `functionOptions.match` value of the SEC-001-https-only
rule in .spectral.yaml, or the two will drift and this test suite will
stop being representative of what actually runs in CI.
"""

import re

# Loopback-only exception: https:// is always allowed; http:// is allowed
# ONLY for exactly "localhost" or "127.0.0.1" (optionally with a port
# and/or path). Any other host — including private network ranges like
# 192.168.x.x, 10.x.x.x, 172.16.x.x, and internal DNS names like
# *.internal — must use https://.
SEC_001_PATTERN = r"^(https://.+|http://(localhost|127\.0\.0\.1)(:\d+)?(/.*)?)$"

_compiled = re.compile(SEC_001_PATTERN)


def is_allowed_server_url(url: str) -> bool:
    """Return True if `url` satisfies the SEC-001-https-only invariant."""
    if not isinstance(url, str):
        return False
    return bool(_compiled.match(url))
