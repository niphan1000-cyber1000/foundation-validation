package main

import rego.v1

# Base Rule Standard
# --------------------------------------------------------------------------
# This is the root aggregation policy for the Foundation Validation Engine.
# It follows the default-deny principle from the Foundation Validation Spec
# (Governance domain): a request is only allowed once every domain-level
# policy package it depends on explicitly proves compliance. No domain
# package is trusted implicitly, and no bypass or force-fail flag exists
# in this file.
#
# NOTE: NOT CURRENTLY WIRED INTO THE CI GATE (code review finding, see PR
# history): `data.main.allow` (this file) and `data.policies.security.*`
# (security-policies.rego) are exercised by `opa test security/` in the
# `security-policy-unit-tests` CI job — that job proves the *rules
# themselves* are correct in isolation. It does NOT mean these rules are
# consulted by GateDecisionEngine when deciding to block a PR: the
# real OpenAPI-spec gate (validators/run_all.py::_invoke_opa) only loads
# `--data policies/` and queries `data.governance.api.deny`, which never
# touches `data.main` or `data.policies.security`. A green
# security-policy-unit-tests run is evidence the auth/password-strength
# logic here is *correct*, not evidence it is *enforced* on anything.
# If/when this domain is wired into the real gate, update this comment
# and cli.py/run_all.py's _DOMAINS wiring together.

default allow := false

# Aggregate decision: allow only when the security domain policy allows.
# Additional domain packages (e.g. data.policies.governance) can be added
# here as further required conditions as the engine grows.
allow if {
data.policies.security.allow
}
