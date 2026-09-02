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
# NOTE: NOT CURRENTLY WIRED INTO THE CI GATE — and it is NOT simply a
# missing wire-up. `data.main.allow` (this file) and
# `data.policies.security.*` (security-policies.rego) evaluate a
# RUNTIME HTTP REQUEST shape (`input.headers.authorization`,
# `input.body.password` — see security-policies_test.rego), not an
# OpenAPI spec. The real spec gate (validators/run_all.py::_invoke_opa)
# calls `opa eval --input <spec_path> --data policies/
# data.governance.api.deny`, where `input` is the parsed OpenAPI
# document (input.info / input.paths / input.servers, as used by
# policies/security.rego). Those two input shapes are incompatible:
# an OpenAPI spec document never has `input.headers` or `input.body`,
# so naively adding `data.policies.security.allow` as a condition
# evaluated against the same spec input would make `allow` false for
# every spec and BLOCK every PR unconditionally — not close a security
# gap, but break the gate outright.
#
# This is why `security-policy-unit-tests` is intentionally its own CI
# job (see .github/workflows/governance.yml): it proves the auth/
# password-strength Rego logic here is *correct* in isolation via
# `opa test`, not that it is *enforced* anywhere. There is currently no
# runtime request-time enforcement point (API gateway, middleware, etc.)
# in this codebase for this policy to attach to.
#
# The intended home for this logic is the not-yet-built
# `validators/security/` domain (see validators/security/README.md,
# Status: "Not yet implemented") — a target-based validator (scans a
# repository/commit/artifact for secrets, CVEs, IaC misconfig, and
# auth/policy issues), which is a materially larger build than adding
# a line to run_all.py's OPA invocation. Do not wire this file into
# validators/run_all.py::_invoke_opa or cli.py's _DOMAINS as a shortcut;
# build validators/security/run.py against its own request/target input
# instead, then wire that.

default allow := false

# Aggregate decision: allow only when the security domain policy allows.
# Additional domain packages (e.g. data.policies.governance) can be added
# here as further required conditions as the engine grows.
allow if {
data.policies.security.allow
}
