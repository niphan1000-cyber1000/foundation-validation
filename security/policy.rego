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

default allow := false

# Aggregate decision: allow only when the security domain policy allows.
# Additional domain packages (e.g. data.policies.governance) can be added
# here as further required conditions as the engine grows.
allow if {
data.policies.security.allow
}
