# validators/policy/

**Rule ID prefix:** `POL-`

## Scope

Validates policy-as-code compliance that is not specifically about
security: naming conventions, resource limits, allowed dependency
licenses, required metadata on services, and similar organization-wide
standards expressed as Rego/OPA (or equivalent) policy.

This is distinct from `validators/security/`, which covers
vulnerabilities and access control. If a rule is about "is this allowed
under CloudForge conventions" rather than "is this exploitable," it
belongs here.

## Input

- `target.type`: any
- `target.reference` / `target.location`: what to check

## Output

One `Finding` per policy violation:

| Violation | Suggested severity |
|---|---|
| Resource limit exceeded (e.g. no CPU/memory limits declared) | HIGH |
| Disallowed dependency license | HIGH |
| Naming convention violation | MEDIUM |
| Missing required metadata (owner, team label) | MEDIUM |
| Style/convention deviation with no functional impact | LOW |

Evidence should include the policy input document and the OPA decision
log (`type: log`).

## Status

Not yet implemented. Planned engine: OPA policies specific to
non-security governance conventions, evaluated the same way as
`validators/security/`, kept in a separate package namespace
(e.g. `policies.conventions`) so security and general policy concerns
don't get tangled together.
