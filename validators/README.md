# validators/

This folder contains the implementation of every validator the Foundation
Validation Engine can execute. It is organized by **domain**, matching the
`Domain` enum in `openapi.yaml` and the domain table in
`docs/foundation-validation-spec.md` (Section 3.1).

| Domain | Folder | Rule ID prefix (suggested) | Checks |
|---|---|---|---|
| Schema | [`schema/`](./schema) | `SCH-` | JSON/YAML content against the JSON Schemas in `schemas/` |
| OpenAPI | [`openapi/`](./openapi) | `API-` | `openapi.yaml` itself — lint, breaking-change detection, style |
| Security | [`security/`](./security) | `SEC-` | Vulnerabilities, secret leakage, dependency CVEs, IaC misconfiguration |
| Policy | [`policy/`](./policy) | `POL-` | Policy-as-code (OPA/Rego), naming conventions, resource limits |
| Governance | [`governance/`](./governance) | `GOV-` | Versioning rules, changelog, ownership/approval, release readiness |
| Traceability | [`traceability/`](./traceability) | `TRC-` | Completeness of requirement → rule → evidence linkage |

## Contract every validator must honor

Regardless of domain, a validator MUST:

1. Accept a `target` (as defined by `Target` in `schemas/validation-request.schema.json`) and a `ruleset_version`.
2. Emit zero or more `Finding` objects shaped exactly like `#/$defs/Finding` in `schemas/validation-result.schema.json`.
3. Attach at least one `Evidence` record (shaped like `schemas/validation-evidence.schema.json`) to every finding it produces — including passing findings.
4. Never mutate a previously captured `Evidence` record. Corrections are new records with `supersedes` set.
5. Assign `severity` per the Severity Model in `docs/foundation-validation-spec.md` (Section 4) — severity is a property of the *rule*, not something a validator run decides ad hoc.

## Adding a new validator

1. Pick the domain folder that matches what you're checking (see table above).
2. Add your rule(s) with an ID following that domain's prefix convention (e.g. `SEC-004`).
3. Register the rule so it is returned by `GET /v1/rules` (see that folder's own `README.md` for the domain-specific registration mechanism).
4. If the rule implements an upstream requirement or compliance clause, add a traceability mapping (see [`traceability/README.md`](./traceability/README.md)) so `coverage_status` doesn't show as `NOT_COVERED`.
5. Write a rule-level test asserting both the pass and fail path before wiring it into CI.

## Status

This structure is scaffolding for Phase C. Each domain folder currently
contains only its `README.md` describing intended scope — no validator
implementations exist yet. Existing OPA policies in `security/` (the
top-level, pre-Phase-C `security/policy.rego` and `security-policies.rego`)
are the Policy-as-code engine that the `policy/` and `security/` validators
below will eventually wrap and report through the `Finding`/`Evidence`
contract above.
