# validators/traceability/

**Rule ID prefix:** `TRC-`

## Scope

Validates the completeness of the traceability chain defined in the
Foundation Validation Spec (Section 6): every mandatory rule must map
back to a `requirement_id`, and that mapping's `coverage_status` must be
`COVERED` — never `NOT_COVERED`, and `PARTIAL` only where explicitly
accepted.

This domain doesn't check the *target* being validated directly — it
checks the *validation engine's own rule registry* for gaps, which is
why it's listed last in the Exit Criteria (Section 7, item 5).

## Input

- The current rule registry (as returned by `GET /v1/rules`)
- The requirement/standard catalogue each rule is expected to map to

## Output

One `Finding` per traceability gap:

| Violation | Suggested severity |
|---|---|
| Mandatory rule has `coverage_status: NOT_COVERED` | HIGH |
| Mandatory rule has `coverage_status: PARTIAL` without a documented reason | MEDIUM |
| Rule references a `requirement_id` that doesn't exist in the catalogue | MEDIUM |
| Requirement has no rule mapped to it at all | LOW (informational until it's declared mandatory) |

Evidence should include the traceability matrix snapshot at the time of
the check (`type: snapshot`).

## Status

Not yet implemented. Planned engine: a script that cross-references
`GET /v1/rules` output against a requirement catalogue (TBD location —
see Open Item in `docs/foundation-validation-spec.md` Section 9) and
reports gaps as findings.
