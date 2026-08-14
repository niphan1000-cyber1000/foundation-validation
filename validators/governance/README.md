# validators/governance/

**Rule ID prefix:** `GOV-`

## Scope

Validates release-readiness and governance process compliance: versioning
rules, changelog presence, ownership/approval sign-off, and waiver
handling as defined in the Foundation Validation Spec (Sections 4.1, 6.3,
and 8).

## Input

- `target.type`: typically `repository` or `commit`
- `target.reference`: the release candidate being evaluated

## Output

One `Finding` per governance gap:

| Violation | Suggested severity |
|---|---|
| Version bump doesn't match the nature of the change (e.g. breaking change without a major bump) | HIGH |
| Missing or expired waiver on an open HIGH finding | HIGH |
| No changelog entry for the release | MEDIUM |
| Missing required approver sign-off | MEDIUM |
| Open finding past its SLA per spec Section 6.3 (escalated) | inherits the escalated severity |

Evidence should include the changelog diff, the waiver record (if any),
and approval metadata (`type: log` or `type: diff`).

## Status

Not yet implemented. Planned engine: a rule set that reads
`CHANGELOG.md`, `openapi.yaml`'s `info.version`, and repo metadata
(tags, PR approvals) and cross-checks them against the SLA/waiver rules
in `docs/foundation-validation-spec.md`.
