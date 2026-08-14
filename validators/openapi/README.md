# validators/openapi/

**Rule ID prefix:** `API-`

## Scope

Validates `openapi.yaml` itself: linting, style, and breaking-change
detection between the target commit/branch and the previously released
contract version. This is the domain responsible for enforcing the rules
already declared in [`.spectral.yaml`](../../.spectral.yaml) at the repo
root, plus any breaking-change checks Spectral doesn't cover.

## Input

- `target.type`: `api_contract`
- `target.reference`: repo/commit reference
- `target.location`: path to the OpenAPI file (default `openapi.yaml`)

## Output

One `Finding` per lint violation or breaking change:

| Violation | Suggested severity |
|---|---|
| Breaking change without a major version bump (e.g. removed endpoint, removed required-response field, narrowed enum) | HIGH |
| Missing `operationId`, `tags`, or `x-api-id` (Spectral `error` rules) | HIGH |
| Missing `x-traceability` (Spectral `warn` rule) | MEDIUM |
| Style/lint issues from `spectral:oas` base ruleset | LOW |
| Placeholder values left in (`example.com`, TODO text) | MEDIUM |

Evidence should include the Spectral JSON output (`type: log`) and, for
breaking-change findings, a diff between the previous and current contract
(`type: diff`).

## Status

Not yet implemented. Planned engine: `spectral lint openapi.yaml --ruleset
.spectral.yaml -f json` piped into a result-shaping step that maps
Spectral's output onto the `Finding`/`Evidence` schema, plus a
breaking-change checker (e.g. `oasdiff`) comparing against the last
`PASSED` run's target reference.
