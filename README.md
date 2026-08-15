# Foundation Validation

A governed validation platform for API contracts, security posture, and
repository governance. Foundation Validation runs a set of domain
validators against project artifacts (OpenAPI specs, schemas, policies)
and produces a unified, auditable result with evidence.

## Status

This project is in **active development (Foundation / Prototype stage)**.

| Domain        | Status                          |
|----------------|----------------------------------|
| Schema         | Implemented                     |
| OpenAPI        | Implemented (Spectral-based)    |
| Security       | Scaffolding                     |
| Policy         | Scaffolding (OPA/Rego present)  |
| Governance     | Scaffolding                     |
| Traceability   | Scaffolding                     |

## Architecture

```
Validation Request
      |
Validation Engine (validators/run_all.py)
      |
   +--+--+-------------+
   |     |              |
Schema  OpenAPI   Policy / Security / Governance / Traceability
   |     |              |
   +-----+--------------+
      |
Finding Aggregator -> normalize_finding()
      |
Gate Evaluator -> status (PASSED / FAILED)
      |
Evidence + Result (validation-result.json, results.sarif)
```

Each domain validator returns findings in a common shape, normalized via
`normalize_finding()` with a domain-specific rule ID prefix (e.g. `SCH`,
`OAS`, `POL`). Findings are aggregated into a single validation result
with a summary, an evidence section (artifacts + hash digest), and an
overall PASS/FAIL status.

## Validation Domains

- **Schema** (`validators/schema/`) — validates JSON documents against
  JSON Schema definitions.
- **OpenAPI** (`validators/openapi/`) — wraps Spectral to lint OpenAPI
  specs and maps findings into the unified Finding model.
- **Security** (`validators/security/`, `security/`) — OPA/Rego policies
  for security posture checks.
- **Policy** (`validators/policy/`) — OPA-based policy validation engine.
- **Governance** (`validators/governance/`) — intended to validate
  repository governance artifacts (versioning, changelogs, ownership).
- **Traceability** (`validators/traceability/`) — intended to link
  findings back to requirements/rules for audit purposes.

## Models

- **Finding** — a single validation issue: `rule_id`, `severity`,
  `category`, `message`, `location`.
- **Evidence** — proof that a validation ran: target file, rule count,
  and an overall `hash_digest` for integrity.
- **Result** — top-level output: `execution` metadata, `status`,
  `summary` (counts by severity), `findings[]`, `evidence`.

Schemas for these are defined in `schemas/`:
- `validation-request.schema.json`
- `validation-result.schema.json`
- `validation-evidence.schema.json`

## Gate Model

Current gate statuses: `PASSED`, `FAILED`.

A commit is blocked by the pre-commit hook (`.git/hooks/pre-commit`) if
validation status is `FAILED`.

> Planned: richer gate states (`WARN`, `SKIPPED`, `NOT_APPLICABLE`,
> `ERROR`) and a configurable severity-to-gate-outcome policy
> (e.g. HIGH = FAIL in production, WARN in development).

## CLI Usage

Run the master validator against an OpenAPI spec:

```bash
python validators/run_all.py --spec openapi.json --sarif results.sarif
```

Arguments:
- `--spec` — path to the OpenAPI spec JSON file to validate.
- `--sarif` — optional path to write SARIF-format output (for CI
  integration / code scanning tools).
- `--output` — path to write the full JSON result
  (default: `validation-result.json`).

Read the result:

```powershell
Get-Content -Path "validation-result.json" | ConvertFrom-Json | Select-Object status, summary
```

## Repository Structure

```
foundation-validation/
├── .github/workflows/        # CI pipelines (governance, api-governance)
├── schemas/                  # Request / Result / Evidence JSON Schemas
├── rules/                    # Rule taxonomy
├── security/                 # Security OPA/Rego policies + tests
├── policies/                 # Governance / security Rego policies
├── validators/
│   ├── schema/                  # Implemented
│   ├── openapi/                 # Implemented (Spectral wrapper)
│   ├── security/                # Scaffolding
│   ├── policy/                  # Scaffolding (OPA engine present)
│   ├── governance/               # Scaffolding
│   ├── traceability/             # Scaffolding
│   ├── tests/                   # Aggregator-level tests
│   └── run_all.py               # Master validation CLI / engine
├── openapi.json               # Spec under governance (validated by CI)
├── openapi.yaml                # API contract for this platform itself
├── .spectral.yaml              # Spectral ruleset for OpenAPI linting
└── README.md
```

## CI / Pre-commit Integration

A pre-commit hook (`.git/hooks/pre-commit`) runs
`validators/run_all.py --spec openapi.json` before every commit and
blocks the commit if validation status is `FAILED`. GitHub Actions
workflows in `.github/workflows/` run governance and API checks on
pull requests.

## Roadmap

Priority order for upcoming work:

1. **P0** — Validation Engine (central orchestrator, rule resolver)
2. **P0** — Rule Registry (single source of truth for all rules)
3. **P0** — Gate Engine (configurable severity-to-outcome policy)
4. **P0** — Test / CI Gate hardening
5. **P1** — OpenAPI Validator (breaking-change detection, semantic checks)
6. **P1** — Security, Governance, Traceability validators (full implementation)
7. **P2** — Evidence Chain (supersedes / audit trail)
8. **P2** — Path/content integrity checks (ensure the file validated is
   the file being committed)

## Development

Requires Python 3.14+. Run tests per domain:

```bash
python -m pytest validators/schema/tests
python -m pytest validators/openapi/tests
python -m pytest validators/policy/tests
```

## License

See `LICENSE`.
