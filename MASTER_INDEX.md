# Master Index — foundation-validation

> Navigation hub for the CloudForge Governance Control Plane & validation engine.
> Platform standards (what to enforce) live in
> [CloudForge-Platform-Foundation](https://github.com/CloudForge-Platform-Foundation-dev/CloudForge-Platform-Foundation).
> This repository implements **how** those standards are enforced in CI.

---

## Getting Started

| Document | Status | Description |
|----------|--------|-------------|
| [README.md](README.md) | ✅ Approved | Capabilities, production status, dual OPA pin rationale |
| [VERSION](VERSION) | ✅ Approved | Current release version |
| [CHANGELOG.md](CHANGELOG.md) | ✅ Approved | Release history |
| [ROADMAP.md](ROADMAP.md) | ✅ Approved | Planned work by phase |

## Governance & Contribution

| Document | Status | Description |
|----------|--------|-------------|
| [CONTRIBUTING.md](CONTRIBUTING.md) | ✅ Approved | Contribution workflow and PR requirements |
| [SECURITY.md](SECURITY.md) | ✅ Approved | Vulnerability reporting and security role of this repo |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | ✅ Approved | Community standards |
| [SUPPORT.md](SUPPORT.md) | ✅ Approved | Where to get help (engine vs Studio vs Foundation) |
| [LICENSE](LICENSE) | ✅ Approved | MIT |

## Core Configuration

| Path | Status | Description |
|------|--------|-------------|
| [gate_policy.yaml](gate_policy.yaml) | ✅ Approved | Per-validator on_fail / on_error actions (BLOCK / WARN / ALLOW) |
| [rules/registry.yaml](rules/registry.yaml) | ✅ Approved | Rule registry (SSOT for rule_id definitions) |
| [registry/rules.yaml](registry/rules.yaml) | ✅ Approved | Secondary / legacy rule listing — keep in sync |
| [policies/](policies/) | ✅ Approved | Rego policies evaluated by the gate (classic syntax) |
| [security/](security/) | ✅ Approved | Security Rego (`import rego.v1`) — unit-tested separately |

## Validators

| Domain | Path | Status | Description |
|--------|------|--------|-------------|
| Orchestrator | [validators/run_all.py](validators/run_all.py) | ✅ Approved | Single entry for CI and reusable gate |
| OpenAPI | [validators/openapi/](validators/openapi/) | ✅ Approved | Spectral lint + server URL policy |
| Policy (OPA) | [validators/policy/](validators/policy/) | ✅ Approved | OPA evaluation against Foundation policies |
| Schema | [validators/schema/](validators/schema/) | ✅ Approved | JSON Schema validation |
| Security | [validators/security/](validators/security/) | ✅ Approved | Secrets / sensitive-pattern scanning |
| Governance | [validators/governance/](validators/governance/) | ✅ Approved | Structure / ownership / version metadata (`GOV-DOC-*`) |
| Traceability | [validators/traceability/](validators/traceability/) | ✅ Approved | Evidence ↔ findings ↔ gate decision chain |

## CI / GitHub Actions

| Workflow | Status | Description |
|----------|--------|-------------|
| [.github/workflows/governance.yml](.github/workflows/governance.yml) | ✅ Approved | Self-validation of this repo |
| [.github/workflows/reusable-gate.yml](.github/workflows/reusable-gate.yml) | ✅ Approved | Called by Studio repos (`workflow_call`) |

## Evidence & Audit

| Path | Status | Description |
|------|--------|-------------|
| [evidence/](evidence/) | ✅ Approved | Sample / generated evidence artifacts (hashes, reports) |
| PowerShell helpers (`Invoke-*.ps1`) | ✅ Approved | Local/ops helpers for evidence, gate, governance, security, traceability |

## Design Decisions

| Document | Status | Description |
|----------|--------|-------------|
| [docs/decisions/2026-09-13-governance-namespace-fix.md](docs/decisions/2026-09-13-governance-namespace-fix.md) | ✅ Closed | Split document-level governance rules into `GOV-DOC-*` namespace |

## Repository Structure

```
foundation-validation
│
├── README.md
├── MASTER_INDEX.md          # This file
├── VERSION / CHANGELOG.md / LICENSE
├── SECURITY.md / CONTRIBUTING.md / CODE_OF_CONDUCT.md / SUPPORT.md / ROADMAP.md
│
├── gate_policy.yaml
├── rules/                   # Rule registry SSOT
├── registry/                # Secondary rule listing
├── policies/                # Classic Rego (OPA 0.55 in CI)
├── security/                # rego.v1 (OPA 1.19 in CI)
│
├── validators/              # Domain engines + run_all.py
├── evidence/
├── docs/decisions/
├── schemas/
├── scripts/
├── src/
├── tests/
└── .github/workflows/
    ├── governance.yml
    └── reusable-gate.yml
```

## Version Compatibility

| Engine version | Compatible Foundation | Studio workflow pin |
|----------------|----------------------|---------------------|
| v1.0.x | Foundation ≥ v0.1.0 | `@v1.0.0` (or matching tag) |

Studios must **not** pin `@main` for production gates.
