# Changelog

All notable changes to foundation-validation will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Standard repository files aligned with CloudForge Platform Foundation checklist
  (`VERSION`, `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  `SUPPORT.md`, `MASTER_INDEX.md`, `ROADMAP.md`)

## [1.0.0] - 2026-09-18

### Added
- Production-ready Governance Control Plane and validation engine
- Hard gate / CI/CD enforcement with fail-closed behavior on critical violations
- Rule registry as single source of truth (`rules/registry.yaml`, `registry/rules.yaml`)
- Evidence integrity via SHA-256 hashes under `evidence/`
- Validators: OpenAPI (Spectral), OPA/policy, schema, security, governance, traceability
- Reusable GitHub Actions workflow: `.github/workflows/reusable-gate.yml`
- Self-validation workflow: `.github/workflows/governance.yml`
- Gate policy (`gate_policy.yaml`) with per-validator BLOCK / WARN actions
- PowerShell helpers for evidence, gate, governance, security, and master traceability checks
- Decision record: governance namespace split (`GOV-DOC-*`) — docs/decisions/2026-09-13-governance-namespace-fix.md

### Notes
- OPA is intentionally pinned to two versions in CI:
  - `v0.55.0` for classic Rego under `policies/`
  - `v1.19.0` for `import rego.v1` under `security/`
- Studios should call the reusable gate at a **pinned tag** (e.g. `@v1.0.0`), not `@main`

## Migration Guides

### Upgrading to v1.0.0

No breaking consumer contract for Studios already on `reusable-gate.yml@v1`
with `engine_ref` pinned. Prefer pinning the workflow to `@v1.0.0` (or the
matching tag) instead of a branch name.
