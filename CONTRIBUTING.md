# Contributing to foundation-validation

> Thank you for investing your time in the CloudForge Governance Control Plane.

---

## Contribution Workflow

```
Issue / Proposal
        │
        ▼
Design note (docs/decisions/ or ADR if cross-cutting)
        │
        ▼
Implementation + unit tests under validators/*/tests/
        │
        ▼
Local run: python validators/run_all.py  (and relevant domain tests)
        │
        ▼
Pull Request
        │
        ▼
governance.yml CI must pass (validate + security-policy-unit-tests)
        │
        ▼
Review & Approval (treat gate/policy changes as security-sensitive)
        │
        ▼
Merge into main → tag release if consumer-facing (e.g. v1.0.1)
```

---

## Pull Request Requirements

Before submitting a PR, verify:

- [ ] Domain tests updated under the relevant `validators/<domain>/tests/`
- [ ] Rule IDs registered in `rules/registry.yaml` (and `registry/rules.yaml` if applicable)
- [ ] No conflicting `rule_id` definitions across registry paths
- [ ] `CHANGELOG.md` updated
- [ ] `VERSION` bumped for consumer-facing or breaking gate behavior changes
- [ ] OPA / Spectral version pins left intentional (see README dual-OPA note)
- [ ] `gate_policy.yaml` changes called out explicitly in the PR description
- [ ] No hardcoded secrets or credentials
- [ ] CI (`governance.yml`) passes

---

## Working on Validators

| Domain | Path | Notes |
|--------|------|--------|
| OpenAPI / Spectral | `validators/openapi/` | Lints Studio `openapi.yaml` against Foundation `.spectral.yaml` |
| OPA / Policy | `validators/policy/` | Evaluates Rego under Foundation `policies/` (classic syntax → OPA 0.55) |
| Schema | `validators/schema/` | JSON Schema checks |
| Security | `validators/security/` | Secrets / sensitive-pattern scanning |
| Governance | `validators/governance/` | Structure / ownership / version metadata (`GOV-DOC-*`) |
| Traceability | `validators/traceability/` | Evidence ↔ findings ↔ gate decision chain |
| Orchestrator | `validators/run_all.py` | Single entry used by CI and the reusable gate |

When adding a **new rule_id**, update the registry and add at least one positive
and one negative test fixture.

---

## Reusable Gate Contract

Studios call:

```yaml
jobs:
  gate:
    uses: <owner>/foundation-validation/.github/workflows/reusable-gate.yml@v1.0.0
    with:
      spec_path: openapi.yaml
    secrets:
      foundation_pat: ${{ secrets.FOUNDATION_PAT }}
```

Breaking changes to inputs, outputs, or default BLOCK behavior require a
**major** version bump and a migration note in `CHANGELOG.md`.

Prefer **pinned tags** (`@v1.0.0`), not `@main`, in every Studio workflow.

---

## OPA Version Pins

Do not “unify” the two OPA versions without re-validating both trees:

- `policies/` → classic Rego → CI job uses **OPA v0.55.0**
- `security/` → `import rego.v1` → CI job uses **OPA v1.19.0**

See the table in [README.md](README.md).

---

## Documentation

- Update [MASTER_INDEX.md](MASTER_INDEX.md) when adding top-level docs or validators
- Significant design choices → `docs/decisions/YYYY-MM-DD-short-title.md`
- Cross-ecosystem standards still live in **CloudForge-Platform-Foundation**

---

## Security

See [SECURITY.md](SECURITY.md). Softening a critical `on_fail: BLOCK` rule is a
security-sensitive change and must be called out in the PR.
