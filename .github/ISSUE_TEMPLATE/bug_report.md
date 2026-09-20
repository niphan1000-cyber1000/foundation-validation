---
name: Bug report
about: Something in the gate, a validator, or the reusable workflow isn't working right
title: "[BUG] "
labels: bug
assignees: ''
---

## What happened

<!-- A clear description of the bug -->

## Which domain is affected

- [ ] OpenAPI / Spectral (`validators/openapi/`)
- [ ] OPA / Policy (`validators/policy/`)
- [ ] Schema (`validators/schema/`)
- [ ] Security (`validators/security/`)
- [ ] Governance (`validators/governance/`)
- [ ] Traceability (`validators/traceability/`)
- [ ] Orchestrator (`validators/run_all.py`)
- [ ] Reusable workflow (`.github/workflows/reusable-gate.yml`)
- [ ] Other / not sure

## Steps to reproduce

<!-- Exact command(s) run, e.g.
python -m validators.run_all --spec openapi.yaml --schema-check schemas/x.schema.json=evidence/y.json
-->

## Expected behavior

## Actual behavior (include full error / traceback)

## Environment

- `foundation-validation` VERSION: <!-- from the VERSION file -->
- OS / shell:
- Called directly, or via `reusable-gate.yml` from a Studio repo?
