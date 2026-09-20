# Roadmap — foundation-validation

## Phase 1: Production Gate (Current — v1.0.x)

- [x] Hard gate / fail-closed CI enforcement
- [x] Rule registry as SSOT
- [x] Evidence integrity (SHA-256)
- [x] Validators: OpenAPI, OPA/policy, schema, security, governance, traceability
- [x] Reusable workflow for Studios (`reusable-gate.yml`)
- [x] Dual OPA pins documented (classic vs `rego.v1`)
- [x] Governance namespace split (`GOV-DOC-*`)
- [x] Standard repository files (VERSION, LICENSE, SECURITY, CONTRIBUTING, …)

## Phase 2: Studio Experience

- [ ] Support multiple OpenAPI specs per gate call
- [ ] Allow Studio-provided `gate_policy.yaml` overrides (with Foundation-imposed floor on critical rules)
- [ ] SARIF upload of Spectral / security findings to GitHub Code Scanning
- [ ] Clearer human-readable gate summary comment on PRs
- [ ] Documented migration guide when bumping major engine versions

## Phase 3: Supply Chain & Hardening

- [ ] Dependency vulnerability scanning in CI (pip / npm tools used by validators)
- [ ] Signed release tags / attestations for reusable workflow consumers
- [ ] Periodic review of OPA and Spectral pins; plan unified OPA major when policies migrate to `rego.v1`
- [ ] Remove or archive the root `.md` stub file if still present

## Phase 4: Observability

- [ ] Structured metrics export (pass/fail counts by domain and rule_id)
- [ ] Optional evidence store integration beyond local `evidence/` files
- [ ] Dashboard-friendly JSON report schema versioning

## Phase 5: Ecosystem Alignment

- [ ] Keep registry rule_ids in lockstep with Foundation policy docs
- [ ] Shared test fixtures published for Studio authors (good/bad OpenAPI examples already present)
- [ ] Optional local CLI wrapper so developers can run the same gate offline before push

---

**Guiding principle:** Prefer a narrow, reliable MVP gate over a wide, flaky one.
Expand scope only after Studios run cleanly on pinned `@v1` tags.
