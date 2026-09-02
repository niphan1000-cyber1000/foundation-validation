
# Governance Control Plane & Foundation Validation

## Current Status: Production-Ready Gate & Validation Engine
This project has successfully evolved from a prototype stage into a fully implemented **Governance Control Plane** featuring active validation engines and automated gate enforcement.

### Key Capabilities Implemented:
1. **Hard Gate & CI/CD Enforcement:** Verified via failure-injection testing to ensure strict PR blocking and fail-closed behavior on critical violations.
2. **Rule Registry (Single Source of Truth):** Centralized rule definitions managed via `rules/registry.yaml`.
3. **Evidence Integrity:** Automated SHA-256 hash calculation of input artifacts stored securely in `evidence/`.
4. **Real Validators:**
   - **Security Validator:** Active scanning for sensitive data and secrets.
   - **Governance Validator:** Policy and structure validation against organizational rules.
5. **End-to-End Traceability:** Complete audit trail connecting artifact hashes, validator findings, gate decisions, and CI exit codes.

## Pinned Tool Versions

### OPA (Open Policy Agent)

CI installs **two different pinned OPA binaries**, one per job, in
`.github/workflows/governance.yml`. This is intentional, not drift:

| CI job | OPA version | Evaluates | Why this version |
|---|---|---|---|
| `validate` | `v0.55.0` | `policies/*.rego` (`package governance.api`) via `opa eval --data policies/ ... data.governance.api.deny`, called from `validators/run_all.py::_invoke_opa` | These files use classic (pre-`rego.v1`) Rego syntax. This is the real spec-validation gate — do not bump without re-validating `policies/*.rego` against the newer engine first. |
| `security-policy-unit-tests` | `v1.19.0` | `security/*.rego` (`package main`, `package policies.security`) via `opa test security/ -v` | These files use `import rego.v1`, which requires OPA ≥ 0.59.0. This job only unit-tests that Rego logic in isolation — see the note at the top of `security/policy.rego` for why it is *not* the same as being enforced by the gate. |

Each job installs its own binary, so the two versions never conflict at
runtime. If you upgrade one, check the corresponding `.rego` files still
parse/evaluate cleanly under the new version before merging — `policies/`
and `security/` are not required to move in lockstep.

