# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| v1.0.x  | ✅ Yes    |
| < v1.0  | ❌ No     |

## Reporting a Vulnerability

Please **DO NOT** open a public issue for security vulnerabilities.

Instead:
1. Email: niphan1000@gmail.com
2. Or use GitHub Security Advisories on this repository

We will respond within 48 hours.

## Security Role of This Repository

`foundation-validation` is the **Governance Control Plane** for the CloudForge
ecosystem. It does not hold customer data, but it does:

- Enforce security and governance rules on Studio OpenAPI specs and policies
- Scan for secrets / sensitive patterns (Security Validator)
- Produce evidence and audit trails used in CI gates

A compromise or false-negative here can weaken every Studio that depends on the
reusable gate. Treat changes to validators, policies, and the gate workflow as
security-sensitive.

## Security Standards

Aligned with CloudForge Platform Foundation
(`docs/security/security-baseline.md`):

- [x] Fail-closed gate behavior on critical validator failures (`gate_policy.yaml`)
- [x] No hardcoded secrets in source; CI secrets via GitHub Actions secrets only
- [x] Security validator domain for sensitive-data / secret pattern checks
- [x] Evidence integrity (SHA-256 of input artifacts under `evidence/`)
- [x] Pinned tool versions in CI (OPA, Spectral) to reduce supply-chain drift
- [ ] Dependency vulnerability scanning in CI (tracked in ROADMAP)
- [ ] SARIF upload of findings to GitHub Code Scanning (tracked in ROADMAP)

## Security Review Process

Security reviews are mandatory for:

- Changes to `validators/security/`, `security/*.rego`, or security rule IDs
- Changes to `gate_policy.yaml` that soften BLOCK → WARN/ALLOW for critical domains
- Changes to `.github/workflows/reusable-gate.yml` or `governance.yml`
- New external dependencies or CI tool version bumps (especially OPA / Spectral)
- Anything that alters evidence hashing or audit trail semantics

## Threat Model (summary)

| Threat | Mitigation |
|--------|------------|
| Studio bypasses the gate | Reusable workflow is the only supported entry; Studios must call pinned `@v1`+ |
| Softened policy in a PR | CODEOWNERS + required reviewers; fail-closed defaults in `gate_policy.yaml` |
| Supply-chain / tool drift | Pin OPA and Spectral versions in workflows; document dual-OPA rationale in README |
| Evidence tampering | SHA-256 of artifacts recorded under `evidence/` and linked in traceability reports |

For the platform-wide threat model, see
[CloudForge-Platform-Foundation/docs/security/security-baseline.md](https://github.com/CloudForge-Platform-Foundation-dev/CloudForge-Platform-Foundation/blob/main/docs/security/security-baseline.md).
