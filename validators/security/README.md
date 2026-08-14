# validators/security/

**Rule ID prefix:** `SEC-`

> **Naming note:** this folder is distinct from the top-level
> [`/security`](../../security) folder, which holds the raw OPA/Rego
> policy source (`policy.rego`, `security-policies.rego`). This folder
> (`validators/security/`) is where those policies get *wrapped* and
> their output reshaped into the `Finding`/`Evidence` contract so the
> engine can report on them uniformly alongside every other domain.

## Scope

Validates a target for security issues: hardcoded secrets, dependency
vulnerabilities (CVEs), infrastructure-as-code misconfiguration, and
authorization/policy checks such as those in the top-level `security/`
Rego packages.

## Input

- `target.type`: any (`repository`, `commit`, `artifact`, `infrastructure_config`)
- `target.reference` / `target.location`: what to scan

## Output

One `Finding` per issue found:

| Violation | Suggested severity |
|---|---|
| Hardcoded secret / credential in tracked files | CRITICAL |
| Remote-code-execution-class vulnerability, missing auth on a sensitive endpoint | CRITICAL |
| Known CVE with high/critical CVSS in a dependency | HIGH |
| IaC misconfiguration (e.g. public storage bucket, open security group) | HIGH |
| Known CVE with medium CVSS | MEDIUM |
| Best-practice deviation (e.g. missing rate limiting) | LOW |

Evidence should reference the scanner's raw report (`type:
external_report`) plus, where relevant, the specific file/line
(`type: snapshot`).

## Status

Not yet implemented. Planned engine: a secret scanner (e.g. `gitleaks`), a
dependency/CVE scanner (e.g. `trivy fs`), and an OPA evaluation step that
runs `opa eval` against `security/policy.rego` and
`security/security-policies.rego`, translating `allow`/`deny_*` decisions
into `Finding` records.
