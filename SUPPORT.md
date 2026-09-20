# Support

## Getting Help

1. Read [README.md](README.md) — capabilities, OPA pin rationale, current status
2. Check [MASTER_INDEX.md](MASTER_INDEX.md) for navigation to validators and docs
3. Review [ROADMAP.md](ROADMAP.md) to see whether a gap is already planned
4. Open a **GitHub Discussion** (or Issue) on this repository for engine bugs,
   rule questions, or gate behavior

## Studio Integration Issues

If a **Studio** fails the foundation-validation gate:

1. Confirm the Studio workflow pins a tag (e.g. `@v1.0.0`), not `@main`
2. Confirm repo secret `FOUNDATION_PAT` can read both Foundation and this repo
3. Check the gate job logs for the specific validator domain (spectral / opa /
   schema / security / governance / traceability)
4. Open the issue on the **Studio** repository first; escalate here only if the
   engine or reusable workflow is at fault

## Platform Standards

Questions about *what* the rules should be (naming, security baseline, API
standards) belong in **CloudForge-Platform-Foundation**, not here.

This repository is the **engine that enforces** those standards — not the
source of the standards themselves.

## Security Issues

Do not file public issues for vulnerabilities. See [SECURITY.md](SECURITY.md).
