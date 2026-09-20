## Summary

<!-- What does this PR change and why? -->

## Type of change

- [ ] Bug fix
- [ ] New validator / rule
- [ ] Gate / policy behavior change (security-sensitive — see below)
- [ ] Documentation only
- [ ] CI / workflow change

## Checklist

(mirrors [CONTRIBUTING.md](CONTRIBUTING.md) > Pull Request Requirements)

- [ ] Domain tests updated under the relevant `validators/<domain>/tests/`
- [ ] Rule IDs registered in `rules/registry.yaml` (and `registry/rules.yaml` if applicable)
- [ ] No conflicting `rule_id` definitions across registry paths
- [ ] `CHANGELOG.md` updated
- [ ] `VERSION` bumped for consumer-facing or breaking gate behavior changes
- [ ] OPA / Spectral version pins left intentional (see README dual-OPA note)
- [ ] `gate_policy.yaml` changes called out explicitly below, if any
- [ ] No hardcoded secrets or credentials
- [ ] CI (`governance.yml`) passes

## Security-sensitive change?

<!--
Per SECURITY.md, changes to validators/security/, security/*.rego, gate_policy.yaml
(BLOCK → WARN/ALLOW), reusable-gate.yml/governance.yml, or evidence/hashing logic
require explicit review. If this PR touches any of those, describe the change
and its impact here. If not, write "N/A".
-->

## Related issue(s)

<!-- Closes #... -->
