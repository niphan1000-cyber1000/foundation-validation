# validators/traceability/

**Rule ID prefix:** `TRC-`

## Scope

Validates the completeness of the traceability chain defined in the
Foundation Validation Spec (Section 6): every mandatory rule must map
back to a `requirement_id`, and that mapping's `coverage_status` must be
`COVERED` — never `NOT_COVERED`, and `PARTIAL` only where explicitly
accepted.

This domain doesn't check the *target* being validated directly — it
checks the *validation engine's own rule registry* for gaps, which is
why it's listed last in the Exit Criteria (Section 7, item 5).

## Input

- The current rule registry (as returned by `GET /v1/rules`)
- The requirement/standard catalogue each rule is expected to map to

## Output

One `Finding` per traceability gap:

| Violation | Suggested severity |
|---|---|
| Mandatory rule has `coverage_status: NOT_COVERED` | HIGH |
| Mandatory rule has `coverage_status: PARTIAL` without a documented reason | MEDIUM |
| Rule references a `requirement_id` that doesn't exist in the catalogue | MEDIUM |
| Requirement has no rule mapped to it at all | LOW (informational until it's declared mandatory) |

Evidence should include the traceability matrix snapshot at the time of
the check (`type: snapshot`).

## Status: Implemented (v0.1.0) and wired into `validators/run_all.py`

| File | Purpose |
|---|---|
| `traceability_engine.py` | `check_traceability(registry, requirements)` — cross-references the rule registry (`rules/registry.yaml`, as loaded by `run_all.load_registry`) against the requirement catalogue (`rules/requirements.json`, as loaded by `run_all.load_requirements`) and returns `TRC-001`..`TRC-004` findings in the same unified shape `openapi_engine`/`policy_engine` produce. |
| `rules.json` | The `TRC-001`..`TRC-004` rule registry, matching the severity table above. |
| `run.py` | Standalone CLI: `python3 run.py --registry <path> --requirements <path>`. |
| `../../rules/requirements.json` | The requirement catalogue itself — resolved the "TBD location" open item by putting it alongside `rules/registry.yaml`. Starts empty (`"requirements": []`); populate it as rules gain real requirement mappings. |

### The requirement catalogue doesn't exist yet in practice

As of registry v1.2.0, every rule in `rules/registry.yaml` has
`requirement_id: null` (see that file's own header comments) and
`rules/requirements.json` ships empty. Running this domain today will
therefore report a `TRC-001` (HIGH) finding for every rule that is both
`status: active` and `gate_behavior: FAIL` — that's the actual, current
state of this repo's traceability, not an engine bug.

Because of that, `run_all.py` treats this domain as **opt-in**: it only
runs when called with `--check-traceability` (or
`enable_traceability=True` / `traceability_json_data=...` when calling
`run_all_validations()` directly), and is `SKIPPED` otherwise. Turn it on
once you're ready to either start populating `requirement_id`s or accept
the resulting findings as a tracked backlog.

### "Mandatory rule" is a proxy, not a registry field

`rules/registry.yaml` has no explicit `mandatory` flag today. This engine
treats a rule as mandatory when it is both `status: active` and
`gate_behavior: FAIL` — i.e. a rule that can actually block a release.
`WARN`/`INFO`-gated rules are informational-only and aren't (yet) held to
the same traceability bar. If a `mandatory` field is ever added to the
registry schema directly, swap this proxy out in `_is_mandatory()`.
