# validators/schema/

**Rule ID prefix:** `SCH-`

## Scope

Validates that a JSON/YAML target conforms to the JSON Schemas published
in [`/schemas`](../../schemas). This is the domain that enforces the
contract of the validation engine's own inputs and outputs (e.g. does an
incoming `ValidationRequest` payload actually match
`validation-request.schema.json`), as well as any other structured
document the engine is asked to validate.

## Input

- `target.type`: typically `artifact` or `api_contract`
- `target.reference` / `target.location`: path or URI to the JSON/YAML document to check
- A schema identifier (which `schemas/*.schema.json` file to validate against)

## Output

One `Finding` per schema violation, `severity` driven by how the violation
affects downstream consumers:

| Violation | Suggested severity |
|---|---|
| Required field missing | HIGH |
| Wrong type / enum value not allowed | HIGH |
| Pattern / format violation (e.g. malformed hash, bad date-time) | MEDIUM |
| Unknown additional property (when `additionalProperties: false`) | MEDIUM |
| Missing `examples`/`description` on a schema property | LOW |

Evidence for each finding should be the offending JSON Pointer path plus
the schema validation error message (`type: log` or `type: diff`).

## Status: Implemented (v0.1.0)

A working engine ships in this folder:

| File | Purpose |
|---|---|
| `schema_engine.py` | Standalone JSON Schema (2020-12 subset) validator, stdlib-only. Supports every keyword used across `/schemas`: `type`, `required`, `properties`, `additionalProperties`, `enum`, `items`, `minItems`, `uniqueItems`, `pattern`, `format` (`date-time`, `uri-reference`), local `$ref`/`$defs`, `oneOf`, `allOf`, `if`/`then`/`else`, `const`, `minimum`, `minLength`. Unsupported keywords raise `NotImplementedError` loudly rather than being silently skipped. |
| `rules.json` | The `SCH-001`..`SCH-005` rule registry (feeds `GET /v1/rules`), matching the severity table below. |
| `run.py` | CLI: `python3 run.py --schema <path> --target <path>`. Validates a JSON/YAML target against a schema and prints `Finding`/`Evidence` records shaped per `schemas/validation-result.schema.json` and `schemas/validation-evidence.schema.json`. Exit code `0` (pass), `1` (fail), `2` (usage/engine-gap error). |
| `tests/` | `unittest` suite: RED/GREEN pairs for all three schemas plus CLI-output shape checks. Run with `python3 -m unittest discover -s tests -v` from this folder. |

### Why a hand-rolled engine

This environment has no network access to install `ajv` or `jsonschema`,
and none were pre-installed. Rather than fake the validator or skip it,
`schema_engine.py` implements exactly the keyword subset the three
schemas in `/schemas` actually use — nothing more. If a future schema
change introduces an unsupported keyword, the engine fails loudly
(`NotImplementedError`) instead of quietly under-validating. If/when
network access is available, swapping in `jsonschema` (Python) is a
drop-in replacement behind the same `validate(instance, schema)` call.

### Known limitation

`format: uri-reference` is checked only as "non-empty string" — full
RFC 3986 validation isn't implemented. This is a deliberate scope cut,
not an oversight; tighten it if `content_ref` values start slipping
through with real formatting problems.

