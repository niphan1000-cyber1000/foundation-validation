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

## Status

Not yet implemented. Planned engine: a JSON Schema 2020-12 validator
(e.g. `ajv` for Node.js tooling, or `jsonschema` for Python tooling),
run against every file under `schemas/` to self-check the engine's own
contracts, and against any target document the person requests via
`domains: ["schema"]`.
