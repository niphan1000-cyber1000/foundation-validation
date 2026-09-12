from validators.security.security_engine import run_security_scan
"""
run_all.py â€” Foundation Validation Engine master gate.

Aggregates findings from the OpenAPI (Spectral) and Policy (OPA) domains,
resolves each finding's severity/gate_behavior against rules/registry.yaml
(the single source of truth for rule metadata), and produces a single
ValidationResultContract object matching schemas/validation-result.schema.json.

Two entry points:
  * run_all_validations(...)  â€” importable function, used by tests and by
    anything that wants to inject already-fetched tool output (openapi_json_data /
    opa_json_data) instead of shelling out to spectral/opa. This is what
    validators/tests/test_aggregator.py exercises.
  * CLI (`python run_all.py --spec ...`) â€” the real gate used by CI and the
    pre-commit hook. It invokes Spectral and OPA itself, then calls
    run_all_validations() with the live output.

Fail-safe rules this module follows (see validators/README.md and
validators/schema/schema_engine.py for the same philosophy elsewhere in
this repo):
  * A missing/unreadable --spec file is a hard error, not a silent PASS.
  * A tool (spectral/opa) that can't be invoked is a hard ERROR, not a
    silent "no findings".
  * A rule_id with no entry in rules/registry.yaml still gets a fail-safe
    default gate_behavior based on severity â€” it is never silently ignored.
"""

import argparse
import hashlib
import json
import shutil
import sys
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None

BASE_DIR = Path(__file__).resolve().parent
for sub in ("openapi", "policy", "schema", "traceability", "security"):
    p = str(BASE_DIR / sub)
    if p not in sys.path:
        sys.path.insert(0, p)

from openapi_engine import parse_spectral_output, SpectralOutputError  # noqa: E402
from policy_engine import parse_opa_output, PolicyOutputError  # noqa: E402
from schema_engine import validate as _validate_schema  # noqa: E402
from traceability_engine import check_traceability as _check_traceability  # noqa: E402
from validators.security.security_engine import run_security_scan as _scan_security
from validators.governance.governance_engine import run_governance_scan as _scan_governance
from validators.governance.governance_engine import run_governance_scan as _scan_governance  # noqa: E402

PLATFORM_VERSION = "1.0.0"

# Fail-safe default gate_behavior for a rule_id that has no entry in the
# registry, keyed by the severity the tool itself reported. Registered
# rules always take their gate_behavior from the registry instead.
_DEFAULT_GATE_BEHAVIOR_BY_SEVERITY = {
    "CRITICAL": "FAIL",
    "HIGH": "FAIL",
    "MEDIUM": "WARN",
    "LOW": "INFO",
}

# Gate policies: how an environment may relax a rule's registry-defined
# gate_behavior. Only a downgrade of HIGH/FAIL -> WARN is currently
# supported for the "dev" environment; CRITICAL always blocks regardless
# of environment, and "production" applies the registry as-is.
GATE_POLICIES = {
    "production": {},
    "dev": {("HIGH", "FAIL"): "WARN"},
}


def load_registry(registry_path="rules/registry.yaml,registry/rules.yaml"):
    """Load one or more rule registries into a single {rule_id: rule_dict}
    map. `registry_path` may be a single path or a comma-separated list of
    paths (e.g. "rules/registry.yaml,../foundation/rules/registry.yaml"),
    so a Studio gate can merge this engine's own bundled registry with an
    external SSOT registry (e.g. Foundation's) that documents rule_ids
    from a ruleset/policy-dir this engine doesn't own.

    Paths are loaded in order and merged; a rule_id defined in a later
    path overrides the same rule_id from an earlier path, so callers
    should list the more-authoritative registry last (Foundation's, for
    an external SSOT, after this engine's own).

    A missing file is not a hard error (a Studio may not have an external
    registry yet) but IS logged to stderr, since a silently-missing
    registry is exactly what caused every finding to fall through to the
    fail-safe default in the past — that fallback should be a visible,
    logged event, not a silent one.

    Returns {} only if no path resolves to any rules at all (fail-safe
    severity-based defaults then apply to every finding; see
    _resolve_finding)."""
    if not yaml:
        return {}
    rules = {}
    paths = [p.strip() for p in str(registry_path).split(",") if p.strip()]
    for raw_path in paths:
        path = Path(raw_path)
        if not path.exists():
            print(f"WARNING: registry file not found, skipping: {path}", file=sys.stderr)
            continue
        with open(path, "r", encoding="utf-8-sig") as f:
            data = yaml.safe_load(f) or {}
        for rule in data.get("rules", []):
            rules[rule.get("rule_id") or rule.get("id")] = rule
    return rules


def load_requirements(requirements_path="rules/requirements.json"):
    """Load the requirement catalogue used by the traceability domain into
    a {requirement_id: requirement_dict} map.

    Mirrors load_registry()'s fail-safe philosophy: a missing catalogue
    file is not a hard error (most repos won't have adopted one yet) but
    IS logged to stderr, and returns {} â€” which check_traceability()
    treats as "no catalogue exists", never as "everything is covered".
    """
    path = Path(requirements_path)
    if not path.exists():
        print(f"WARNING: requirement catalogue not found, skipping: {path}", file=sys.stderr)
        return {}
    with open(path, "r", encoding="utf-8-sig") as f:
        data = json.load(f) or {}
    return {r.get("requirement_id"): r for r in data.get("requirements", [])}


# Maps a schema_engine.SchemaError's `keyword` to the SCH- rule_id it
# corresponds to, per validators/schema/README.md's severity table.
# Duplicated (not imported) from validators/schema/run.py: that module's
# copy is the CLI-facing one, this is the aggregator-facing one, and
# keeping this a plain literal here avoids run_all.py depending on
# schema/run.py's argparse-oriented module just to reuse one dict.
_SCHEMA_KEYWORD_TO_RULE = {
    "required": "SCH-001",
    "type": "SCH-002",
    "enum": "SCH-002",
    "const": "SCH-002",
    "pattern": "SCH-003",
    "format": "SCH-003",
    "minLength": "SCH-003",
    "minimum": "SCH-003",
    "minItems": "SCH-003",
    "uniqueItems": "SCH-003",
    "additionalProperties": "SCH-004",
    "oneOf": "SCH-005",
    "allOf": "SCH-005",
}


def _load_schema_rule_severities():
    """Reads validators/schema/rules.json for SCH- rule severities, so
    schema-domain findings carry the same severity the schema/ folder's
    own CLI (run.py) would report, instead of a hardcoded guess here."""
    path = BASE_DIR / "schema" / "rules.json"
    try:
        with open(path, "r", encoding="utf-8") as f:
            rules = json.load(f)
        return {r["rule_id"]: r.get("severity", "MEDIUM") for r in rules}
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _run_schema_check(schema_path, target_path):
    """Validate target_path against schema_path using the stdlib-only
    engine in validators/schema/schema_engine.py, and return findings in
    the same unified shape openapi_engine/policy_engine produce (so
    run_all_validations can merge them into one findings list untouched).

    Raises on any load/validate problem (missing file, bad JSON/YAML, or
    a schema keyword schema_engine.py doesn't support) rather than
    swallowing it â€” same fail-safe rule as every other domain in this
    file: a check that couldn't actually run is a system ERROR, never a
    silent pass.
    """
    schema_path = Path(schema_path)
    target_path = Path(target_path)

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    text = target_path.read_text(encoding="utf-8")
    if target_path.suffix in (".yaml", ".yml"):
        if not yaml:
            raise RuntimeError("PyYAML is required to validate a YAML target but is not installed")
        instance = yaml.safe_load(text)
    else:
        instance = json.loads(text)

    errors = _validate_schema(instance, schema)
    severities = _load_schema_rule_severities()
    findings = []
    for err in errors:
        rule_id = _SCHEMA_KEYWORD_TO_RULE.get(err.keyword, "SCH-003")
        findings.append({
            "rule_id": rule_id,
            "severity": severities.get(rule_id, "MEDIUM"),
            "category": "schema",
            "message": f"[{err.keyword}] at {err.path}: {err.message}",
            "location": {
                "file": str(target_path),
                "path": err.path,
                "line": 0,
            },
        })
    return findings


def _resolve_finding(finding, registry, environment):
    """Attach severity/gate_behavior/effective_gate_behavior to a raw
    finding, using the registry as the source of truth when the rule is
    catalogued and a fail-safe severity-based default otherwise.

    The fail-safe default for an unregistered rule_id must still respect
    the severity the underlying tool (Spectral/OPA) itself reported,
    via _DEFAULT_GATE_BEHAVIOR_BY_SEVERITY — NOT a blanket CRITICAL/FAIL.
    A ruleset can carry many rules (e.g. the ~100 built-in spectral:oas
    rules) that will never all be individually catalogued in a registry;
    treating every one of those as CRITICAL/BLOCK the moment a Studio
    lints against a ruleset with a different naming scheme than this
    registry defeats the purpose of severity entirely and makes the gate
    behavior indistinguishable from "always BLOCK"."""
    rule_id = finding.get("rule_id", "") if isinstance(finding, dict) else str(finding)
    rule_meta = registry.get(rule_id)

    if rule_meta:
        severity = str(rule_meta.get("severity", finding.get("severity", "MEDIUM"))).upper()
        gate_behavior = str(rule_meta.get("gate_behavior", "FAIL")).upper()
        finding["rule_version"] = rule_meta.get("version", "0.0.0")
    else:
        # Fail-safe default for unknown/unregistered rules: trust the
        # tool's own reported severity and derive gate_behavior from it,
        # same as a catalogued rule would be treated at that severity.
        severity = str(finding.get("severity", "MEDIUM") if isinstance(finding, dict) else "MEDIUM").upper()
        if severity not in _DEFAULT_GATE_BEHAVIOR_BY_SEVERITY:
            severity = "MEDIUM"
        gate_behavior = _DEFAULT_GATE_BEHAVIOR_BY_SEVERITY[severity]
        finding["rule_version"] = "unknown"

    policy = GATE_POLICIES.get(environment, GATE_POLICIES["production"])
    effective_gate_behavior = policy.get((severity, gate_behavior), gate_behavior)

    # INVARIANT (Gate Cannot Be Cheated, adversarial review finding): a
    # registered rule's gate_behavior comes straight from rules/registry.yaml
    # above, verbatim, with no severity check. That means a registry entry
    # that declares `severity: CRITICAL, gate_behavior: WARN` -- whether
    # from a careless edit or a tampered SSOT -- was silently resolving to
    # effective_gate_behavior "WARN", i.e. a CRITICAL finding that would
    # NOT block. GATE_POLICIES' own comment already states "CRITICAL
    # always blocks regardless of environment" for environment-level
    # relaxation (the dev downgrade only ever targets HIGH); this clamp
    # makes that the same guarantee against a registry-level override too,
    # since both are just different sources for the same gate_behavior
    # value up to this point. This line, not the registry, is the trusted
    # guard: no combination of registry content can produce a non-FAIL
    # outcome for a CRITICAL finding.
    if severity == "CRITICAL":
        effective_gate_behavior = "FAIL"

    finding["severity"] = severity
    finding["gate_behavior"] = gate_behavior
    finding["effective_gate_behavior"] = effective_gate_behavior
    finding.setdefault("category", finding.get("category", "openapi"))
    return finding


def _resolve_executable(name):
    """Resolve a command name to a full, invokable path.

    shutil.which() checks PATHEXT on Windows (so it correctly finds e.g.
    npx.cmd for "npx"), which subprocess.run([name, ...]) does NOT do on
    its own when shell=False â€” that mismatch is what produced
    "WinError 2: The system cannot find the file specified" for a tool
    that clearly works fine when typed directly into PowerShell. Returns
    None if the tool truly isn't on PATH.
    """
    return shutil.which(name)


def _parse_leading_json(text, tool_name):
    """Parse the first well-formed JSON value at the start of `text` and
    ignore anything after it.

    Some CLI wrappers (notably `npx` on Windows, and sometimes OPA)
    print a valid JSON payload to stdout immediately followed by an
    unrelated notice/warning line with no separating newline â€” a plain
    json.loads() then fails with "Extra data" even though the tool's
    actual output was perfectly valid. json.JSONDecoder.raw_decode()
    parses only the leading value and reports where it ended, which is
    exactly what we need here; trailing bytes are logged, not treated as
    a parse failure.
    """
    decoder = json.JSONDecoder()
    try:
        value, end = decoder.raw_decode(text)
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"{tool_name} returned non-JSON output: {e}. "
            f"First 300 chars of stdout: {text[:300]!r}"
        ) from e

    trailing = text[end:].strip()
    if trailing:
        print(
            f"WARNING: {tool_name} printed {len(trailing)} extra characters "
            f"after its JSON output (ignored): {trailing[:200]!r}",
            file=sys.stderr,
        )
    return value


def _invoke_spectral(spec_path, ruleset_path=None):
    """Run Spectral CLI against spec_path and return its raw JSON findings
    list. Raises RuntimeError (system error, not a silent []) if Spectral
    can't be invoked at all.

    ruleset_path, when given, is passed through as `-r <path>` so callers
    (e.g. the reusable gate workflow, validating a Studio spec against a
    Foundation-owned .spectral.yaml) can point Spectral at a ruleset that
    isn't this repo's own bundled .spectral.yaml. When omitted, Spectral
    falls back to its normal auto-discovery behavior.
    """
    npx = _resolve_executable("npx")
    if not npx:
        raise RuntimeError("npx not found on PATH â€” is Node.js installed?")
    cmd = [npx, "--yes", "@stoplight/spectral-cli", "lint", str(spec_path), "-f", "json"]
    if ruleset_path is not None:
        cmd.extend(["-r", str(ruleset_path)])
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as e:
        raise RuntimeError(f"could not invoke Spectral CLI: {e}") from e

    stdout = (proc.stdout or "").strip()
    if not stdout:
        # A clean Spectral lint with `-f json` still prints "[]" â€” empty
        # stdout means the CLI itself didn't run (missing package, no
        # network, bad invocation, etc.), which is a system error, not
        # "no findings". Surface stderr so the real cause is visible.
        stderr = (proc.stderr or "").strip()
        raise RuntimeError(
            f"Spectral CLI produced no output (exit {proc.returncode}): {stderr[:500]}"
        )
    return _parse_leading_json(stdout, tool_name="Spectral CLI")


def _invoke_opa(spec_path, policy_dir="policies"):
    """Run `opa eval` against spec_path using the Rego policies in
    policy_dir and return the raw OPA JSON result. Raises RuntimeError if
    OPA can't be invoked. If policy_dir doesn't exist, the policy domain is
    treated as NOT_APPLICABLE (returns None), not as a finding source."""
    if not Path(policy_dir).exists():
        return None
    opa = _resolve_executable("opa")
    if not opa:
        raise RuntimeError("opa not found on PATH â€” is OPA CLI installed?")
    try:
        proc = subprocess.run(
            [opa, "eval", "--data", policy_dir, "--input", str(spec_path),
             "data.governance.api.deny", "--format", "json"],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as e:
        raise RuntimeError(f"could not invoke OPA CLI: {e}") from e

    stdout = (proc.stdout or "").strip()
    if not stdout:
        stderr = (proc.stderr or "").strip()
        raise RuntimeError(
            f"OPA CLI produced no output (exit {proc.returncode}): {stderr[:500]}"
        )
    parsed = _parse_leading_json(stdout, tool_name="OPA CLI")

    # `opa eval` reports Rego compile/parse errors as a 0-exit-code JSON
    # payload shaped {"errors": [...]}, NOT as {"result": [...]}. Treating
    # that as "zero violations found" would silently turn a broken policy
    # file into a clean pass â€” the opposite of this project's fail-safe
    # design (a tool that can't actually evaluate the policy is a hard
    # ERROR, same as a missing/uninvokable binary).
    if isinstance(parsed, dict) and parsed.get("errors"):
        first_err = parsed["errors"][0] if parsed["errors"] else {}
        loc = first_err.get("location", {}) if isinstance(first_err, dict) else {}
        where = f"{loc.get('file', policy_dir)}:{loc.get('row', '?')}" if loc else policy_dir
        message = first_err.get("message", "unknown error") if isinstance(first_err, dict) else str(first_err)
        raise RuntimeError(f"OPA policy failed to compile/evaluate at {where}: {message}")

    return parsed


def run_all_validations(
    spec_path=None,
    registry_path="rules/registry.yaml,registry/rules.yaml",
    openapi_json_data=None,
    opa_json_data=None,
    policy_dir="policies",
    ruleset_path=None,
    environment="production",
    schema_checks=None,
    schema_json_data=None,
    enable_traceability=False,
    requirements_path="rules/requirements.json",
    traceability_json_data=None,
    security_target=None,
    security_json_data=None,
    governance_target=None,
    governance_json_data=None,
):
    """Aggregate the OpenAPI, Policy, Schema, and Traceability domains
    into a single ValidationResultContract-shaped dict.

    openapi_json_data / opa_json_data / schema_json_data /
    traceability_json_data let callers (tests, or the CLI after it has
    already produced raw domain output itself) inject already-computed
    findings instead of this function invoking the underlying tool/engine
    itself. When none of the four domains has either injected data or the
    input it needs to run (spec_path for openapi/policy, schema_checks for
    schema, enable_traceability=True for traceability), that domain is
    SKIPPED â€” with an empty spec_path/schema_checks and
    enable_traceability=False this is an empty PASS, which is what lets
    run_all_validations() be called with no arguments in unit tests.

    ruleset_path, when given, is forwarded to _invoke_spectral so the spec
    is linted against an external ruleset (e.g. a Foundation repo's
    .spectral.yaml) instead of this repo's own bundled one. Ignored when
    openapi_json_data is injected directly.

    schema_checks, when given, is a list of {"schema": path, "target":
    path} dicts; each pair is validated via validators/schema's engine and
    the resulting findings merged in. This domain is unlike the others in
    that it has no single natural "target" (see validators/schema/README.md)
    so it's opt-in per invocation rather than tied to spec_path.

    enable_traceability, when True, runs the traceability domain against
    the already-loaded rule registry and the requirement catalogue at
    requirements_path. It defaults to False: as of registry v1.2.0 every
    rule's requirement_id is null, so turning this on will immediately
    surface a TRC-001 HIGH finding (and therefore a FAILED gate in
    production) for every currently active FAIL-gated rule â€” a real,
    pre-existing gap, not a bug, but one this function won't spring on a
    caller who hasn't opted in. See traceability_engine.py.
    """
    registry = load_registry(registry_path)
    domains_status = {}
    findings = []
    artifacts = []
    system_errors = []

    # --- OpenAPI / Spectral domain ---
    if openapi_json_data is not None:
        raw = openapi_json_data
        domains_status["openapi"] = "RUN"
    elif spec_path is not None:
        try:
            raw = _invoke_spectral(spec_path, ruleset_path=ruleset_path)
            domains_status["openapi"] = "RUN"
        except Exception as e:
            # Deliberately broad (not just RuntimeError): a genuine bug in
            # _invoke_spectral (e.g. an unexpected exception type) must
            # still resolve to a reported domain ERROR with evidence, not
            # an uncaught traceback that aborts run_all_validations()
            # before evidence collection in src/cli.py ever runs -- see
            # tests/test_gate_cannot_be_cheated.py's "validator crash" case.
            raw = []
            domains_status["openapi"] = "ERROR"
            system_errors.append(f"openapi: {e}")
    else:
        raw = None
        domains_status["openapi"] = "SKIPPED"

    if raw is not None:
        try:
            openapi_findings = parse_spectral_output(raw, target_path=str(spec_path or ""))
        except Exception as e:
            # Deliberately broad, not just SpectralOutputError: a crash
            # while parsing (e.g. a malformed item inside an otherwise
            # well-formed array) must fail the domain the same way a
            # recognized bad-shape error does, not propagate as an
            # uncaught exception. See the "validator crash" /
            # "malformed JSON" rows in tests/test_gate_cannot_be_cheated.py
            # and validators/tests/test_adversarial_matrix.py.
            openapi_findings = []
            domains_status["openapi"] = "ERROR"
            system_errors.append(f"openapi: {e}")
        for f in openapi_findings:
            f["category"] = "openapi"
        findings.extend(openapi_findings)
        artifacts.append({
            "domain": "openapi",
            "target_file": str(spec_path or "injected"),
            "rule_count": len(openapi_findings),
        })

    # --- Policy / OPA domain ---
    if opa_json_data is not None:
        raw_opa = opa_json_data
        domains_status["policy"] = "RUN"
    elif spec_path is not None:
        try:
            raw_opa = _invoke_opa(spec_path, policy_dir=policy_dir)
            domains_status["policy"] = "RUN" if raw_opa is not None else "NOT_APPLICABLE"
        except Exception as e:
            raw_opa = None
            domains_status["policy"] = "ERROR"
            system_errors.append(f"policy: {e}")
    else:
        raw_opa = None
        domains_status["policy"] = "SKIPPED"

    if raw_opa is not None:
        try:
            policy_findings = parse_opa_output(raw_opa, target_path=str(spec_path or ""))
        except Exception as e:
            # Deliberately broad, not just PolicyOutputError -- see the
            # matching comment on the openapi domain's parse step above.
            policy_findings = []
            domains_status["policy"] = "ERROR"
            system_errors.append(f"policy: {e}")
        for f in policy_findings:
            f["category"] = "policy"
        findings.extend(policy_findings)
        artifacts.append({
            "domain": "policy",
            "target_file": str(spec_path or "injected"),
            "rule_count": len(policy_findings),
        })

    # --- Schema domain ---
    schema_findings = []
    if schema_json_data is not None:
        schema_findings = schema_json_data
        domains_status["schema"] = "RUN"
    elif schema_checks:
        try:
            for check in schema_checks:
                schema_findings.extend(_run_schema_check(check["schema"], check["target"]))
            domains_status["schema"] = "RUN"
        except Exception as e:
            schema_findings = []
            domains_status["schema"] = "ERROR"
            system_errors.append(f"schema: {e}")
    else:
        domains_status["schema"] = "SKIPPED"

    if domains_status["schema"] == "RUN":
        findings.extend(schema_findings)
        artifacts.append({
            "domain": "schema",
            "target_file": ",".join(str(c.get("target")) for c in (schema_checks or [])) or "injected",
            "rule_count": len(schema_findings),
        })

    # --- Traceability domain ---
    # This domain checks the registry/catalogue, not spec_path, so it
    # runs at most once per call regardless of spec_path being set.
    traceability_findings = []
    if traceability_json_data is not None:
        traceability_findings = traceability_json_data
        domains_status["traceability"] = "RUN"
    elif enable_traceability:
        try:
            requirements = load_requirements(requirements_path)
            traceability_findings = _check_traceability(registry, requirements)
            domains_status["traceability"] = "RUN"
        except Exception as e:
            traceability_findings = []
            domains_status["traceability"] = "ERROR"
            system_errors.append(f"traceability: {e}")
    else:
        domains_status["traceability"] = "SKIPPED"

    if domains_status["traceability"] == "RUN":
        findings.extend(traceability_findings)
        artifacts.append({
            "domain": "traceability",
            "target_file": str(requirements_path),
            "rule_count": len(traceability_findings),
        })

    # --- Security domain (opt-in via security_target / security_json_data) ---
    security_findings = []
    if security_json_data is not None:
        security_findings = security_json_data.get("findings", []) if isinstance(security_json_data, dict) else security_json_data
        domains_status["security"] = "RUN"
    elif security_target:
        try:
            _security_result = _scan_security(security_target)
            if isinstance(_security_result, dict) and _security_result.get("status") == "ERROR":
                security_findings = []
                domains_status["security"] = "ERROR"
                system_errors.append(f"security: {_security_result.get('message')}")
            else:
                security_findings = _security_result.get("findings", []) if isinstance(_security_result, dict) else _security_result
                domains_status["security"] = "RUN"
        except Exception as e:
            security_findings = []
            domains_status["security"] = "ERROR"
            system_errors.append(f"security: {e}")
    else:
        domains_status["security"] = "SKIPPED"

    if domains_status["security"] == "RUN":
        for f in security_findings:
            if isinstance(f, dict):
                f.setdefault("category", "security")
        findings.extend(security_findings)
        artifacts.append({
            "domain": "security",
            "target_file": str(security_target) if security_target else "injected",
            "rule_count": len(security_findings),
        })

    # --- Governance domain (opt-in via governance_target / governance_json_data) ---
    governance_findings = []
    if governance_json_data is not None:
        governance_findings = governance_json_data.get("findings", []) if isinstance(governance_json_data, dict) else governance_json_data
        domains_status["governance"] = "RUN"
    elif governance_target:
        try:
            _governance_result = _scan_governance(governance_target)
            if isinstance(_governance_result, dict) and _governance_result.get("status") == "ERROR":
                governance_findings = []
                domains_status["governance"] = "ERROR"
                system_errors.append(f"governance: {_governance_result.get('message')}")
            else:
                governance_findings = _governance_result.get("findings", []) if isinstance(_governance_result, dict) else _governance_result
                domains_status["governance"] = "RUN"
        except Exception as e:
            governance_findings = []
            domains_status["governance"] = "ERROR"
            system_errors.append(f"governance: {e}")
    else:
        domains_status["governance"] = "SKIPPED"

    if domains_status["governance"] == "RUN":
        for f in governance_findings:
            if isinstance(f, dict):
                f.setdefault("category", "governance")
        findings.extend(governance_findings)
        artifacts.append({
            "domain": "governance",
            "target_file": str(governance_target) if governance_target else "injected",
            "rule_count": len(governance_findings),
        })

    # --- Resolve every finding against the registry + gate policy ---
    findings = [_resolve_finding({"message": f} if isinstance(f, str) else f, registry, environment) for f in findings]

    summary = {"total_findings": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0}
    has_blocking = False
    for f in findings:
        sev = f["severity"]
        key = sev.lower()
        if key in summary:
            summary[key] += 1
        if f["effective_gate_behavior"] == "FAIL":
            has_blocking = True

    if system_errors:
        status = "ERROR"
    elif has_blocking:
        status = "FAILED"
    else:
        status = "PASSED"

    digest_source = json.dumps(
        {"findings": findings, "summary": summary, "system_errors": system_errors},
        sort_keys=True,
        default=str,
    ).encode("utf-8")
    hash_digest = hashlib.sha256(digest_source).hexdigest()

    result = {
        "execution": {
            "execution_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "platform_version": PLATFORM_VERSION,
            "environment": environment,
            "domains": domains_status,
            "system_errors": system_errors,
        },
        "status": status,
        "summary": summary,
        "findings": findings,
        "evidence": {
            "artifacts": artifacts,
            "hash_digest": hash_digest,
        },
    }
    return result


def _write_sarif(result, sarif_path, registry):
    findings = result["findings"]
    sarif_output = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Foundation Validation Engine",
                        "rules": list(registry.values()),
                    }
                },
                "results": [
                    {
                        "ruleId": f["rule_id"],
                        "message": {"text": f["message"]},
                        "level": "error" if f["severity"] in ("CRITICAL", "HIGH") else "warning",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": f.get("location", {}).get("file", "")}
                                }
                            }
                        ],
                    }
                    for f in findings
                ],
            }
        ],
    }
    with open(sarif_path, "w", encoding="utf-8") as sf:
        json.dump(sarif_output, sf, indent=2)


def main():
    parser = argparse.ArgumentParser(description="Foundation Validation Engine â€” master gate")
    parser.add_argument("--spec", required=True, help="Path to the OpenAPI spec file to validate")
    parser.add_argument("--sarif", help="Path to write a SARIF report to")
    parser.add_argument("--output", help="Path to write the full ValidationResultContract JSON to")
    parser.add_argument("--registry", default="rules/registry.yaml,registry/rules.yaml", help="Path to rule registry YAML, or a comma-separated list of registry YAML paths to merge (later paths win on rule_id conflicts)")
    parser.add_argument("--policies", default="policies", help="Path to the OPA policy directory")
    parser.add_argument("--ruleset", default=None, help="Path to a Spectral ruleset (.spectral.yaml) to lint against; defaults to Spectral's own auto-discovery")
    parser.add_argument("--env", default="production", choices=sorted(GATE_POLICIES.keys()),
                         help="Gate policy environment (production = strict, dev = relaxed)")
    parser.add_argument("--schema-check", action="append", default=None, metavar="SCHEMA=TARGET",
                         help="Run the schema domain (SCH- rules) against SCHEMA=TARGET "
                              "(repeatable, e.g. --schema-check schemas/validation-result.schema.json=evidence/audit_evidence.json). "
                              "Uses '=' rather than ':' as the separator so Windows drive-letter paths aren't ambiguous. "
                              "Omit to skip the schema domain (its default).")
    parser.add_argument("--check-governance", type=str, help="Path to scan for governance compliance")
    parser.add_argument("--check-security", metavar="PATH",
                        help="Opt-in: scan PATH (file or directory) for hardcoded secrets via security_engine. Off by default.")
    parser.add_argument("--check-traceability", action="store_true",
                         help="Run the traceability domain (TRC- rules) against --registry and "
                              "--requirements. Off by default: no rule in this repo's registry has "
                              "a requirement_id mapped yet, so enabling this will surface new HIGH "
                              "findings for every active FAIL-gated rule. See traceability_engine.py.")
    parser.add_argument("--requirements", default="rules/requirements.json",
                         help="Path to the requirement catalogue JSON used by the traceability domain")
    args = parser.parse_args()

    spec_path = Path(args.spec)
    if not spec_path.exists():
        print(f"ERROR: spec file not found: {spec_path}", file=sys.stderr)
        sys.exit(2)

    schema_checks = None
    if args.schema_check:
        schema_checks = []
        for raw in args.schema_check:
            if "=" not in raw:
                print(f"ERROR: --schema-check must be SCHEMA=TARGET, got: {raw!r}", file=sys.stderr)
                sys.exit(2)
            schema_path, target_path = raw.split("=", 1)
            schema_checks.append({"schema": schema_path, "target": target_path})

    registry = load_registry(args.registry)
    result = run_all_validations(
        spec_path=spec_path,
        registry_path=args.registry,
        policy_dir=args.policies,
        ruleset_path=args.ruleset,
        environment=args.env,
        schema_checks=schema_checks,
        enable_traceability=args.check_traceability,
        requirements_path=args.requirements,
        security_target=args.check_security,
        governance_target=args.check_governance,
    )

    print(json.dumps(result, indent=2))

    if args.sarif:
        _write_sarif(result, args.sarif, registry)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)

    if result["status"] == "ERROR":
        sys.exit(2)
    elif result["status"] == "FAILED":
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()













