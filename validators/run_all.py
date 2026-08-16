"""
run_all.py — Foundation Validation Engine master gate.

Aggregates findings from the OpenAPI (Spectral) and Policy (OPA) domains,
resolves each finding's severity/gate_behavior against rules/registry.yaml
(the single source of truth for rule metadata), and produces a single
ValidationResultContract object matching schemas/validation-result.schema.json.

Two entry points:
  * run_all_validations(...)  — importable function, used by tests and by
    anything that wants to inject already-fetched tool output (openapi_json_data /
    opa_json_data) instead of shelling out to spectral/opa. This is what
    validators/tests/test_aggregator.py exercises.
  * CLI (`python run_all.py --spec ...`) — the real gate used by CI and the
    pre-commit hook. It invokes Spectral and OPA itself, then calls
    run_all_validations() with the live output.

Fail-safe rules this module follows (see validators/README.md and
validators/schema/schema_engine.py for the same philosophy elsewhere in
this repo):
  * A missing/unreadable --spec file is a hard error, not a silent PASS.
  * A tool (spectral/opa) that can't be invoked is a hard ERROR, not a
    silent "no findings".
  * A rule_id with no entry in rules/registry.yaml still gets a fail-safe
    default gate_behavior based on severity — it is never silently ignored.
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
for sub in ("openapi", "policy"):
    p = str(BASE_DIR / sub)
    if p not in sys.path:
        sys.path.insert(0, p)

from openapi_engine import parse_spectral_output  # noqa: E402
from policy_engine import parse_opa_output  # noqa: E402

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


def load_registry(registry_path="rules/registry.yaml"):
    """Load rules/registry.yaml into {rule_id: rule_dict}. Returns {} if the
    file is missing (fail-safe defaults then apply to every finding)."""
    if not yaml:
        return {}
    path = Path(registry_path)
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8-sig") as f:
        data = yaml.safe_load(f) or {}
    rules = {}
    for rule in data.get("rules", []):
        rules[rule.get("rule_id") or rule.get("id")] = rule
    return rules


def _resolve_finding(finding, registry, environment):
    """Attach severity/gate_behavior/effective_gate_behavior to a raw
    finding, using the registry as the source of truth when the rule is
    catalogued and a fail-safe severity-based default otherwise."""
    rule_id = finding.get("rule_id", "")
    rule_meta = registry.get(rule_id)

    if rule_meta:
        severity = str(rule_meta.get("severity", finding.get("severity", "MEDIUM"))).upper()
        gate_behavior = str(rule_meta.get("gate_behavior", "FAIL")).upper()
        finding["rule_version"] = rule_meta.get("version", "0.0.0")
    else:
        severity = str(finding.get("severity", "MEDIUM")).upper()
        gate_behavior = _DEFAULT_GATE_BEHAVIOR_BY_SEVERITY.get(severity, "WARN")
        finding.setdefault("rule_version", "unregistered")

    policy = GATE_POLICIES.get(environment, GATE_POLICIES["production"])
    effective_gate_behavior = policy.get((severity, gate_behavior), gate_behavior)

    finding["severity"] = severity
    finding["gate_behavior"] = gate_behavior
    finding["effective_gate_behavior"] = effective_gate_behavior
    finding.setdefault("category", finding.get("category", "openapi"))
    return finding


def _resolve_executable(name):
    """Resolve a command name to a full, invokable path.

    shutil.which() checks PATHEXT on Windows (so it correctly finds e.g.
    npx.cmd for "npx"), which subprocess.run([name, ...]) does NOT do on
    its own when shell=False — that mismatch is what produced
    "WinError 2: The system cannot find the file specified" for a tool
    that clearly works fine when typed directly into PowerShell. Returns
    None if the tool truly isn't on PATH.
    """
    return shutil.which(name)


def _invoke_spectral(spec_path):
    """Run Spectral CLI against spec_path and return its raw JSON findings
    list. Raises RuntimeError (system error, not a silent []) if Spectral
    can't be invoked at all."""
    npx = _resolve_executable("npx")
    if not npx:
        raise RuntimeError("npx not found on PATH — is Node.js installed?")
    try:
        proc = subprocess.run(
            [npx, "--yes", "@stoplight/spectral-cli", "lint", str(spec_path), "-f", "json"],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired) as e:
        raise RuntimeError(f"could not invoke Spectral CLI: {e}") from e

    stdout = (proc.stdout or "").strip()
    if not stdout:
        # A clean Spectral lint with `-f json` still prints "[]" — empty
        # stdout means the CLI itself didn't run (missing package, no
        # network, bad invocation, etc.), which is a system error, not
        # "no findings". Surface stderr so the real cause is visible.
        stderr = (proc.stderr or "").strip()
        raise RuntimeError(
            f"Spectral CLI produced no output (exit {proc.returncode}): {stderr[:500]}"
        )
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Spectral CLI returned non-JSON output: {e}") from e


def _invoke_opa(spec_path, policy_dir="policies"):
    """Run `opa eval` against spec_path using the Rego policies in
    policy_dir and return the raw OPA JSON result. Raises RuntimeError if
    OPA can't be invoked. If policy_dir doesn't exist, the policy domain is
    treated as NOT_APPLICABLE (returns None), not as a finding source."""
    if not Path(policy_dir).exists():
        return None
    opa = _resolve_executable("opa")
    if not opa:
        raise RuntimeError("opa not found on PATH — is OPA CLI installed?")
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
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"OPA CLI returned non-JSON output: {e}") from e


def run_all_validations(
    spec_path=None,
    registry_path="rules/registry.yaml",
    openapi_json_data=None,
    opa_json_data=None,
    policy_dir="policies",
    environment="production",
):
    """Aggregate the OpenAPI and Policy domains into a single
    ValidationResultContract-shaped dict.

    openapi_json_data / opa_json_data let callers (tests, or the CLI after
    it has already shelled out to spectral/opa) inject already-fetched raw
    tool output instead of this function invoking the tools itself. When
    neither injected data nor a spec_path is given, both domains are
    SKIPPED and the result is an empty PASS — this is what lets
    run_all_validations() be called with no arguments in unit tests.
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
            raw = _invoke_spectral(spec_path)
            domains_status["openapi"] = "RUN"
        except RuntimeError as e:
            raw = []
            domains_status["openapi"] = "ERROR"
            system_errors.append(f"openapi: {e}")
    else:
        raw = None
        domains_status["openapi"] = "SKIPPED"

    if raw is not None:
        openapi_findings = parse_spectral_output(raw, target_path=str(spec_path or ""))
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
        except RuntimeError as e:
            raw_opa = None
            domains_status["policy"] = "ERROR"
            system_errors.append(f"policy: {e}")
    else:
        raw_opa = None
        domains_status["policy"] = "SKIPPED"

    if raw_opa is not None:
        policy_findings = parse_opa_output(raw_opa, target_path=str(spec_path or ""))
        for f in policy_findings:
            f["category"] = "policy"
        findings.extend(policy_findings)
        artifacts.append({
            "domain": "policy",
            "target_file": str(spec_path or "injected"),
            "rule_count": len(policy_findings),
        })

    # --- Resolve every finding against the registry + gate policy ---
    findings = [_resolve_finding(f, registry, environment) for f in findings]

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
    parser = argparse.ArgumentParser(description="Foundation Validation Engine — master gate")
    parser.add_argument("--spec", required=True, help="Path to the OpenAPI spec file to validate")
    parser.add_argument("--sarif", help="Path to write a SARIF report to")
    parser.add_argument("--output", help="Path to write the full ValidationResultContract JSON to")
    parser.add_argument("--registry", default="rules/registry.yaml", help="Path to rule registry YAML")
    parser.add_argument("--policies", default="policies", help="Path to the OPA policy directory")
    parser.add_argument("--env", default="production", choices=sorted(GATE_POLICIES.keys()),
                         help="Gate policy environment (production = strict, dev = relaxed)")
    args = parser.parse_args()

    spec_path = Path(args.spec)
    if not spec_path.exists():
        print(f"ERROR: spec file not found: {spec_path}", file=sys.stderr)
        sys.exit(2)

    registry = load_registry(args.registry)
    result = run_all_validations(
        spec_path=spec_path,
        registry_path=args.registry,
        policy_dir=args.policies,
        environment=args.env,
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
