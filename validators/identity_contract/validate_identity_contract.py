#!/usr/bin/env python3
"""
validate_identity_contract.py — Foundation gate validator

Implements CloudForge Identity Contract v1, §8 (Foundation Gate Rule):

    Governance Guard ต้อง block PR ถ้าเจอ:
    1. OpenAPI endpoint ที่มี auth dependency แต่ไม่ประกาศทั้ง 401 และ 403
    2. Studio import auth logic ที่ไม่ใช่จาก cloudforge-auth-core
       (ป้องกันการ copy-paste auth code กลับมาอีก)
    3. claims["scopes"] (list form) ปรากฏในโค้ด

Fail-closed by design, matching gate_policy.yaml's existing convention:
any unexpected error while validating is itself a BLOCK (crash != PASS),
never silently skipped.

Output: single JSON object on stdout, same shape as the other validators
in this pipeline (spectral/opa/schema/trace), so Smart Gate can merge it
into the combined governance report unchanged:

    {"validator": "identity-contract", "action": "PASS" | "BLOCK",
     "reasons": [...]}

Exit code: 0 if PASS, 1 if BLOCK (including on internal error).
"""
from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    yaml = None  # handled explicitly below — missing tool must BLOCK, not skip


VALIDATOR_NAME = "identity-contract"

# Directories never treated as "this repo's own code" — vendored/dependency
# trees can legitimately contain jwt.decode / PyJWKClient etc.
EXCLUDED_DIR_PARTS = {
    ".venv", "venv", "node_modules", "site-packages",
    ".git", "__pycache__", ".pytest_cache", "dist", "build",
}

# The one place allowed to actually implement JWT verification.
ALLOWED_IMPLEMENTATION_PATH_MARKER = "cloudforge_auth_core"

# Rule 3/2 note: detection is AST-based (see check_* functions below), not
# regex-over-raw-text. A first version used line regexes and false-positived
# on a docstring merely *mentioning* `claims["scopes"]` as a prohibited
# example — comments and docstrings must never trip this validator, only
# actual executable Subscript/Call expressions should.

# Paths that are allowed to reference these patterns even outside
# cloudforge_auth_core: tests exercising negative/garbage-token cases
# sometimes need to construct raw tokens with `pyjwt` directly, which is
# fine — pyjwt.encode() is not jwt.decode()/PyJWKClient, so those don't
# match anyway. This set is intentionally empty; kept as an explicit,
# documented extension point rather than silently widening the regexes
# above if a real exception is ever needed.
REIMPLEMENTATION_ALLOWLIST: set[str] = set()


def _is_excluded(path: Path) -> bool:
    return any(part in EXCLUDED_DIR_PARTS for part in path.parts)


def _iter_source_files(root: Path):
    for path in root.rglob("*.py"):
        if not _is_excluded(path):
            yield path


def check_deprecated_scopes_shape(root: Path) -> list[str]:
    """
    AST-based: flags actual code reading claims["scopes"] or
    claims.get("scopes"), never a comment/docstring merely mentioning it,
    and never a dict literal like {"scopes": [...]} used to construct a
    test token payload (that's a write, not a read of a real claims dict).
    """
    violations = []
    for path in _iter_source_files(root):
        try:
            source = path.read_text(encoding="utf-8-sig", errors="ignore")
            tree = ast.parse(source, filename=str(path))
        except (OSError, SyntaxError) as exc:
            violations.append(f"could not parse {path}: {exc}")
            continue

        for node in ast.walk(tree):
            # claims["scopes"] / payload["scopes"] / user["scopes"]
            if isinstance(node, ast.Subscript):
                key = node.slice
                if isinstance(key, ast.Constant) and key.value == "scopes":
                    violations.append(
                        f"{path}:{node.lineno}: reads deprecated `scopes` "
                        f"(list) claim via subscript — Contract v1 §2 "
                        f"requires `scope` (space-separated string) only"
                    )
            # claims.get("scopes") / payload.get("scopes", [])
            elif isinstance(node, ast.Call):
                func = node.func
                if (
                    isinstance(func, ast.Attribute)
                    and func.attr == "get"
                    and node.args
                    and isinstance(node.args[0], ast.Constant)
                    and node.args[0].value == "scopes"
                ):
                    violations.append(
                        f"{path}:{node.lineno}: reads deprecated `scopes` "
                        f"(list) claim via .get() — Contract v1 §2 "
                        f"requires `scope` (space-separated string) only"
                    )
    return violations


def check_no_reimplementation(root: Path) -> list[str]:
    """
    AST-based: flags actual `jwt.decode(...)` calls or `PyJWKClient(...)`
    instantiation outside cloudforge_auth_core — never a comment or
    docstring that merely mentions these names (e.g. explaining what NOT
    to do, or what auth-core does internally).
    """
    violations = []
    for path in _iter_source_files(root):
        rel_path = path.relative_to(root)
        # Exact path-segment match, not a substring check: a real
        # cloudforge_auth_core install has "cloudforge_auth_core" as an
        # actual directory component (e.g. .../cloudforge_auth_core/jwt.py).
        # A file merely NAMED to contain that string as a substring, e.g.
        # "src/cloudforge_auth_core_evil.py", is NOT the real package and
        # must not be silently exempted just because the string appears —
        # that would be exactly the kind of decoy-naming bypass this gate
        # exists to prevent.
        if ALLOWED_IMPLEMENTATION_PATH_MARKER in rel_path.parts:
            continue
        if str(rel_path) in REIMPLEMENTATION_ALLOWLIST:
            continue
        try:
            source = path.read_text(encoding="utf-8-sig", errors="ignore")
            tree = ast.parse(source, filename=str(path))
        except (OSError, SyntaxError) as exc:
            violations.append(f"could not parse {path}: {exc}")
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            # PyJWKClient(...)
            if isinstance(func, ast.Name) and func.id == "PyJWKClient":
                violations.append(
                    f"{path}:{node.lineno}: instantiates PyJWKClient "
                    f"directly — Contract v1 §3 requires all Studios to "
                    f"import verification logic from cloudforge_auth_core, "
                    f"not reimplement it"
                )
            # jwt.decode(...)  (specifically the `jwt` module, to avoid
            # flagging unrelated `.decode()` calls like bytes.decode())
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "decode"
                and isinstance(func.value, ast.Name)
                and func.value.id == "jwt"
            ):
                violations.append(
                    f"{path}:{node.lineno}: calls jwt.decode() directly — "
                    f"Contract v1 §3 requires all Studios to import "
                    f"verification logic from cloudforge_auth_core, not "
                    f"reimplement it"
                )
    return violations


def _effective_security(operation: dict, global_security) -> list:
    if "security" in operation:
        return operation["security"] or []
    return global_security or []


def check_openapi_401_403(root: Path) -> list[str]:
    violations: list[str] = []
    spec_path = None
    for candidate in ("openapi.yaml", "openapi.yml"):
        p = root / candidate
        if p.exists():
            spec_path = p
            break
    if spec_path is None:
        return violations  # no OpenAPI spec in this repo — not this validator's concern

    if yaml is None:
        # Missing PyYAML must BLOCK, not silently pass — fail-closed.
        return [
            "PyYAML is not installed in the CI environment; cannot "
            "validate openapi.yaml against Contract v1 §5/§8. This is a "
            "tooling failure, not a spec pass."
        ]

    try:
        spec = yaml.safe_load(spec_path.read_text(encoding="utf-8-sig"))
    except Exception as exc:  # noqa: BLE001 — any parse failure must BLOCK
        return [f"failed to parse {spec_path}: {exc}"]

    global_security = spec.get("security")
    paths = spec.get("paths") or {}

    for path_name, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in (
                "get", "post", "put", "patch", "delete", "options", "head",
            ):
                continue
            if not isinstance(operation, dict):
                continue

            effective = _effective_security(operation, global_security)
            requires_auth = bool(effective)
            if not requires_auth:
                continue  # explicitly public endpoint (e.g. /healthz) — fine

            responses = operation.get("responses") or {}
            response_codes = {str(code) for code in responses.keys()}
            missing = {"401", "403"} - response_codes
            if missing:
                violations.append(
                    f"{spec_path}: {method.upper()} {path_name} requires "
                    f"auth but is missing response(s) {sorted(missing)} — "
                    f"Contract v1 §5 requires both 401 and 403 declared "
                    f"on every authenticated endpoint"
                )

    return violations


def run_check(root: Path | str | None = None) -> dict:
    """Library entry point used by src.cli / GateDecisionEngine path.

    Returns the same JSON-shaped dict the CLI prints:
        {"validator": "identity-contract", "action": "PASS"|"BLOCK", "reasons": [...]}
    Never raises — any unexpected error is converted to action=BLOCK (fail-closed).
    """
    resolved = Path(root if root is not None else ".").resolve()
    reasons: list[str] = []
    try:
        reasons += check_deprecated_scopes_shape(resolved)
        reasons += check_no_reimplementation(resolved)
        reasons += check_openapi_401_403(resolved)
    except Exception as exc:  # noqa: BLE001 — fail-closed: crash => BLOCK
        return {
            "validator": VALIDATOR_NAME,
            "action": "BLOCK",
            "reasons": [
                f"validator crashed unexpectedly ({type(exc).__name__}: {exc}) "
                f"— treated as BLOCK per fail-closed policy, not PASS"
            ],
        }
    action = "BLOCK" if reasons else "PASS"
    return {"validator": VALIDATOR_NAME, "action": action, "reasons": reasons}


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    result = run_check(root)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 1 if result["action"] == "BLOCK" else 0


if __name__ == "__main__":
    sys.exit(main())
