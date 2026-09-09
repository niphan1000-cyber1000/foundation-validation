"""
traceability_engine.py — Traceability domain (TRC-) validator.

Cross-references the Foundation Validation Engine's own rule registry
(rules/registry.yaml, as loaded by run_all.load_registry) against a
requirement catalogue (rules/requirements.json) and reports gaps in the
requirement -> rule -> evidence chain, per this folder's README and the
Foundation Validation Spec (Section 6).

Unlike every other domain, this one does NOT check the *target* being
validated (the OpenAPI spec, a policy input, etc.) — it checks the
validation engine's OWN metadata for completeness. That's why every
finding's `location.file` below points at the registry/catalogue files
themselves, not at a user's spec, and why it's meant to be run once per
registry change rather than once per spec lint.

Findings, per the README's severity table:
  TRC-001  Mandatory rule has coverage_status NOT_COVERED           HIGH
  TRC-002  Mandatory rule has coverage_status PARTIAL, no reason    MEDIUM
  TRC-003  Rule references a requirement_id absent from catalogue   MEDIUM
  TRC-004  Requirement marked mandatory has no rule mapped to it    LOW

"Mandatory rule" here means status == "active" and gate_behavior ==
"FAIL" — i.e. a rule that can actually block a release, not a WARN/INFO
one. This is a deliberate, documented proxy: rules/registry.yaml has no
separate "mandatory" flag today, and using gate_behavior keeps this
engine's definition anchored to something already load-bearing rather
than inventing new registry schema.

Known limitation: as of registry v1.2.0, every rule's requirement_id is
null (see rules/registry.yaml's own comments) — turning on the
traceability domain (`--check-traceability` in run_all.py) will
therefore immediately surface a TRC-001 HIGH finding for every currently
active FAIL-gated rule. That's a real, existing gap this engine is
designed to make visible, not a bug in the engine — see run_all.py's CLI
help text for why the domain defaults to off.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


def _is_mandatory(rule: Dict[str, Any]) -> bool:
    return (
        str(rule.get("status", "active")).lower() == "active"
        and str(rule.get("gate_behavior", "")).upper() == "FAIL"
    )


def _finding(rule_id: str, severity: str, message: str, path: str) -> Dict[str, Any]:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "category": "traceability",
        "message": message,
        "location": {
            "file": "rules/registry.yaml",
            "path": path,
            "line": 0,
        },
    }


def check_traceability(
    registry: Dict[str, Dict[str, Any]],
    requirements: Optional[Dict[str, Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Returns a list of unified Finding dicts — the same
    rule_id/severity/category/message/location shape that
    openapi_engine.parse_spectral_output and policy_engine.parse_opa_output
    produce — so run_all.py can extend its findings list with these
    untouched, ahead of the shared _resolve_finding() severity/gate step.

    registry: {rule_id: rule_dict}, as returned by run_all.load_registry().
    requirements: {requirement_id: requirement_dict}, as returned by
        run_all.load_requirements(). None/{} means "no catalogue exists
        yet" — a fail-safe state, not "everything is covered".
    """
    requirements = requirements or {}
    findings: List[Dict[str, Any]] = []
    mapped_requirement_ids = set()

    for rule_id in sorted(registry):
        rule = registry[rule_id]
        requirement_id = rule.get("requirement_id")
        coverage_status = str(
            rule.get("coverage_status") or ("COVERED" if requirement_id else "NOT_COVERED")
        ).upper()

        if requirement_id:
            mapped_requirement_ids.add(requirement_id)
            if requirement_id not in requirements:
                findings.append(_finding(
                    "TRC-003",
                    "MEDIUM",
                    f"Rule '{rule_id}' references requirement_id '{requirement_id}', "
                    f"which does not exist in the requirement catalogue.",
                    rule_id,
                ))

        if coverage_status == "PARTIAL" and not rule.get("coverage_reason"):
            findings.append(_finding(
                "TRC-002",
                "MEDIUM",
                f"Rule '{rule_id}' has coverage_status PARTIAL with no documented "
                f"coverage_reason.",
                rule_id,
            ))
        elif coverage_status == "NOT_COVERED" and _is_mandatory(rule):
            findings.append(_finding(
                "TRC-001",
                "HIGH",
                f"Mandatory rule '{rule_id}' (status=active, gate_behavior=FAIL) has "
                f"no requirement_id mapped (coverage_status=NOT_COVERED).",
                rule_id,
            ))

    for requirement_id in sorted(requirements):
        req = requirements[requirement_id]
        if req.get("mandatory") and requirement_id not in mapped_requirement_ids:
            findings.append(_finding(
                "TRC-004",
                "LOW",
                f"Requirement '{requirement_id}' is marked mandatory but has no rule "
                f"mapped to it in the registry.",
                requirement_id,
            ))

    return findings
