from typing import List, Dict, Any
from src.core.models import ValidatorResult, GateDecision, GateAction, ValidationState

class GateDecisionEngine:
    def __init__(self, policy: Dict[str, Any]):
        self.policy = policy

    def evaluate(self, run_id: str, results: List[ValidatorResult]) -> GateDecision:
        actions: List[GateAction] = []
        reasons: List[str] = []

        fail_safe_default = {"on_fail": "BLOCK", "on_error": "BLOCK"}
        rules = self.policy.get("rules", {}) if isinstance(self.policy, dict) else {}

        for res in results:
            validator_policy = rules.get(
                res.validator_name,
                rules.get("default", fail_safe_default),
            )
            if not isinstance(validator_policy, dict):
                validator_policy = fail_safe_default

            if res.state == ValidationState.ERROR:
                actions.append(GateAction.BLOCK)
                reasons.append(
                    f"Validator '{res.validator_name}' encountered an ERROR: {res.error_message or 'Unknown error'}. Forced BLOCK."
                )
            elif res.state == ValidationState.FAIL:
                action_str = validator_policy.get("on_fail", "BLOCK").upper()
                action = GateAction(action_str)
                actions.append(action)
                reasons.append(
                    f"Validator '{res.validator_name}' FAILED with {res.findings_count} findings. Policy action: {action.value}."
                )
            elif res.state == ValidationState.SKIPPED:
                reasons.append(f"Validator '{res.validator_name}' was SKIPPED.")
            elif res.state == ValidationState.PASS:
                reasons.append(f"Validator '{res.validator_name}' PASSED.")
            elif res.state == ValidationState.NOT_APPLICABLE:
                reasons.append(f"Validator '{res.validator_name}' is NOT_APPLICABLE.")

        final_action = GateAction.ALLOW
        if GateAction.BLOCK in actions:
            final_action = GateAction.BLOCK
        elif GateAction.WARN in actions:
            final_action = GateAction.WARN

        return GateDecision(
            run_id=run_id,
            action=final_action,
            reasons=reasons,
            results=results
        )