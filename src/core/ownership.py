from typing import Dict, List

class RuleOwnershipManager:
    """Manages rule ownership and separation between Spectral and OPA."""
    
    def __init__(self):
        # กำหนดขอบเขตความรับผิดชอบของแต่ละเครื่องมืออย่างชัดเจน (Separation of Concerns)
        self.ownership_registry: Dict[str, List[str]] = {
            "spectral": ["openapi-structure", "naming-convention", "http-methods"],
            "opa": ["security-compliance", "data-privacy-policy", "rbac-authorization"]
        }

    def get_owner(self, rule_id: str) -> str:
        """Determines which validator owns a specific rule ID."""
        for owner, rules in self.ownership_registry.items():
            if rule_id in rules:
                return owner
        return "unknown"

    def validate_ownership(self, validator_name: str, rule_id: str) -> bool:
        """Validates if a rule is executed by its rightful owner."""
        owner = self.get_owner(rule_id)
        if owner == "unknown":
            return True # อนุญาตให้กฎทั่วไปผ่านได้
        return owner == validator_name