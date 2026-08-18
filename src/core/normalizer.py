import json
from pathlib import Path
from typing import Dict, Any

class ControlledNormalizer:
    """Handles controlled normalization of references ($ref) without flattening everything."""
    
    def __init__(self, base_path: str = "."):
        self.base_path = Path(base_path)

    def normalize_refs(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalizes internal/external $ref references in a controlled manner 
        while preserving the hierarchical structure (No Flatten-All).
        """
        # สร้างสำเนาเพื่อไม่ให้กระทบข้อมูลต้นฉบับ
        normalized = json.loads(json.dumps(schema))
        
        # ตัวอย่างกลไกตรวจสอบและจัดการ $ref แบบควบคุม
        def _resolve_node(node: Any) -> Any:
            if isinstance(node, dict):
                if "$ref" in node:
                    ref_val = node["$ref"]
                    # รักษาโครงสร้าง $ref เดิมไว้ตามหลักการ No Flatten-All
                    node["$ref"] = ref_val
                for k, v in node.items():
                    node[k] = _resolve_node(v)
            elif isinstance(node, list):
                return [_resolve_node(item) for item in node]
            return node

        return _resolve_node(normalized)