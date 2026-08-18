import json
from pathlib import Path
from typing import Dict, Any, List

class EvidenceCollector:
    """Collects and maintains an evidence chain tied to a specific run_id."""
    
    def __init__(self, run_id: str, output_dir: str = "evidence_output"):
        self.run_id = run_id
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.chain_data: List[Dict[str, Any]] = []

    def add_evidence(self, step_name: str, data: Dict[str, Any]) -> None:
        """Adds a piece of evidence to the chain for this run_id."""
        evidence_entry = {
            "run_id": self.run_id,
            "step": step_name,
            "payload": data
        }
        self.chain_data.append(evidence_entry)

    def save_chain(self) -> Path:
        """Saves the complete evidence chain to a JSON file."""
        file_path = self.output_dir / f"evidence_{self.run_id}.json"
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(self.chain_data, f, indent=2, ensure_ascii=False)
        return file_path