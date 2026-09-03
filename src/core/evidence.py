import hashlib
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

    def compute_hash(self) -> str:
        """Returns the SHA-256 hex digest of the evidence chain, serialized
        exactly the way save_chain() writes it to disk (same indent/
        ensure_ascii, so the hash matches the saved file byte-for-byte).
        Callers use this as a short, verifiable fingerprint of "what
        evidence backed this gate decision" without needing to ship the
        full evidence file around.
        """
        serialized = json.dumps(self.chain_data, indent=2, ensure_ascii=False).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()