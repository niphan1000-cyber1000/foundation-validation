import hashlib
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Union


def hash_file(path: Union[str, Path]) -> Optional[str]:
    """SHA-256 hex digest of a single file's raw bytes, or None if the path
    doesn't exist / isn't a file. Recording this (not just the path string)
    is what makes "which ruleset/registry backed this decision" verifiable
    after the fact — a path alone proves nothing once the checkout is gone,
    since the same path can point at different content on different refs."""
    p = Path(path)
    if not p.is_file():
        return None
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_paths(comma_separated_paths: str) -> Dict[str, Optional[str]]:
    """Hash each path in a comma-separated list (as accepted by
    validators/run_all.py::load_registry). Returns {path: hash_or_None},
    preserving every path (including missing ones as None) so a reviewer
    can see exactly what was and wasn't found at evidence-collection time."""
    paths = [p.strip() for p in str(comma_separated_paths).split(",") if p.strip()]
    return {p: hash_file(p) for p in paths}


def hash_directory(path: Union[str, Path], pattern: str = "*.rego") -> Optional[str]:
    """Combined SHA-256 fingerprint of every file matching `pattern` under
    `path`, sorted by relative path for determinism. Returns None if the
    directory doesn't exist or contains no matching files (mirrors
    validators/run_all.py's OPA-domain "nothing to evaluate" case).

    This exists because a single directory path (e.g. --opa-policy-dir)
    can silently point at a completely different Rego package between two
    runs (as happened when it was pointed at the wrong Foundation
    directory) — hashing the actual file contents makes that difference
    visible in the evidence chain instead of hiding behind an
    identical-looking path string."""
    p = Path(path)
    if not p.is_dir():
        return None
    files = sorted(p.rglob(pattern))
    if not files:
        return None
    combined = hashlib.sha256()
    for f in files:
        rel = f.relative_to(p).as_posix()
        combined.update(rel.encode("utf-8"))
        combined.update(b"\0")
        combined.update((hash_file(f) or "").encode("utf-8"))
        combined.update(b"\n")
    return combined.hexdigest()


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