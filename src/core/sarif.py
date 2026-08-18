import json
from pathlib import Path
from typing import List, Dict, Any
from src.core.models import ValidatorResult, ValidationState

class SarifGenerator:
    """Generates SARIF (Static Analysis Results Interchange Format) reports from validator results."""
    
    def __init__(self, tool_name: str = "FoundationValidationEngine"):
        self.tool_name = tool_name

    def generate_report(self, results: List[ValidatorResult]) -> Dict[str, Any]:
        """Converts validator results into a standard SARIF dictionary structure."""
        sarif_results = []
        
        for res in results:
            if res.state == ValidationState.FAIL:
                sarif_results.append({
                    "ruleId": res.validator_name,
                    "level": "error",
                    "message": {
                        "text": f"Validation failed in {res.validator_name} with {res.findings_count} findings."
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": "config/schema"
                            }
                        }
                    }]
                })

        sarif_report = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": self.tool_name,
                        "informationUri": "https://github.com/foundation-validation"
                    }
                },
                "results": sarif_results
            }]
        }
        return sarif_report

    def save_report(self, results: List[ValidatorResult], output_path: str = "sarif_report.json") -> Path:
        """Saves the SARIF report to a JSON file."""
        report = self.generate_report(results)
        path = Path(output_path)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        return path