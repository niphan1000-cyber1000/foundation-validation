# Policy Validator (OPA / Rego Domain)

Wraps OPA evaluation output and maps policy violations into the unified Finding/Evidence data contract.

## Usage
\\\ash
python run.py --rules rules.json --target path/to/policy_eval.json
\\\
"@ -Encoding UTF8

Set-Content -Path "validators\policy\rules.json" -Value @"
[
  {
    "id": "POL-001",
    "severity": "HIGH",
    "category": "policy",
    "description": "Policy evaluation identified access or compliance rule violations"
  }
]
