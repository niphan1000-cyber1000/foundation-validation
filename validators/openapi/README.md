# OpenAPI Validator (OAS Domain)

Wraps Spectral CLI output and maps OAS linting findings into the unified Finding/Evidence data contract.

## Usage
\\\ash
python run.py --rules rules.json --target path/to/openapi.yaml
\\\
"@ -Encoding UTF8
Set-Content -Path "validators\openapi\rules.json" -Value @"
[
  {
    "id": "OAS-001",
    "severity": "CRITICAL",
    "category": "openapi",
    "description": "OpenAPI spec contains spectral linting violations"
  }
]
