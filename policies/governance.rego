package governance.api

# GOV-001: Enforce Mandatory Metadata (x-governance-id, x-owner, x-domain)
deny[msg] {
    info := input.info
    not info["x-governance-id"]
    msg := {
        "rule_id": "GOV-001-MISSING-GOVERNANCE-ID",
        "severity": "HIGH",
        "message": "Missing required metadata field 'info.x-governance-id'.",
        "path": "info"
    }
}

deny[msg] {
    info := input.info
    not info["x-owner"]
    msg := {
        "rule_id": "GOV-001-MISSING-OWNER",
        "severity": "HIGH",
        "message": "Missing required metadata field 'info.x-owner'.",
        "path": "info"
    }
}

deny[msg] {
    info := input.info
    not info["x-domain"]
    msg := {
        "rule_id": "GOV-001-MISSING-DOMAIN",
        "severity": "HIGH",
        "message": "Missing required metadata field 'info.x-domain'.",
        "path": "info"
    }
}

# GOV-002: Enforce Semantic Versioning Format
deny[msg] {
    version := input.info.version
    not regex.match("^[0-9]+\\.[0-9]+\\.[0-9]+$", version)
    msg := {
        "rule_id": "GOV-002-INVALID-SEMVER",
        "severity": "MEDIUM",
        "message": sprintf("Version '%s' does not follow Semantic Versioning (X.Y.Z).", [version]),
        "path": "info.version"
    }
}

# GOV-003: Require Operations to Have Descriptions and Tags for Traceability
deny[msg] {
    some path_key, op_key
    operation := input.paths[path_key][op_key]
    op_key != "parameters"
    not operation.description
    msg := {
        "rule_id": "GOV-003-MISSING-OPERATION-DESCRIPTION",
        "severity": "MEDIUM",
        "message": sprintf("Operation '%s %s' must have a description.", [upper(op_key), path_key]),
        "path": sprintf("paths.%s.%s", [path_key, op_key])
    }
}

deny[msg] {
    some path_key, op_key
    operation := input.paths[path_key][op_key]
    op_key != "parameters"
    not operation.tags
    msg := {
        "rule_id": "GOV-003-MISSING-OPERATION-TAGS",
        "severity": "MEDIUM",
        "message": sprintf("Operation '%s %s' must define at least one tag.", [upper(op_key), path_key]),
        "path": sprintf("paths.%s.%s", [path_key, op_key])
    }
}