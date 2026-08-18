package governance.api

# SEC-001: Require Global Security or Operation-Level Security
deny[msg] {
    not input.security
    not all_paths_have_security(input.paths)
    msg := {
        "rule_id": "SEC-001-MISSING-SECURITY",
        "severity": "HIGH",
        "message": "API Spec must define global 'security' requirement or operation-level security.",
        "path": "security"
    }
}

# Helper: check if all operations under paths have security defined
all_paths_have_security(paths) {
    count({path | paths[path][op]; op != "parameters"; not paths[path][op].security}) == 0
}

# SEC-002: Enforce HTTPS Scheme in Server URLs
deny[msg] {
    some i
    server := input.servers[i]
    url := server.url
    not startswith(url, "https://")
    not startswith(url, "{") # allow parameterized URLs like {protocol}://
    msg := {
        "rule_id": "SEC-002-NON-HTTPS-SERVER",
        "severity": "HIGH",
        "message": sprintf("Server URL '%s' must use HTTPS scheme.", [url]),
        "path": sprintf("servers[%d].url", [i])
    }
}

# SEC-003: Prohibit Sensitive Terms in Query Parameters
deny[msg] {
    some path_key, op_key
    operation := input.paths[path_key][op_key]
    param := operation.parameters[_]
    param.in == "query"
    is_sensitive_name(param.name)
    msg := {
        "rule_id": "SEC-003-SENSITIVE-QUERY-PARAM",
        "severity": "CRITICAL",
        "message": sprintf("Sensitive parameter '%s' must not be passed via query string.", [param.name]),
        "path": sprintf("paths.%s.%s.parameters.%s", [path_key, op_key, param.name])
    }
}

is_sensitive_name(name) {
    lower_name := lower(name)
    sensitive_keywords := ["token", "password", "secret", "apikey", "access_token"]
    some kw in sensitive_keywords
    contains(lower_name, kw)
}