package governance.api

import future.keywords.in

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

# SEC-002: Enforce HTTPS Scheme in Server URLs, with a loopback-only
# exception for local development. This must express the exact same
# invariant as SEC-001-https-only in .spectral.yaml / rules/registry.yaml:
# HTTPS is mandatory for non-loopback server endpoints; plain HTTP is
# permitted ONLY for exactly "localhost" or "127.0.0.1" (optionally with
# a port and/or path) — never for private network ranges (192.168.x.x,
# 10.x.x.x, 172.16.x.x) or internal DNS names, since those can be real,
# reachable network endpoints.
deny[msg] {
    some i
    server := input.servers[i]
    url := server.url
    not startswith(url, "https://")
    not startswith(url, "{") # allow parameterized URLs like {protocol}://
    not is_loopback_http(url)
    msg := {
        "rule_id": "SEC-002-NON-HTTPS-SERVER",
        "severity": "HIGH",
        "message": sprintf("Server URL '%s' must use HTTPS scheme (HTTP is only permitted for localhost/127.0.0.1 development endpoints).", [url]),
        "path": sprintf("servers[%d].url", [i])
    }
}

# Loopback-only exception — keep this pattern in sync with the regex in
# .spectral.yaml's SEC-001-https-only rule.
is_loopback_http(url) {
    regex.match(`^http://(localhost|127\.0\.0\.1)(:[0-9]+)?(/.*)?$`, url)
}

# SEC-003: Prohibit Sensitive Terms in Query Parameters
deny[msg] {
    some path_key, op_key
    operation := input.paths[path_key][op_key]
    param := operation.parameters[_]
    param["in"] == "query"
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