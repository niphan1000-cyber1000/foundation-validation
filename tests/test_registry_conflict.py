def test_load_registry_conflicting_duplicate_rule_id_raises():
    """Two registries that both define the same rule_id, but disagree
    about its content (severity, domain, etc.), is a genuine identity
    conflict, not something the loader is entitled to resolve on its
    own by picking whichever path happened to load last. Silently
    letting the later path win is exactly the failure mode that let a
    generic engine-level rule_id shadow a more specific, field-level
    rule_id from another registry with no error and no log line."""
    import tempfile
    import os
    from validators.run_all import load_registry

    with tempfile.TemporaryDirectory() as tmpdir:
        path_a = os.path.join(tmpdir, "registry_a.yaml")
        path_b = os.path.join(tmpdir, "registry_b.yaml")

        with open(path_a, "w", encoding="utf-8") as f:
            f.write("rules:\n  - rule_id: TEST-CONFLICT-001\n    domain: test\n    severity: HIGH\n")

        with open(path_b, "w", encoding="utf-8") as f:
            f.write("rules:\n  - rule_id: TEST-CONFLICT-001\n    domain: test\n    severity: MEDIUM\n")

        raised = False
        try:
            load_registry(path_a + "," + path_b)
        except ValueError as e:
            raised = True
            assert "TEST-CONFLICT-001" in str(e)

        assert raised, "expected ValueError for conflicting rule_id definitions"


def test_load_registry_identical_duplicate_rule_id_is_ok():
    """The same rule_id appearing in more than one path is only a
    problem when the definitions disagree. A Studio may legitimately
    list the same registry file twice (e.g. via a shared include), or
    two paths may happen to both vendor an identical copy of a rule;
    that must not be treated as a conflict."""
    import tempfile
    import os
    from validators.run_all import load_registry

    with tempfile.TemporaryDirectory() as tmpdir:
        path_a = os.path.join(tmpdir, "registry_a.yaml")
        path_b = os.path.join(tmpdir, "registry_b.yaml")

        identical_content = "rules:\n  - rule_id: TEST-SAME-001\n    domain: test\n    severity: HIGH\n"

        with open(path_a, "w", encoding="utf-8") as f:
            f.write(identical_content)

        with open(path_b, "w", encoding="utf-8") as f:
            f.write(identical_content)

        result = load_registry(path_a + "," + path_b)
        assert result["TEST-SAME-001"]["severity"] == "HIGH"


def test_load_registry_distinct_rule_ids_across_paths_merge_normally():
    """The common case: two registries contribute different rule_ids
    with no overlap at all. This must keep working exactly as before --
    the conflict check must not become a false positive that blocks
    normal multi-registry merges."""
    import tempfile
    import os
    from validators.run_all import load_registry

    with tempfile.TemporaryDirectory() as tmpdir:
        path_a = os.path.join(tmpdir, "registry_a.yaml")
        path_b = os.path.join(tmpdir, "registry_b.yaml")

        with open(path_a, "w", encoding="utf-8") as f:
            f.write("rules:\n  - rule_id: TEST-A-001\n    domain: test\n    severity: HIGH\n")

        with open(path_b, "w", encoding="utf-8") as f:
            f.write("rules:\n  - rule_id: TEST-B-001\n    domain: test\n    severity: MEDIUM\n")

        result = load_registry(path_a + "," + path_b)
        assert result["TEST-A-001"]["severity"] == "HIGH"
        assert result["TEST-B-001"]["severity"] == "MEDIUM"

def test_load_registry_rejects_governance_rule_without_gov_prefix():
    """domain=governance requires rule_id to start with GOV- (covers both
    GOV-* API/spec rules and GOV-DOC-* document rules). Anything else is
    a namespace-convention violation and must raise rather than silently
    enter the registry."""
    import tempfile
    import os
    from validators.run_all import load_registry

    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "bad_registry.yaml")
        with open(path, "w", encoding="utf-8") as f:
            f.write(
                "rules:\n"
                "  - rule_id: BAD-001-NO-PREFIX\n"
                "    domain: governance\n"
                "    severity: HIGH\n"
            )
        raised = False
        try:
            load_registry(path)
        except ValueError as e:
            raised = True
            assert "BAD-001-NO-PREFIX" in str(e)
            assert "GOV-" in str(e)
        assert raised, "expected ValueError for governance rule without GOV- prefix"


def test_load_registry_accepts_gov_and_gov_doc_prefixes():
    """Both GOV-* and GOV-DOC-* are valid under domain=governance."""
    import tempfile
    import os
    from validators.run_all import load_registry

    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "ok_registry.yaml")
        with open(path, "w", encoding="utf-8") as f:
            f.write(
                "rules:\n"
                "  - rule_id: GOV-099-TEST\n"
                "    domain: governance\n"
                "    severity: MEDIUM\n"
                "  - rule_id: GOV-DOC-099-TEST\n"
                "    domain: governance\n"
                "    severity: HIGH\n"
            )
        result = load_registry(path)
        assert "GOV-099-TEST" in result
        assert "GOV-DOC-099-TEST" in result
