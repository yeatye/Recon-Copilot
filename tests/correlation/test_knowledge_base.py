from __future__ import annotations

from recon_copilot.correlation.knowledge_base import (
    build_kb_context,
    lookup_by_service_name,
    lookup_by_template_id,
)


def test_lookup_by_template_id_known():
    entry = lookup_by_template_id("sql-injection")
    assert entry is not None
    assert "CWE-89" in entry.cwe_refs


def test_lookup_by_template_id_unknown_returns_none():
    assert lookup_by_template_id("totally-made-up-template") is None


def test_lookup_by_service_name_case_insensitive():
    assert lookup_by_service_name("SSH") is not None
    assert lookup_by_service_name("ssh") is not None


def test_lookup_by_service_name_none_input():
    assert lookup_by_service_name(None) is None


def test_build_kb_context_only_includes_matches():
    context = build_kb_context(["tls-version"], ["ssh"])
    assert "tls-version" in context
    assert "ssh" in context
    assert "sql-injection" not in context  # pas demande, ne doit pas apparaitre


def test_build_kb_context_no_match_returns_explicit_message():
    context = build_kb_context(["unknown-template"], ["unknown-service"])
    assert "Aucune entree" in context


def test_build_kb_context_deduplicates():
    context = build_kb_context(["tls-version", "tls-version"], [])
    assert context.count("template Nuclei 'tls-version'") == 1
