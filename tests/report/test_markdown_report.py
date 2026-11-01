from __future__ import annotations

from recon_copilot.report.markdown_report import generate_markdown


def test_french_report_contains_french_labels(sample_context):
    md = generate_markdown(sample_context, "fr")
    assert "Resume executif" in md
    assert "Constatations techniques" in md
    assert "Critique" in md  # severite traduite


def test_english_report_contains_english_labels(sample_context):
    md = generate_markdown(sample_context, "en")
    assert "Executive Summary" in md
    assert "Technical Findings" in md
    assert "Critical" in md


def test_findings_sorted_critical_first(sample_context):
    md = generate_markdown(sample_context, "fr")
    assert md.index("Injection SQL") < md.index("TLS obsolete")


def test_unverified_citation_warning_present(sample_context):
    md = generate_markdown(sample_context, "fr")
    assert "citation non verifiee" in md or "non verifiee automatiquement" in md


def test_verified_finding_has_no_warning_attached_to_it(sample_context):
    md = generate_markdown(sample_context, "fr")
    sql_section = md[md.index("Injection SQL"):md.index("TLS obsolete")]
    assert "ATTENTION" not in sql_section


def test_empty_context_shows_no_findings_message(empty_context):
    md = generate_markdown(empty_context, "fr")
    assert "Aucune constatation" in md


def test_cwe_and_mitre_refs_included(sample_context):
    md = generate_markdown(sample_context, "fr")
    assert "CWE-89" in md
    assert "T1190" in md


def test_scope_section_shows_allowed_and_excluded_targets(sample_context):
    md = generate_markdown(sample_context, "fr")
    assert "10.0.0.0/24" in md
    assert "10.0.0.254" in md


def test_scope_section_shows_placeholder_when_no_scope(empty_context):
    md = generate_markdown(empty_context, "fr")
    assert "Aucun perimetre" in md


def test_command_used_shown_when_present(sample_context):
    md = generate_markdown(sample_context, "fr")
    assert "nmap -T3 -Pn -sV -oX - 10.0.0.5" in md


def test_command_used_absent_when_none(sample_context):
    md = generate_markdown(sample_context, "fr")
    tls_section = md[md.index("TLS obsolete"):]
    assert "Commande utilisee" not in tls_section


def test_remediation_priorities_only_critical_and_high(sample_context):
    md = generate_markdown(sample_context, "fr")
    priorities_section = md[md.index("Remediation prioritaire"):]
    assert "Injection SQL" in priorities_section
    assert "TLS obsolete" not in priorities_section
