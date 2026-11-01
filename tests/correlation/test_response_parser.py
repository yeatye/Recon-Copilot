from __future__ import annotations

from recon_copilot.correlation.response_parser import parse_llm_response

VALID_SOURCES = [
    '<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx"/></port>',
    '{"template-id": "exposed-panel-generic", "matched-at": "http://10.0.0.5:80/admin"}',
]

GOOD_RESPONSE = """[
  {
    "title": "Panneau admin expose",
    "description": "Un panneau admin est accessible sans authentification.",
    "severity": "medium",
    "cvss_score": 5.3,
    "confidence": "high",
    "source_type": "nuclei",
    "source_citation": "matched-at\\": \\"http://10.0.0.5:80/admin",
    "cve_refs": [],
    "cwe_refs": ["CWE-284"],
    "mitre_refs": ["T1595.002"],
    "remediation": "Restreindre l'acces au panel."
  }
]"""


def test_valid_response_produces_verified_finding():
    findings, warnings = parse_llm_response(GOOD_RESPONSE, VALID_SOURCES)
    assert len(findings) == 1
    assert findings[0].citation_verified is True
    assert findings[0].severity == "medium"
    assert warnings == []


def test_hallucinated_citation_is_flagged_not_dropped():
    response = GOOD_RESPONSE.replace(
        'matched-at\\": \\"http://10.0.0.5:80/admin', "ceci n'existe nulle part dans les sources"
    )
    findings, warnings = parse_llm_response(response, VALID_SOURCES)
    assert len(findings) == 1  # conserve
    assert findings[0].citation_verified is False
    assert any("citation non retrouvee" in w for w in warnings)


def test_markdown_fenced_response_is_stripped():
    fenced = "```json\n" + GOOD_RESPONSE + "\n```"
    findings, warnings = parse_llm_response(fenced, VALID_SOURCES)
    assert len(findings) == 1


def test_invalid_json_returns_empty_with_warning():
    findings, warnings = parse_llm_response("ceci n'est pas du JSON", VALID_SOURCES)
    assert findings == []
    assert len(warnings) == 1
    assert "non-JSON" in warnings[0]


def test_json_object_instead_of_array_returns_empty_with_warning():
    findings, warnings = parse_llm_response('{"not": "a list"}', VALID_SOURCES)
    assert findings == []
    assert "pas un tableau" in warnings[0]


def test_empty_array_is_valid_no_findings():
    findings, warnings = parse_llm_response("[]", VALID_SOURCES)
    assert findings == []
    assert warnings == []


def test_missing_required_fields_skips_item_and_warns():
    response = '[{"description": "sans titre ni citation"}]'
    findings, warnings = parse_llm_response(response, VALID_SOURCES)
    assert findings == []
    assert "manquant" in warnings[0]


def test_invalid_severity_falls_back_to_info():
    response = (
        '[{"title": "x", "source_citation": "http://10.0.0.5:80/admin", '
        '"severity": "catastrophic", "confidence": "high"}]'
    )
    findings, warnings = parse_llm_response(response, VALID_SOURCES)
    assert findings[0].severity == "info"
    assert any("severite" in w for w in warnings)


def test_non_numeric_cvss_becomes_none():
    response = (
        '[{"title": "x", "source_citation": "http://10.0.0.5:80/admin", '
        '"severity": "low", "confidence": "low", "cvss_score": "pas un nombre"}]'
    )
    findings, warnings = parse_llm_response(response, VALID_SOURCES)
    assert findings[0].cvss_score is None
    assert any("cvss_score" in w for w in warnings)
