from __future__ import annotations

from recon_copilot.correlation.prompt import _nuclei_candidate_citations, build_correlation_prompt
from recon_copilot.parser.models import NucleiDetection

# Raw_line realiste, compact (pas d'espaces apres : ou ,), avec un enorme
# champ "response" -- exactement le pattern qui cassait les citations en
# usage reel (voir la conversation qui a motive ce fix).
REAL_RAW_LINE = (
    '{"template":"http/misconfiguration/http-missing-security-headers.yaml",'
    '"template-id":"http-missing-security-headers",'
    '"info":{"name":"HTTP Missing Security Headers","severity":"info"},'
    '"matcher-name":"strict-transport-security",'
    '"extracted-results":["/ftp"],'
    '"matched-at":"http://127.0.0.1:3000",'
    '"response":"HTTP/1.1 200 OK\\r\\n' + ("X" * 3000) + '"}'
)


def _detection(**overrides) -> NucleiDetection:
    defaults = dict(
        template_id="http-missing-security-headers",
        name="HTTP Missing Security Headers",
        severity="info",
        matched_at="http://127.0.0.1:3000",
        tags=("misconfig",),
        description="This template searches for missing HTTP security headers.",
        raw_line=REAL_RAW_LINE,
        line_number=1,
    )
    defaults.update(overrides)
    return NucleiDetection(**defaults)


def test_candidate_citations_are_all_real_substrings_of_raw_line():
    d = _detection()
    candidates = _nuclei_candidate_citations(d)
    assert candidates  # au moins template-id et matched-at
    for c in candidates:
        assert c in d.raw_line


def test_candidate_citations_include_template_id_and_matched_at():
    d = _detection()
    candidates = _nuclei_candidate_citations(d)
    assert '"template-id":"http-missing-security-headers"' in candidates
    assert '"matched-at":"http://127.0.0.1:3000"' in candidates


def test_candidate_citations_include_matcher_name_when_present():
    d = _detection()
    candidates = _nuclei_candidate_citations(d)
    assert '"matcher-name":"strict-transport-security"' in candidates


def test_candidate_citations_include_extracted_results_when_present():
    d = _detection()
    candidates = _nuclei_candidate_citations(d)
    assert any("extracted-results" in c for c in candidates)


def test_candidate_citations_skip_absent_fields_gracefully():
    raw = '{"template-id":"x","matched-at":"http://y"}'  # pas de matcher-name ni extracted-results
    d = _detection(raw_line=raw)
    candidates = _nuclei_candidate_citations(d)
    assert all("matcher-name" not in c for c in candidates)
    assert all("extracted-results" not in c for c in candidates)
    for c in candidates:
        assert c in raw


def test_candidate_citations_tolerant_to_spaced_json_formatting():
    """Regression : du JSON avec des espaces apres ':' (pas le format compact
    habituel de nuclei, mais rencontre en pratique) ne doit pas produire une
    liste de candidates vide -- l'extraction doit suivre le texte reel."""
    raw = (
        '{"template-id": "http-missing-security-headers", '
        '"matched-at": "http://127.0.0.1:3000", '
        '"matcher-name": "strict-transport-security"}'
    )
    d = _detection(
        template_id="http-missing-security-headers",
        matched_at="http://127.0.0.1:3000",
        raw_line=raw,
    )
    candidates = _nuclei_candidate_citations(d)
    assert candidates  # ne doit JAMAIS etre vide quand les champs existent bien
    assert '"template-id": "http-missing-security-headers"' in candidates
    assert '"matched-at": "http://127.0.0.1:3000"' in candidates
    assert '"matcher-name": "strict-transport-security"' in candidates
    for c in candidates:
        assert c in raw  # chaque candidate reste une sous-chaine exacte reelle


def test_prompt_does_not_dump_the_full_multi_kb_response_field():
    """Le prompt ne doit plus contenir le champ 'response' complet -- c'est
    exactement ce qui faisait paraphraser/tronquer le LLM en usage reel."""
    d = _detection()
    prompt = build_correlation_prompt(None, [d], "kb context")
    assert "X" * 3000 not in prompt  # le gros blob "response" n'est plus recopie tel quel


def test_prompt_includes_short_candidate_citations():
    d = _detection()
    prompt = build_correlation_prompt(None, [d], "kb context")
    assert '"template-id":"http-missing-security-headers"' in prompt
    assert '"matched-at":"http://127.0.0.1:3000"' in prompt


def test_prompt_includes_description_marked_as_non_citable_context():
    d = _detection()
    prompt = build_correlation_prompt(None, [d], "kb context")
    assert "This template searches for missing HTTP security headers." in prompt
    assert "NE PAS citer mot pour mot" in prompt


def test_prompt_no_findings_section_when_no_detections():
    prompt = build_correlation_prompt(None, [], "kb context")
    assert "aucune" in prompt
