from __future__ import annotations

from pathlib import Path

from recon_copilot.parser.nuclei_parser import parse_nuclei_jsonl

FIXTURE = (Path(__file__).parent / "fixtures" / "sample_nuclei.jsonl").read_text()


def test_parses_valid_detections():
    result = parse_nuclei_jsonl(FIXTURE)
    template_ids = {d.template_id for d in result.detections}
    assert "exposed-panel-generic" in template_ids
    assert "tls-version" in template_ids
    assert "critical-rce-cve-2026-0001" in template_ids


def test_invalid_json_line_is_logged_not_raised():
    result = parse_nuclei_jsonl(FIXTURE)
    assert any("ligne 3" in e for e in result.parse_errors)


def test_missing_template_id_is_logged_and_skipped():
    result = parse_nuclei_jsonl(FIXTURE)
    assert any("template-id" in e for e in result.parse_errors)
    # ligne 4 (template-id vide) ne doit pas produire de detection
    assert not any(d.line_number == 4 for d in result.detections)


def test_detection_preserves_raw_line_and_line_number():
    result = parse_nuclei_jsonl(FIXTURE)
    critical = next(d for d in result.detections if d.template_id == "critical-rce-cve-2026-0001")
    assert critical.line_number == 5
    assert critical.raw_line.startswith("{")
    assert "critical-rce-cve-2026-0001" in critical.raw_line


def test_severity_and_tags_extracted():
    result = parse_nuclei_jsonl(FIXTURE)
    panel = next(d for d in result.detections if d.template_id == "exposed-panel-generic")
    assert panel.severity == "medium"
    assert "panel" in panel.tags
    assert panel.matched_at == "http://10.0.0.5:80/admin"


def test_empty_output_is_not_an_error():
    result = parse_nuclei_jsonl("")
    assert result.detections == ()
    assert result.parse_errors == ()


def test_blank_lines_are_skipped_silently():
    result = parse_nuclei_jsonl("\n\n   \n")
    assert result.detections == ()
    assert result.parse_errors == ()


def test_severity_defaults_to_unknown_when_missing():
    result = parse_nuclei_jsonl('{"template-id": "no-severity-template", "matched-at": "x"}')
    assert result.detections[0].severity == "unknown"
