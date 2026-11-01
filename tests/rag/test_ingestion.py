from __future__ import annotations

from pathlib import Path

from recon_copilot.rag.ingestion import (
    ingest_nuclei_templates_dir,
    parse_cisa_kev_json,
    parse_nuclei_template_yaml,
)

FIXTURES = Path(__file__).parent / "fixtures"
KEV_JSON = (FIXTURES / "sample_kev.json").read_text()


def test_parse_cisa_kev_extracts_valid_entries():
    docs, errors = parse_cisa_kev_json(KEV_JSON)
    ids = {d.id for d in docs}
    assert "CVE-2021-44228" in ids
    assert "CVE-2023-99999" in ids
    assert len(docs) == 2  # la 3eme entree (sans cveID) est exclue


def test_parse_cisa_kev_logs_entry_missing_cve_id():
    docs, errors = parse_cisa_kev_json(KEV_JSON)
    assert any("cveID" in e for e in errors)


def test_parse_cisa_kev_populates_metadata():
    docs, _ = parse_cisa_kev_json(KEV_JSON)
    log4j = next(d for d in docs if d.id == "CVE-2021-44228")
    assert log4j.source == "cisa_kev"
    assert log4j.metadata["vendor"] == "Apache"
    assert log4j.metadata["known_ransomware"] == "Known"
    assert "Log4Shell" in log4j.content or "JNDI" in log4j.content


def test_parse_cisa_kev_invalid_json_returns_empty_with_error():
    docs, errors = parse_cisa_kev_json("not json")
    assert docs == []
    assert len(errors) == 1


def test_parse_cisa_kev_missing_vulnerabilities_key():
    docs, errors = parse_cisa_kev_json('{"count": 0}')
    assert docs == []
    assert "vulnerabilities" in errors[0]


def test_parse_nuclei_template_valid():
    raw = (FIXTURES / "nuclei_templates" / "http" / "log4shell.yaml").read_text()
    doc, error = parse_nuclei_template_yaml(raw, "log4shell.yaml")
    assert error is None
    assert doc.id == "CVE-2021-44228"
    assert doc.source == "nuclei_template"
    assert doc.metadata["severity"] == "critical"
    assert "kev" in doc.metadata["tags"]


def test_parse_nuclei_template_missing_id_field():
    raw = (FIXTURES / "nuclei_templates" / "malformed.yaml").read_text()
    doc, error = parse_nuclei_template_yaml(raw, "malformed.yaml")
    assert doc is None
    assert "id" in error


def test_parse_nuclei_template_invalid_yaml():
    raw = (FIXTURES / "nuclei_templates" / "not-yaml-at-all.yaml").read_text()
    doc, error = parse_nuclei_template_yaml(raw, "not-yaml-at-all.yaml")
    assert doc is None
    assert "YAML invalide" in error


def test_ingest_nuclei_templates_dir_walks_recursively():
    docs, errors = ingest_nuclei_templates_dir(FIXTURES / "nuclei_templates")
    ids = {d.id for d in docs}
    assert "exposed-admin-panel" in ids  # dans le sous-dossier http/
    assert "CVE-2021-44228" in ids


def test_ingest_nuclei_templates_dir_collects_errors_without_stopping():
    docs, errors = ingest_nuclei_templates_dir(FIXTURES / "nuclei_templates")
    assert len(docs) == 2  # les 2 valides
    assert len(errors) == 2  # malformed.yaml (id absent) + not-yaml-at-all.yaml


def test_ingest_nuclei_templates_dir_missing_directory():
    docs, errors = ingest_nuclei_templates_dir("/tmp/does-not-exist-recon-copilot")
    assert docs == []
    assert len(errors) == 1
    assert "introuvable" in errors[0]
