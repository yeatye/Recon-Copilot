from __future__ import annotations

import json

from recon_copilot.report import generate_report
from recon_copilot.db import get_connection


def _seed_finding(conn, engagement="eng-facade"):
    conn.execute(
        """
        INSERT INTO correlated_findings
            (created_at, engagement, target, title, description, severity, cvss_score, confidence,
             source_type, source_citation, citation_verified, raw_llm_response, review_status,
             remediation, cve_refs, cwe_refs, mitre_refs, risk_score, risk_level)
        VALUES ('2026-01-01T00:00:00Z', ?, '10.0.0.5', 'Test finding', 'desc', 'high', 7.8, 'high',
                'nuclei', 'citation', 1, '[]', 'accepted', 'fix it', '[]', '[]', '[]', 6.0, 'high')
        """,
        (engagement,),
    )
    conn.commit()


def test_generate_report_sarif_and_vex_produced_once_not_per_language(tmp_path):
    conn = get_connection(":memory:")
    _seed_finding(conn)

    paths = generate_report(
        conn, "eng-facade", tmp_path, formats=("sarif", "vex"), langs=("fr", "en")
    )

    sarif_paths = [p for p in paths if p.suffix == ".sarif"]
    vex_paths = [p for p in paths if "vex" in p.name]
    assert len(sarif_paths) == 1  # une seule fois, pas une fois par langue
    assert len(vex_paths) == 1


def test_generate_report_sarif_file_is_valid_json(tmp_path):
    conn = get_connection(":memory:")
    _seed_finding(conn)

    paths = generate_report(conn, "eng-facade", tmp_path, formats=("sarif",), langs=("fr",))

    sarif_path = next(p for p in paths if p.suffix == ".sarif")
    doc = json.loads(sarif_path.read_text())
    assert doc["version"] == "2.1.0"


def test_generate_report_vex_file_is_valid_json(tmp_path):
    conn = get_connection(":memory:")
    _seed_finding(conn)

    paths = generate_report(conn, "eng-facade", tmp_path, formats=("vex",), langs=("fr",))

    vex_path = next(p for p in paths if "vex" in p.name)
    doc = json.loads(vex_path.read_text())
    assert doc["bomFormat"] == "CycloneDX"


def test_generate_report_md_only_does_not_produce_sarif_or_vex(tmp_path):
    conn = get_connection(":memory:")
    _seed_finding(conn)

    paths = generate_report(conn, "eng-facade", tmp_path, formats=("md",), langs=("fr",))

    assert not any(p.suffix == ".sarif" for p in paths)
    assert not any("vex" in p.name for p in paths)


def test_generate_report_all_formats_together(tmp_path):
    conn = get_connection(":memory:")
    _seed_finding(conn)

    paths = generate_report(
        conn, "eng-facade", tmp_path, formats=("md", "docx", "pdf", "sarif", "vex"), langs=("fr", "en")
    )

    suffixes = [p.suffix for p in paths]
    assert suffixes.count(".md") == 2  # fr + en
    assert suffixes.count(".docx") == 2
    assert suffixes.count(".pdf") == 2
    assert suffixes.count(".sarif") == 1
    assert sum(1 for p in paths if "vex" in p.name) == 1
