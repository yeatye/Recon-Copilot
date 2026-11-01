from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from recon_copilot.report.sarif_report import build_sarif, save_sarif

SCHEMA_PATH = Path(__file__).parent / "schemas" / "sarif-schema-2.1.0.json"
SARIF_SCHEMA = json.loads(SCHEMA_PATH.read_text())


def _validate(doc: dict) -> None:
    """Valide contre le VRAI schema officiel OASIS SARIF 2.1.0 (draft-04)."""
    jsonschema.Draft4Validator(SARIF_SCHEMA).validate(doc)


def test_sarif_output_validates_against_official_schema(sample_context):
    doc = build_sarif(sample_context)
    _validate(doc)  # leve une exception si non-conforme -- c'est le test


def test_sarif_empty_context_still_validates(empty_context):
    doc = build_sarif(empty_context)
    _validate(doc)


def test_sarif_top_level_structure(sample_context):
    doc = build_sarif(sample_context)
    assert doc["version"] == "2.1.0"
    assert len(doc["runs"]) == 1
    assert doc["runs"][0]["tool"]["driver"]["name"] == "recon-copilot"


def test_sarif_severity_mapped_to_correct_level(sample_context):
    doc = build_sarif(sample_context)
    results = {r["ruleId"]: r for r in doc["runs"][0]["results"]}
    assert results["injection-sql"]["level"] == "error"
    assert results["tls-obsolete"]["level"] == "note"


def test_sarif_rule_id_uses_cve_when_available():
    from recon_copilot.report.models import ReportContext, ReportFinding

    finding = ReportFinding(
        target="10.0.0.5", title="Log4Shell", description="RCE", severity="critical",
        risk_score=9.8, risk_level="critical", remediation="patch",
        cve_refs=("CVE-2021-44228",), cwe_refs=(), mitre_refs=(),
        source_citation="x", citation_verified=True,
    )
    context = ReportContext(engagement="e", generated_at="t", findings=(finding,))
    doc = build_sarif(context)
    assert doc["runs"][0]["results"][0]["ruleId"] == "CVE-2021-44228"


def test_sarif_rule_id_slugified_from_title_when_no_cve(sample_context):
    doc = build_sarif(sample_context)
    tls_result = next(r for r in doc["runs"][0]["results"] if "TLS" in r["message"]["text"])
    assert tls_result["ruleId"] == "tls-obsolete"


def test_sarif_unverified_citation_flagged_in_message(sample_context):
    doc = build_sarif(sample_context)
    results = {r["ruleId"]: r for r in doc["runs"][0]["results"]}
    assert "ATTENTION" in results["tls-obsolete"]["message"]["text"]
    assert results["tls-obsolete"]["properties"]["citation_verified"] is False


def test_sarif_verified_citation_no_warning_in_message(sample_context):
    doc = build_sarif(sample_context)
    results = {r["ruleId"]: r for r in doc["runs"][0]["results"]}
    assert "ATTENTION" not in results["injection-sql"]["message"]["text"]


def test_sarif_target_included_as_artifact_location(sample_context):
    doc = build_sarif(sample_context)
    result = doc["runs"][0]["results"][0]
    uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert "10.0.0.5" in uri


def test_sarif_deduplicates_rules_for_same_finding_type():
    from recon_copilot.report.models import ReportContext, ReportFinding

    def _f(target):
        return ReportFinding(
            target=target, title="Same Finding Type", description="d", severity="low",
            risk_score=2.0, risk_level="low", remediation="r",
            cve_refs=(), cwe_refs=(), mitre_refs=(), source_citation="x", citation_verified=True,
        )

    context = ReportContext(engagement="e", generated_at="t", findings=(_f("10.0.0.1"), _f("10.0.0.2")))
    doc = build_sarif(context)
    assert len(doc["runs"][0]["tool"]["driver"]["rules"]) == 1  # une seule regle
    assert len(doc["runs"][0]["results"]) == 2  # deux resultats distincts


def test_save_sarif_writes_valid_json_file(sample_context, tmp_path):
    path = save_sarif(sample_context, tmp_path / "out.sarif")
    assert path.exists()
    doc = json.loads(path.read_text())
    _validate(doc)
