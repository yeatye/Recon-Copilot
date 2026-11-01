from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from recon_copilot.report.vex_report import build_vex, save_vex

SCHEMA_PATH = Path(__file__).parent / "schemas" / "cyclonedx-bom-1.5.schema.json"
CYCLONEDX_SCHEMA = json.loads(SCHEMA_PATH.read_text())


def _validate(doc: dict) -> None:
    """Valide contre le VRAI schema officiel CycloneDX 1.5 (draft-07)."""
    jsonschema.Draft7Validator(CYCLONEDX_SCHEMA).validate(doc)


def test_vex_output_validates_against_official_schema(sample_context):
    doc = build_vex(sample_context)
    _validate(doc)


def test_vex_empty_context_still_validates(empty_context):
    doc = build_vex(empty_context)
    _validate(doc)


def test_vex_top_level_fields(sample_context):
    doc = build_vex(sample_context)
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.5"
    assert doc["serialNumber"].startswith("urn:uuid:")
    assert doc["metadata"]["component"]["name"] == "eng-test"


def test_vex_creates_one_component_per_distinct_target():
    from recon_copilot.report.models import ReportContext, ReportFinding

    def _f(target, title):
        return ReportFinding(
            target=target, title=title, description="d", severity="low", risk_score=2.0, risk_level="low",
            remediation="r", cve_refs=(), cwe_refs=(), mitre_refs=(), source_citation="x", citation_verified=True,
        )

    context = ReportContext(
        engagement="e", generated_at="t",
        findings=(_f("10.0.0.1", "F1"), _f("10.0.0.1", "F2"), _f("10.0.0.2", "F3")),
    )
    doc = build_vex(context)
    assert len(doc["components"]) == 2  # 2 cibles distinctes, pas 3


def test_vex_analysis_state_is_exploitable_for_reviewed_findings(sample_context):
    doc = build_vex(sample_context)
    for vuln in doc["vulnerabilities"]:
        assert vuln["analysis"]["state"] == "exploitable"  # deja valide par revue humaine


def test_vex_unverified_citation_flagged_in_analysis_detail(sample_context):
    doc = build_vex(sample_context)
    tls_vuln = next(v for v in doc["vulnerabilities"] if v["description"].startswith("TLS"))
    assert "ATTENTION" in tls_vuln["analysis"]["detail"]


def test_vex_uses_cve_id_when_available():
    from recon_copilot.report.models import ReportContext, ReportFinding

    finding = ReportFinding(
        target="10.0.0.5", title="Log4Shell", description="RCE", severity="critical",
        risk_score=9.8, risk_level="critical", remediation="patch",
        cve_refs=("CVE-2021-44228",), cwe_refs=("CWE-502",), mitre_refs=(),
        source_citation="x", citation_verified=True,
    )
    context = ReportContext(engagement="e", generated_at="t", findings=(finding,))
    doc = build_vex(context)
    assert doc["vulnerabilities"][0]["id"] == "CVE-2021-44228"
    assert doc["vulnerabilities"][0]["cwes"] == [502]


def test_vex_synthetic_id_when_no_cve(sample_context):
    doc = build_vex(sample_context)
    tls_vuln = next(v for v in doc["vulnerabilities"] if v["description"].startswith("TLS"))
    assert tls_vuln["id"].startswith("RECON-COPILOT-")


def test_vex_affects_references_correct_component_bom_ref(sample_context):
    doc = build_vex(sample_context)
    component_ref = doc["components"][0]["bom-ref"]
    for vuln in doc["vulnerabilities"]:
        assert vuln["affects"][0]["ref"] == component_ref  # meme cible pour les 2 findings du fixture


def test_vex_omits_recommendation_when_absent():
    from recon_copilot.report.models import ReportContext, ReportFinding

    finding = ReportFinding(
        target="10.0.0.5", title="X", description="d", severity="low", risk_score=1.0, risk_level="low",
        remediation="", cve_refs=(), cwe_refs=(), mitre_refs=(), source_citation="x", citation_verified=True,
    )
    context = ReportContext(engagement="e", generated_at="t", findings=(finding,))
    doc = build_vex(context)
    assert "recommendation" not in doc["vulnerabilities"][0]


def test_save_vex_writes_valid_json_file(sample_context, tmp_path):
    path = save_vex(sample_context, tmp_path / "out.vex.json")
    assert path.exists()
    doc = json.loads(path.read_text())
    _validate(doc)
