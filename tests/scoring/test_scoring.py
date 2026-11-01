from __future__ import annotations

import pytest

from recon_copilot.scoring import AssetCriticality, RiskLevel, compute_risk_score, score_and_store


def test_critical_severity_high_criticality_yields_critical_level():
    score = compute_risk_score("critical", 9.8, AssetCriticality.HIGH, port_number=443)
    assert score.risk_level == RiskLevel.CRITICAL


def test_info_severity_low_criticality_yields_low_level():
    score = compute_risk_score("info", None, AssetCriticality.LOW, port_number=22)
    assert score.risk_level == RiskLevel.LOW


def test_uses_provided_cvss_over_severity_bareme():
    high_cvss = compute_risk_score("low", 9.9, AssetCriticality.MEDIUM)
    low_cvss = compute_risk_score("low", 0.5, AssetCriticality.MEDIUM)
    assert high_cvss.composite_score > low_cvss.composite_score


def test_falls_back_to_severity_bareme_when_cvss_missing():
    score = compute_risk_score("high", None, AssetCriticality.MEDIUM)
    assert score.severity_component == 8.0


def test_out_of_range_cvss_falls_back_to_severity_bareme():
    score = compute_risk_score("medium", 15.0, AssetCriticality.MEDIUM)
    assert score.severity_component == 5.5  # bareme "medium", pas 15.0


def test_high_exposure_port_scores_higher_than_low_exposure_port():
    web = compute_risk_score("medium", 6.0, AssetCriticality.MEDIUM, port_number=443)
    admin = compute_risk_score("medium", 6.0, AssetCriticality.MEDIUM, port_number=22)
    assert web.exposure_component > admin.exposure_component
    assert web.composite_score > admin.composite_score


def test_unknown_port_gets_neutral_exposure():
    score = compute_risk_score("medium", 6.0, AssetCriticality.MEDIUM, port_number=None)
    assert score.exposure_component == 5.0


def test_asset_criticality_shifts_composite_score():
    low_asset = compute_risk_score("medium", 6.0, AssetCriticality.LOW, port_number=443)
    high_asset = compute_risk_score("medium", 6.0, AssetCriticality.HIGH, port_number=443)
    assert high_asset.composite_score > low_asset.composite_score


def test_composite_score_never_exceeds_ten():
    score = compute_risk_score("critical", 10.0, AssetCriticality.HIGH, port_number=443)
    assert score.composite_score <= 10.0


def test_weights_must_sum_to_one():
    with pytest.raises(ValueError):
        compute_risk_score("medium", 5.0, AssetCriticality.MEDIUM, weight_severity=0.5, weight_exposure=0.5, weight_criticality=0.5)


def test_score_and_store_updates_finding_row(db_conn):
    db_conn.execute(
        """
        INSERT INTO correlated_findings
            (created_at, engagement, target, title, description, severity, cvss_score, confidence,
             source_type, source_citation, citation_verified, raw_llm_response)
        VALUES ('2026-01-01T00:00:00Z', 'eng', '10.0.0.5', 'Test finding', 'desc', 'high', 7.8, 'high',
                'nuclei', 'citation', 1, '[]')
        """
    )
    db_conn.commit()
    finding_id = db_conn.execute("SELECT id FROM correlated_findings").fetchone()["id"]

    score = score_and_store(db_conn, finding_id, AssetCriticality.HIGH, port_number=443)

    row = db_conn.execute("SELECT risk_score, risk_level, asset_criticality FROM correlated_findings WHERE id=?", (finding_id,)).fetchone()
    assert row["risk_score"] == score.composite_score
    assert row["risk_level"] == score.risk_level.value
    assert row["asset_criticality"] == "high"


def test_score_and_store_unknown_finding_raises(db_conn):
    with pytest.raises(ValueError):
        score_and_store(db_conn, 9999, AssetCriticality.MEDIUM)
