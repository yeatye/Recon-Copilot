from __future__ import annotations

import pytest

from recon_copilot.review import accept_finding, edit_finding, get_pending_findings, reject_finding


def _insert_finding(conn, engagement="eng-1", target="10.0.0.5", risk_score=None, title="Test finding"):
    conn.execute(
        """
        INSERT INTO correlated_findings
            (created_at, engagement, target, title, description, severity, cvss_score, confidence,
             source_type, source_citation, citation_verified, raw_llm_response, risk_score)
        VALUES ('2026-01-01T00:00:00Z', ?, ?, ?, 'desc', 'high', 7.8, 'high',
                'nuclei', 'citation', 1, '[]', ?)
        """,
        (engagement, target, title, risk_score),
    )
    conn.commit()
    return conn.execute("SELECT id FROM correlated_findings WHERE title = ?", (title,)).fetchone()["id"]


def test_get_pending_findings_returns_only_pending(db_conn):
    id1 = _insert_finding(db_conn, title="pending one")
    id2 = _insert_finding(db_conn, title="already accepted")
    accept_finding(db_conn, id2, "houda")

    pending = get_pending_findings(db_conn, "eng-1")

    assert len(pending) == 1
    assert pending[0].id == id1


def test_get_pending_findings_orders_by_risk_score_desc(db_conn):
    low = _insert_finding(db_conn, title="low risk", risk_score=2.0)
    high = _insert_finding(db_conn, title="high risk", risk_score=9.0)

    pending = get_pending_findings(db_conn, "eng-1")

    assert [p.id for p in pending] == [high, low]


def test_get_pending_findings_null_score_appears_last(db_conn):
    scored = _insert_finding(db_conn, title="scored", risk_score=5.0)
    unscored = _insert_finding(db_conn, title="unscored", risk_score=None)

    pending = get_pending_findings(db_conn, "eng-1")

    assert [p.id for p in pending] == [scored, unscored]


def test_get_pending_findings_filters_by_engagement(db_conn):
    _insert_finding(db_conn, engagement="eng-1", title="in scope")
    _insert_finding(db_conn, engagement="eng-2", title="other engagement")

    pending = get_pending_findings(db_conn, "eng-1")

    assert len(pending) == 1
    assert pending[0].title == "in scope"


def test_accept_finding_updates_status_and_logs(db_conn):
    finding_id = _insert_finding(db_conn)

    accept_finding(db_conn, finding_id, "houda", comment="confirme manuellement")

    row = db_conn.execute("SELECT review_status, reviewed_by, review_comment FROM correlated_findings WHERE id=?", (finding_id,)).fetchone()
    assert row["review_status"] == "accepted"
    assert row["reviewed_by"] == "houda"
    assert row["review_comment"] == "confirme manuellement"

    log = db_conn.execute("SELECT * FROM review_log WHERE finding_id=?", (finding_id,)).fetchone()
    assert log["decision"] == "accepted"
    assert log["analyst"] == "houda"


def test_edit_finding_updates_edited_fields(db_conn):
    finding_id = _insert_finding(db_conn)

    edit_finding(db_conn, finding_id, "houda", edited_title="Titre corrige", comment="titre trop vague")

    row = db_conn.execute("SELECT review_status, edited_title, edited_description FROM correlated_findings WHERE id=?", (finding_id,)).fetchone()
    assert row["review_status"] == "edited"
    assert row["edited_title"] == "Titre corrige"
    assert row["edited_description"] is None


def test_edit_finding_requires_at_least_one_field(db_conn):
    finding_id = _insert_finding(db_conn)
    with pytest.raises(ValueError):
        edit_finding(db_conn, finding_id, "houda")


def test_reject_finding_requires_comment(db_conn):
    finding_id = _insert_finding(db_conn)
    with pytest.raises(ValueError):
        reject_finding(db_conn, finding_id, "houda", comment="")


def test_reject_finding_with_comment_succeeds(db_conn):
    finding_id = _insert_finding(db_conn)
    reject_finding(db_conn, finding_id, "houda", comment="faux positif, service en realite patche")

    row = db_conn.execute("SELECT review_status FROM correlated_findings WHERE id=?", (finding_id,)).fetchone()
    assert row["review_status"] == "rejected"


def test_decision_on_unknown_finding_raises(db_conn):
    with pytest.raises(ValueError):
        accept_finding(db_conn, 9999, "houda")


def test_multiple_decisions_all_logged_in_review_log(db_conn):
    id1 = _insert_finding(db_conn, title="f1")
    id2 = _insert_finding(db_conn, title="f2")
    accept_finding(db_conn, id1, "houda")
    reject_finding(db_conn, id2, "houda", comment="non pertinent")

    logs = db_conn.execute("SELECT * FROM review_log ORDER BY id").fetchall()
    assert len(logs) == 2
