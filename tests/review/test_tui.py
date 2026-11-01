from __future__ import annotations

from recon_copilot.review.tui import ReviewApp


def _seed_finding(conn, engagement="eng-tui", title="Finding test", citation_verified=1, target="10.0.0.5"):
    conn.execute(
        """
        INSERT INTO correlated_findings
            (created_at, engagement, target, title, description, severity, cvss_score, confidence,
             source_type, source_citation, citation_verified, raw_llm_response, risk_score)
        VALUES ('2026-01-01T00:00:00Z', ?, ?, ?, 'description du finding', 'high', 7.8, 'high',
                'nuclei', 'citation exacte', ?, '[]', 6.5)
        """,
        (engagement, target, title, citation_verified),
    )
    conn.commit()
    return conn.execute("SELECT id FROM correlated_findings WHERE title = ?", (title,)).fetchone()["id"]


async def test_tui_loads_pending_findings_into_table(db_conn):
    _seed_finding(db_conn, title="F1")
    _seed_finding(db_conn, title="F2")
    app = ReviewApp(db_conn, "eng-tui", "houda")

    async with app.run_test() as pilot:
        table = app.query_one("DataTable")
        assert table.row_count == 2


async def test_tui_shows_citation_verified_marker_green(db_conn):
    _seed_finding(db_conn, title="Verifiee", citation_verified=1)
    app = ReviewApp(db_conn, "eng-tui", "houda")

    async with app.run_test() as pilot:
        table = app.query_one("DataTable")
        row = table.get_row_at(0)
        assert "verifiee" in str(row[3]) and "\u2713" in str(row[3])


async def test_tui_shows_citation_unverified_marker_red(db_conn):
    _seed_finding(db_conn, title="Non verifiee", citation_verified=0)
    app = ReviewApp(db_conn, "eng-tui", "houda")

    async with app.run_test() as pilot:
        table = app.query_one("DataTable")
        row = table.get_row_at(0)
        assert "NON verifiee" in str(row[3]) and "\u2717" in str(row[3])


async def test_tui_accept_action_updates_database(db_conn):
    finding_id = _seed_finding(db_conn, title="A accepter")
    app = ReviewApp(db_conn, "eng-tui", "houda")

    async with app.run_test() as pilot:
        table = app.query_one("DataTable")
        table.cursor_coordinate = table.cursor_coordinate  # force la selection de la ligne 0
        await pilot.press("a")
        await pilot.pause()
        # la modale de commentaire est maintenant ouverte -- on valide directement (commentaire optionnel)
        await pilot.press("enter")
        await pilot.pause()

    row = db_conn.execute(
        "SELECT review_status, reviewed_by FROM correlated_findings WHERE id = ?", (finding_id,)
    ).fetchone()
    assert row["review_status"] == "accepted"
    assert row["reviewed_by"] == "houda"


async def test_tui_reject_requires_non_empty_comment(db_conn):
    finding_id = _seed_finding(db_conn, title="A rejeter")
    app = ReviewApp(db_conn, "eng-tui", "houda")

    async with app.run_test() as pilot:
        await pilot.press("r")
        await pilot.pause()
        # tente de valider sans rien saisir -- doit rester bloque (rejet exige une raison)
        await pilot.press("enter")
        await pilot.pause()

    row = db_conn.execute("SELECT review_status FROM correlated_findings WHERE id = ?", (finding_id,)).fetchone()
    assert row["review_status"] == "pending"  # toujours en attente, le rejet vide a ete refuse


async def test_tui_reject_with_comment_updates_database(db_conn):
    finding_id = _seed_finding(db_conn, title="A rejeter avec raison")
    app = ReviewApp(db_conn, "eng-tui", "houda")

    async with app.run_test() as pilot:
        await pilot.press("r")
        await pilot.pause()
        for ch in "faux positif":
            await pilot.press(ch if ch != " " else "space")
        await pilot.press("enter")
        await pilot.pause()

    row = db_conn.execute(
        "SELECT review_status, review_comment FROM correlated_findings WHERE id = ?", (finding_id,)
    ).fetchone()
    assert row["review_status"] == "rejected"
    assert "faux positif" in row["review_comment"]


async def test_tui_refresh_removes_reviewed_finding_from_table(db_conn):
    _seed_finding(db_conn, title="Sera acceptee")
    app = ReviewApp(db_conn, "eng-tui", "houda")

    async with app.run_test() as pilot:
        await pilot.press("a")
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()

        table = app.query_one("DataTable")
        assert table.row_count == 0  # plus rien en attente


async def test_tui_empty_engagement_shows_no_findings_message(db_conn):
    app = ReviewApp(db_conn, "eng-vide", "houda")

    async with app.run_test() as pilot:
        table = app.query_one("DataTable")
        assert table.row_count == 0
        detail_widget = app.query_one("#detail-text")
        assert "Aucun finding" in str(detail_widget._Static__content)


async def test_tui_only_shows_findings_for_correct_engagement(db_conn):
    _seed_finding(db_conn, engagement="eng-a", title="Dans eng-a")
    _seed_finding(db_conn, engagement="eng-b", title="Dans eng-b")
    app = ReviewApp(db_conn, "eng-a", "houda")

    async with app.run_test() as pilot:
        table = app.query_one("DataTable")
        assert table.row_count == 1
