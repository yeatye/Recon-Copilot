from __future__ import annotations

from recon_copilot.report.data import build_report_context
from recon_copilot.scope import ScopeConfig


def _insert_finding(conn, engagement="eng-1", target="10.0.0.5", source_type="nmap", title="F1"):
    conn.execute(
        """
        INSERT INTO correlated_findings
            (created_at, engagement, target, title, description, severity, cvss_score, confidence,
             source_type, source_citation, citation_verified, raw_llm_response, review_status)
        VALUES ('2026-01-01T00:00:00Z', ?, ?, ?, 'desc', 'high', 7.8, 'high',
                ?, 'citation', 1, '[]', 'accepted')
        """,
        (engagement, target, title, source_type),
    )
    conn.commit()


def _insert_raw_scan_result(conn, engagement, target, tool, command):
    conn.execute(
        """
        INSERT INTO raw_scan_results (timestamp, engagement, tool, target, aggressiveness, command, raw_output, exit_code)
        VALUES ('2026-01-01T00:00:00Z', ?, ?, ?, 'standard', ?, 'output', 0)
        """,
        (engagement, tool, target, command),
    )
    conn.commit()


def test_build_report_context_includes_command_used(db_conn):
    _insert_raw_scan_result(db_conn, "eng-1", "10.0.0.5", "nmap", "nmap -T3 -Pn -sV -oX - 10.0.0.5")
    _insert_finding(db_conn, title="F-nmap", source_type="nmap")

    context = build_report_context(db_conn, "eng-1")

    assert context.findings[0].command_used == "nmap -T3 -Pn -sV -oX - 10.0.0.5"


def test_build_report_context_command_used_none_when_no_raw_scan_result(db_conn):
    _insert_finding(db_conn, title="F-orphan", source_type="nmap")

    context = build_report_context(db_conn, "eng-1")

    assert context.findings[0].command_used is None


def test_build_report_context_uses_most_recent_command_for_same_target_tool(db_conn):
    _insert_raw_scan_result(db_conn, "eng-1", "10.0.0.5", "nmap", "nmap -T2 10.0.0.5")
    _insert_raw_scan_result(db_conn, "eng-1", "10.0.0.5", "nmap", "nmap -T4 -p- 10.0.0.5")
    _insert_finding(db_conn, title="F-nmap")

    context = build_report_context(db_conn, "eng-1")

    assert context.findings[0].command_used == "nmap -T4 -p- 10.0.0.5"


def test_build_report_context_matches_command_by_tool_not_just_target(db_conn):
    _insert_raw_scan_result(db_conn, "eng-1", "10.0.0.5", "nmap", "nmap -T3 10.0.0.5")
    _insert_raw_scan_result(db_conn, "eng-1", "10.0.0.5", "nuclei", "nuclei -target 10.0.0.5")
    _insert_finding(db_conn, title="F-nuclei", source_type="nuclei")

    context = build_report_context(db_conn, "eng-1")

    assert context.findings[0].command_used == "nuclei -target 10.0.0.5"


def test_build_report_context_no_scope_gives_empty_tuples(db_conn):
    context = build_report_context(db_conn, "eng-1")
    assert context.scope_allowed_targets == ()
    assert context.scope_excluded_targets == ()


def test_build_report_context_includes_provided_scope(db_conn):
    scope = ScopeConfig(allowed_targets=("10.0.0.0/24",), excluded_targets=("10.0.0.254",))
    context = build_report_context(db_conn, "eng-1", scope=scope)
    assert context.scope_allowed_targets == ("10.0.0.0/24",)
    assert context.scope_excluded_targets == ("10.0.0.254",)
