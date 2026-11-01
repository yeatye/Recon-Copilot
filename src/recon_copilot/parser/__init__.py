"""Facade du module parser.

Point d'entree unique pour le reste du pipeline : `parse_and_store()`.
Elle lit un `RawScanResult` (tel que retourne par `scanner.run_scan`),
le normalise via le bon parseur (Nmap ou Nuclei), persiste le resultat
structure en base, et retourne l'objet parse -- ou `None` si la sortie
n'etait pas exploitable (auquel cas l'erreur est quand meme tracee dans
`parse_errors`, jamais perdue silencieusement).
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

from recon_copilot.parser.models import NmapParseResult, NucleiParseResult
from recon_copilot.parser.nmap_parser import NmapParseError, parse_nmap_xml
from recon_copilot.parser.nuclei_parser import parse_nuclei_jsonl
from recon_copilot.scanner.models import RawScanResult

__all__ = [
    "NmapParseError",
    "NmapParseResult",
    "NucleiParseResult",
    "parse_raw_result",
    "parse_and_store",
]


def parse_raw_result(result: RawScanResult) -> NmapParseResult | NucleiParseResult:
    """Dispatch pur (aucun acces base) : nmap -> NmapParseResult, nuclei -> NucleiParseResult."""
    if result.tool == "nmap":
        return parse_nmap_xml(result.raw_output)
    if result.tool == "nuclei":
        return parse_nuclei_jsonl(result.raw_output)
    raise ValueError(f"outil inconnu du parser: {result.tool!r}")


def _log_parse_error(conn: sqlite3.Connection, raw_scan_result_id: int | None, tool: str, detail: str) -> None:
    conn.execute(
        "INSERT INTO parse_errors (timestamp, raw_scan_result_id, tool, detail) VALUES (?, ?, ?, ?)",
        (datetime.now(timezone.utc).isoformat(), raw_scan_result_id, tool, detail),
    )
    conn.commit()


def _store_nmap(conn: sqlite3.Connection, engagement: str, raw_scan_result_id: int, parsed: NmapParseResult) -> None:
    for host in parsed.hosts:
        cursor = conn.execute(
            """
            INSERT INTO parsed_hosts (raw_scan_result_id, engagement, ip, hostnames, status, source_fragment)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (raw_scan_result_id, engagement, host.ip, json.dumps(list(host.hostnames)), host.status, host.source_fragment),
        )
        host_id = cursor.lastrowid
        for extra in host.extraports:
            conn.execute(
                """
                INSERT INTO parsed_extraports (parsed_host_id, state, count, source_fragment)
                VALUES (?, ?, ?, ?)
                """,
                (host_id, extra.state, extra.count, extra.source_fragment),
            )
        for port in host.ports:
            port_cursor = conn.execute(
                """
                INSERT INTO parsed_ports
                    (parsed_host_id, number, protocol, state, service_name, product, version, extra_info, source_fragment)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    host_id,
                    port.number,
                    port.protocol,
                    port.state,
                    port.service_name,
                    port.product,
                    port.version,
                    port.extra_info,
                    port.source_fragment,
                ),
            )
            port_id = port_cursor.lastrowid
            for script in port.scripts:
                conn.execute(
                    """
                    INSERT INTO nmap_script_outputs (parsed_port_id, script_id, output, source_fragment)
                    VALUES (?, ?, ?, ?)
                    """,
                    (port_id, script.script_id, script.output, script.source_fragment),
                )
    conn.commit()
    for err in parsed.parse_errors:
        _log_parse_error(conn, raw_scan_result_id, "nmap", err)


def _store_nuclei(conn: sqlite3.Connection, engagement: str, raw_scan_result_id: int, parsed: NucleiParseResult) -> None:
    for det in parsed.detections:
        conn.execute(
            """
            INSERT INTO nuclei_detections
                (raw_scan_result_id, engagement, template_id, name, severity, matched_at, tags, description, raw_line, line_number)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                raw_scan_result_id,
                engagement,
                det.template_id,
                det.name,
                det.severity,
                det.matched_at,
                json.dumps(list(det.tags)),
                det.description,
                det.raw_line,
                det.line_number,
            ),
        )
    conn.commit()
    for err in parsed.parse_errors:
        _log_parse_error(conn, raw_scan_result_id, "nuclei", err)


def parse_and_store(
    conn: sqlite3.Connection, engagement: str, result: RawScanResult
) -> NmapParseResult | NucleiParseResult | None:
    """Parse `result` et persiste le resultat structure. Requiert `result.db_id` (rempli par run_scan()).

    Retourne `None` si la sortie n'etait pas exploitable (ex: Nmap tue par
    timeout, XML tronque) -- dans ce cas l'echec est trace dans
    `parse_errors`, jamais leve silencieusement plus haut dans le pipeline.
    """
    if result.db_id is None:
        raise ValueError(
            "result.db_id est vide -- ce RawScanResult n'a pas ete persiste par run_scan(), "
            "impossible de le rattacher a un raw_scan_result_id"
        )

    try:
        parsed = parse_raw_result(result)
    except NmapParseError as exc:
        _log_parse_error(conn, result.db_id, result.tool, str(exc))
        return None

    if isinstance(parsed, NmapParseResult):
        _store_nmap(conn, engagement, result.db_id, parsed)
    else:
        _store_nuclei(conn, engagement, result.db_id, parsed)

    return parsed
