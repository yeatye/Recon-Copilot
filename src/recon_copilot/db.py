"""Acces SQLite partage.

Un seul fichier de schema pour tout le pipeline evite les migrations
divergentes module par module. Chaque module (scanner, parser, correlation,
...) ajoutera ses propres tables ici au fur et a mesure de sa livraison,
mais la connexion et l'initialisation restent centralisees.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,       -- scan_start | scan_complete | scan_error | scope_violation | fuzz_start | ...
    target TEXT,
    port INTEGER,
    aggressiveness TEXT,
    chosen_by TEXT,
    comment TEXT,
    command TEXT,                   -- commande externe exacte executee (nmap/nuclei/ffuf), si applicable
    detail TEXT                     -- JSON libre pour tout contexte additionnel
);

CREATE TABLE IF NOT EXISTS raw_scan_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    engagement TEXT NOT NULL,
    tool TEXT NOT NULL,             -- 'nmap' | 'nuclei'
    target TEXT NOT NULL,
    aggressiveness TEXT NOT NULL,
    command TEXT NOT NULL,
    raw_output TEXT NOT NULL,       -- sortie brute (XML pour nmap, JSONL pour nuclei)
    exit_code INTEGER NOT NULL
);

-- Tables du module parser : normalisation des sorties brutes ci-dessus.
-- Chaque ligne garde un lien vers raw_scan_results ET un `source_fragment`
-- (extrait exact de la sortie brute qui la justifie), pour que la future
-- etape de correlation LLM puisse citer une source verifiable plutot que
-- de paraphraser sans preuve.

CREATE TABLE IF NOT EXISTS parsed_hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    raw_scan_result_id INTEGER NOT NULL REFERENCES raw_scan_results(id),
    engagement TEXT NOT NULL,
    ip TEXT NOT NULL,
    hostnames TEXT,                 -- JSON list
    status TEXT NOT NULL,           -- 'up' | 'down'
    source_fragment TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS parsed_ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    parsed_host_id INTEGER NOT NULL REFERENCES parsed_hosts(id),
    number INTEGER NOT NULL,
    protocol TEXT NOT NULL,         -- 'tcp' | 'udp'
    state TEXT NOT NULL,            -- 'open' | 'closed' | 'filtered' | ...
    service_name TEXT,
    product TEXT,
    version TEXT,
    extra_info TEXT,
    source_fragment TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS parsed_extraports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    parsed_host_id INTEGER NOT NULL REFERENCES parsed_hosts(id),
    state TEXT NOT NULL,            -- 'closed' | 'filtered' | ...
    count INTEGER NOT NULL,         -- nombre de ports Nmap a groupes dans cet etat
    source_fragment TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nmap_script_outputs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    parsed_port_id INTEGER NOT NULL REFERENCES parsed_ports(id),
    script_id TEXT NOT NULL,
    output TEXT NOT NULL,
    source_fragment TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nuclei_detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    raw_scan_result_id INTEGER NOT NULL REFERENCES raw_scan_results(id),
    engagement TEXT NOT NULL,
    template_id TEXT NOT NULL,
    name TEXT,
    severity TEXT NOT NULL,
    matched_at TEXT NOT NULL,
    tags TEXT,                      -- JSON list
    description TEXT,
    raw_line TEXT NOT NULL,         -- ligne JSONL exacte, citable telle quelle
    line_number INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS parse_errors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    raw_scan_result_id INTEGER,
    tool TEXT NOT NULL,             -- 'nmap' | 'nuclei' | 'correlation' | 'fuzzing'
    detail TEXT NOT NULL            -- jamais silencieux : toute ligne/element non parsable finit ici
);

-- Module correlation (etape 3) : findings proposes par le LLM, TOUJOURS
-- rattaches a une citation verifiee contre les donnees sources reelles.
CREATE TABLE IF NOT EXISTS correlated_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    engagement TEXT NOT NULL,
    target TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,             -- info|low|medium|high|critical
    cvss_score REAL,
    confidence TEXT NOT NULL,           -- low|medium|high (confiance du LLM dans sa propre correlation)
    source_type TEXT NOT NULL,          -- 'nmap' | 'nuclei'
    source_citation TEXT NOT NULL,      -- extrait cite par le LLM
    citation_verified INTEGER NOT NULL, -- 1 si source_citation est bien un extrait reel des donnees fournies
    cve_refs TEXT,                      -- JSON list
    cwe_refs TEXT,                      -- JSON list
    mitre_refs TEXT,                    -- JSON list
    remediation TEXT,
    raw_llm_response TEXT NOT NULL,     -- reponse brute complete, pour audit/debug
    -- rempli par le module scoring :
    risk_score REAL,
    risk_level TEXT,
    asset_criticality TEXT,
    -- rempli par le module review :
    review_status TEXT NOT NULL DEFAULT 'pending',  -- pending|accepted|edited|rejected
    reviewed_by TEXT,
    reviewed_at TEXT,
    review_comment TEXT,
    edited_title TEXT,
    edited_description TEXT
);

CREATE TABLE IF NOT EXISTS review_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    finding_id INTEGER NOT NULL REFERENCES correlated_findings(id),
    analyst TEXT NOT NULL,
    decision TEXT NOT NULL,             -- accepted|edited|rejected
    comment TEXT
);

-- Module fuzzing (etape 4)
CREATE TABLE IF NOT EXISTS fuzz_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    engagement TEXT NOT NULL,
    target_url TEXT NOT NULL,
    payload TEXT NOT NULL,
    status_code INTEGER,
    body_size INTEGER,
    response_time_ms REAL,
    is_anomaly INTEGER NOT NULL,
    triage_explanation TEXT,            -- rempli seulement pour les anomalies (triage LLM groupe)
    triage_severity_guess TEXT
);
"""


def get_connection(db_path: str | Path) -> sqlite3.Connection:
    """Ouvre (et initialise si besoin) la base SQLite du pipeline."""
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    conn.commit()
    return conn
