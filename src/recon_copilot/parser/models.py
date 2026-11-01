"""Modeles de donnees du module parser.

Le principe directeur : chaque objet structure garde un `source_fragment`
(ou `raw_line` + `line_number` pour Nuclei) qui est un extrait EXACT de la
sortie brute d'origine. Rien n'est reformule ici. C'est ce qui permettra a
la future etape de correlation LLM de citer une preuve verifiable au lieu
de paraphraser sans source.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class NmapScriptOutput:
    script_id: str
    output: str
    source_fragment: str  # element XML <script> brut correspondant


@dataclass(frozen=True)
class ParsedPort:
    number: int
    protocol: str  # "tcp" | "udp"
    state: str  # "open" | "closed" | "filtered" | ...
    service_name: str | None
    product: str | None
    version: str | None
    extra_info: str | None
    scripts: tuple[NmapScriptOutput, ...]
    source_fragment: str  # element XML <port> brut correspondant


@dataclass(frozen=True)
class ExtraPortsSummary:
    """Resume d'un groupe de ports dans le meme etat, tel que Nmap les compresse en XML.

    Quand un grand nombre de ports partagent le meme etat (typiquement
    "closed" ou "filtered"), Nmap ne genere PAS un <port> par port dans le
    XML : il emet un unique <extraports state=... count=.../>. Ignorer cet
    element donnerait l'impression qu'aucun port n'a ete scanne alors que
    c'est le resultat le plus frequent sur une cible correctement filtree.
    On ne reconstruit pas la liste exacte des ports concernes ici (elle
    n'est pas toujours fiable/presente selon la version de Nmap) : on
    consigne le compte et l'etat, honnetement.
    """

    state: str
    count: int
    source_fragment: str


@dataclass(frozen=True)
class ParsedHost:
    ip: str
    hostnames: tuple[str, ...]
    status: str  # "up" | "down"
    ports: tuple[ParsedPort, ...]
    extraports: tuple[ExtraPortsSummary, ...]  # ports groupes par etat (voir ExtraPortsSummary)
    source_fragment: str  # element XML <host> brut correspondant


@dataclass(frozen=True)
class NmapParseResult:
    hosts: tuple[ParsedHost, ...]
    parse_errors: tuple[str, ...]  # anomalies non-fatales rencontrees (jamais silencieuses)


@dataclass(frozen=True)
class NucleiDetection:
    template_id: str
    name: str | None
    severity: str
    matched_at: str
    tags: tuple[str, ...]
    description: str | None
    raw_line: str  # ligne JSONL brute exacte -- citable directement
    line_number: int  # position 1-indexee dans raw_output, pour tracabilite


@dataclass(frozen=True)
class NucleiParseResult:
    detections: tuple[NucleiDetection, ...]
    parse_errors: tuple[str, ...]  # lignes JSON invalides : signalees, jamais ignorees en silence
