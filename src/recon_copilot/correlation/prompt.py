"""Construction du prompt de correlation.

Le prompt embarque les extraits sources (source_fragment / raw_line) EN
TOUTES LETTRES, et l'instruction est explicite : le LLM doit copier la
citation mot pour mot depuis ces extraits, jamais en resumer ou en
inventer une. C'est ce qui rend `citation_verified` (voir response_parser.py)
verifiable : on sait exactement quel texte source etait disponible.

Pour Nuclei, `raw_line` peut faire plusieurs Ko (reponse HTTP complete
embarquee) -- demander au LLM d'en extraire un morceau exact a la main
s'est revele peu fiable en usage reel, meme avec un modele 32B a
temperature 0 (il reconstruit un JSON "a peu pres valide" en supprimant
des champs au passage, ce qui casse la correspondance exacte). Plutot que
de compter sur l'extraction libre, `_nuclei_candidate_citations()`
precalcule des sous-chaines COURTES et VERIFIEES exactes de `raw_line`,
et le prompt ne demande au LLM que de recopier l'une d'entre elles.
"""

from __future__ import annotations

import re

from recon_copilot.parser.models import ParsedHost
from recon_copilot.parser.nuclei_parser import NucleiDetection

SYSTEM_PROMPT = (
    "Tu es un assistant d'analyse pour un pentester. Tu recois des donnees "
    "de scan BRUTES (Nmap et Nuclei) et une base de connaissances statique. "
    "Ton role est de proposer des findings de securite plausibles, chacun "
    "OBLIGATOIREMENT appuye par une citation EXACTE d'une ligne des donnees "
    "fournies. Tu ne dois JAMAIS inventer une citation qui ne figure pas "
    "mot pour mot dans les donnees sources. Si tu n'es pas sur, indique une "
    "confiance 'low' plutot que d'inventer. "
    "IMPORTANT sur la citation : choisis toujours un extrait COURT (quelques "
    "mots a une phrase, jamais un champ entier tel que 'response' qui peut "
    "etre tres long) qui existe mot pour mot dans les donnees. Ne resume "
    "JAMAIS une citation et n'utilise JAMAIS '...' pour raccourcir un extrait "
    "-- un extrait court et exact vaut mieux qu'un extrait long et modifie. "
    "Reponds UNIQUEMENT avec un tableau JSON valide, sans texte avant ou "
    "apres, sans balises markdown."
)

_FINDING_SCHEMA_HINT = """\
Chaque element du tableau JSON doit avoir exactement ces champs :
{
  "title": "titre court",
  "description": "explication du finding",
  "severity": "info|low|medium|high|critical",
  "cvss_score": nombre ou null,
  "confidence": "low|medium|high",
  "source_type": "nmap" ou "nuclei",
  "source_citation": "extrait COURT (quelques mots) copie mot pour mot, jamais tronque avec '...'",
  "cve_refs": ["CVE-..."] ou [],
  "cwe_refs": ["CWE-..."] ou [],
  "mitre_refs": ["T..."] ou [],
  "remediation": "recommandation concrete"
}
Si aucun finding pertinent n'est identifiable, reponds avec un tableau vide [].
"""


def _host_section(host: ParsedHost) -> str:
    lines = [f"=== Hote Nmap : {host.ip} (status={host.status}) ==="]
    lines.append(f"Fragment source hote : {host.source_fragment}")
    for extra in host.extraports:
        lines.append(f"Fragment source ports groupes : {extra.source_fragment}")
    for port in host.ports:
        lines.append(
            f"Port {port.number}/{port.protocol} etat={port.state} "
            f"service={port.service_name} produit={port.product} version={port.version}"
        )
        lines.append(f"Fragment source port : {port.source_fragment}")
        for script in port.scripts:
            lines.append(f"Fragment source script {script.script_id} : {script.source_fragment}")
    return "\n".join(lines)


def _nuclei_candidate_citations(d: NucleiDetection) -> list[str]:
    """Sous-chaines COURTES et VERIFIEES exactes de d.raw_line, proposees
    comme citations sures. On ne demande jamais au LLM d'extraire a la main
    depuis un raw_line potentiellement enorme -- c'est cette extraction
    libre qui produisait des citations reformulees en usage reel.

    Extraction par regex (pas construction a la main) : ne suppose jamais
    un espacement JSON precis (compact vs avec espaces apres ':'). Le nuclei
    reel observe en usage produit du JSON compact, mais construire la
    chaine "a la main" plutot que l'extraire du texte reel est fragile des
    que le format differe un peu -- constate en testant ce module."""
    candidates = []
    patterns = [
        rf'"template-id"\s*:\s*"{re.escape(d.template_id)}"',
        rf'"matched-at"\s*:\s*"{re.escape(d.matched_at)}"',
        r'"matcher-name"\s*:\s*"[^"]*"',
        r'"extracted-results"\s*:\s*\[[^\]]{0,300}\]',
    ]
    for pattern in patterns:
        m = re.search(pattern, d.raw_line)
        if m:
            candidates.append(m.group(0))
    # Filet de securite : ne jamais proposer une candidate qui ne serait
    # pas reellement une sous-chaine exacte de raw_line (regex mal formee,
    # champ absent, etc.) -- garantie meme si un pattern ci-dessus a un bug.
    return [c for c in candidates if c in d.raw_line]


def _nuclei_section(detections: list[NucleiDetection]) -> str:
    if not detections:
        return "=== Detections Nuclei : aucune ==="
    lines = ["=== Detections Nuclei ==="]
    for d in detections:
        lines.append(f"[{d.severity}] {d.name or d.template_id}")
        if d.description:
            lines.append(f"  Description (contexte pour redaction, NE PAS citer mot pour mot) : {d.description}")
        candidates = _nuclei_candidate_citations(d)
        lines.append("  Pour source_citation, copie UNE des chaines suivantes EXACTEMENT, caractere pour caractere :")
        for c in candidates:
            lines.append(f"    {c}")
    return "\n".join(lines)


def build_correlation_prompt(
    host: ParsedHost | None,
    nuclei_detections: list[NucleiDetection],
    kb_context: str,
    rag_context: str | None = None,
) -> str:
    """`rag_context` est optionnel et additif : a `None` (defaut), le prompt
    genere est IDENTIQUE a avant l'introduction du module RAG -- aucune
    section supplementaire n'est ajoutee. C'est ce qui garantit la
    retrocompatibilite des tests et du comportement existant.
    """
    sections = []
    if host is not None:
        sections.append(_host_section(host))
    sections.append(_nuclei_section(nuclei_detections))
    sections.append("=== Base de connaissances statique (CVE/CWE/MITRE) ===\n" + kb_context)
    if rag_context:
        sections.append(
            "=== Contexte RAG (recherche semantique, CISA KEV / templates Nuclei) ===\n"
            "Ces elements sont recuperes automatiquement par similarite -- ils peuvent "
            "etre partiellement pertinents ou pas du tout. Utilise-les comme piste "
            "supplementaire, jamais comme verite absolue.\n" + rag_context
        )
    sections.append(_FINDING_SCHEMA_HINT)

    return "\n\n".join(sections)
