"""Libelles bilingues FR/EN pour le rapport.

Le contenu dynamique (titres/descriptions des findings) reste dans la
langue ou il a ete produit par le LLM (generalement l'anglais pour les
CVE/CWE, ce qui est normal et attendu dans un rapport de pentest) --
seuls les libelles STRUCTURELS du rapport (titres de section, en-tetes de
tableau) sont traduits ici. Traduire automatiquement le contenu dynamique
demanderait un appel LLM supplementaire et un risque de derive non
maitrise ; ce n'est pas fait par ce module (voir README).
"""

from __future__ import annotations

LABELS = {
    "fr": {
        "report_title": "Rapport de test d'intrusion",
        "exec_summary": "Resume executif",
        "methodology": "Methodologie",
        "findings_section": "Constatations techniques",
        "remediation_priorities": "Remediation prioritaire",
        "engagement": "Engagement",
        "generated_at": "Genere le",
        "severity": "Severite",
        "risk_score": "Score de risque",
        "target": "Cible",
        "remediation": "Remediation",
        "source_citation": "Preuve (extrait source)",
        "citation_unverified_warning": (
            "ATTENTION : citation non verifiee automatiquement contre les donnees sources -- "
            "a confirmer manuellement avant tout envoi au client."
        ),
        "no_findings": "Aucune constatation retenue pour ce rapport.",
        "cve_refs": "CVE",
        "cwe_refs": "CWE",
        "mitre_refs": "MITRE ATT&CK",
        "command_used": "Commande utilisee",
        "scope_section": "Perimetre de l'engagement",
        "scope_allowed": "Cibles autorisees",
        "scope_excluded": "Cibles explicitement exclues",
        "scope_none": "Aucun perimetre renseigne.",
        "severities": {"critical": "Critique", "high": "Elevee", "medium": "Moyenne", "low": "Faible", "info": "Information"},
        "methodology_text": (
            "Ce test d'intrusion a ete conduit selon une methodologie manuelle a faible agressivite, "
            "assistee par des outils automatises (Nmap, Nuclei, ffuf) dont les resultats ont ete "
            "correles, notes et revus individuellement par un analyste humain avant integration a ce "
            "rapport. Aucune constatation n'est incluse sans validation explicite de l'analyste."
        ),
    },
    "en": {
        "report_title": "Penetration Test Report",
        "exec_summary": "Executive Summary",
        "methodology": "Methodology",
        "findings_section": "Technical Findings",
        "remediation_priorities": "Remediation Priorities",
        "engagement": "Engagement",
        "generated_at": "Generated on",
        "severity": "Severity",
        "risk_score": "Risk score",
        "target": "Target",
        "remediation": "Remediation",
        "source_citation": "Evidence (source excerpt)",
        "citation_unverified_warning": (
            "WARNING: citation was not automatically verified against source data -- "
            "confirm manually before sending to the client."
        ),
        "no_findings": "No findings retained for this report.",
        "cve_refs": "CVE",
        "cwe_refs": "CWE",
        "mitre_refs": "MITRE ATT&CK",
        "command_used": "Command used",
        "scope_section": "Engagement Scope",
        "scope_allowed": "Authorized targets",
        "scope_excluded": "Explicitly excluded targets",
        "scope_none": "No scope information provided.",
        "severities": {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"},
        "methodology_text": (
            "This penetration test was conducted using a manual, low-aggression methodology, "
            "assisted by automated tooling (Nmap, Nuclei, ffuf) whose output was correlated, "
            "scored, and individually reviewed by a human analyst before inclusion in this report. "
            "No finding is included without explicit analyst validation."
        ),
    },
}


def t(lang: str, key: str):
    return LABELS[lang][key]


def build_executive_summary(counts: dict[str, int], lang: str) -> str:
    total = sum(counts.values())
    if lang == "fr":
        if total == 0:
            return "Aucune constatation validee n'a ete identifiee lors de cet engagement."
        parts = [f"{counts[s]} {LABELS['fr']['severities'][s].lower()}" for s in ("critical", "high", "medium", "low", "info") if counts[s]]
        return (
            f"Cet engagement a permis d'identifier {total} constatation(s) validee(s) par l'analyste : "
            f"{', '.join(parts)}. Les constatations de severite critique et elevee doivent faire l'objet "
            f"d'une remediation prioritaire (voir section dediee)."
        )
    else:
        if total == 0:
            return "No validated findings were identified during this engagement."
        parts = [f"{counts[s]} {LABELS['en']['severities'][s].lower()}" for s in ("critical", "high", "medium", "low", "info") if counts[s]]
        return (
            f"This engagement identified {total} analyst-validated finding(s): {', '.join(parts)}. "
            f"Critical and high severity findings should be prioritized for remediation "
            f"(see dedicated section)."
        )
