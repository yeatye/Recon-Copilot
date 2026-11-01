"""Table statique CVE/CWE/MITRE ATT&CK embarquee dans le prompt (few-shot/lookup).

Volontairement PAS un flux CVE en direct ni du RAG : quelques entrees
representatives, choisies pour couvrir les familles de findings les plus
frequentes en pentest web/reseau. C'est un point de depart -- a enrichir
avec les templates Nuclei/services reellement rencontres en engagement.
Cle = identifiant de template Nuclei (correspondance exacte) OU nom de
service Nmap en minuscules (correspondance approximative), au choix de
l'appelant via lookup_by_template_id / lookup_by_service_name.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class KbEntry:
    cve_refs: tuple[str, ...]
    cwe_refs: tuple[str, ...]
    mitre_refs: tuple[str, ...]
    default_severity: str
    default_cvss: float | None
    remediation: str
    notes: str


# Cles = template-id Nuclei (correspondance exacte la plus courante en sortie -jsonl)
BY_NUCLEI_TEMPLATE: dict[str, KbEntry] = {
    "exposed-panel-generic": KbEntry(
        cve_refs=(),
        cwe_refs=("CWE-284",),
        mitre_refs=("T1595.002",),
        default_severity="medium",
        default_cvss=5.3,
        remediation="Restreindre l'acces au panel (authentification, IP allowlist) ou le retirer d'exposition publique.",
        notes="Panel d'administration expose publiquement sans preuve d'exploitation active.",
    ),
    "tls-version": KbEntry(
        cve_refs=(),
        cwe_refs=("CWE-326",),
        mitre_refs=("T1040",),
        default_severity="low",
        default_cvss=3.1,
        remediation="Desactiver TLS 1.0/1.1, forcer TLS 1.2+ avec des suites cryptographiques modernes.",
        notes="Version TLS depreciee acceptee par le serveur.",
    ),
    "default-login": KbEntry(
        cve_refs=(),
        cwe_refs=("CWE-521", "CWE-1392"),
        mitre_refs=("T1078.001",),
        default_severity="high",
        default_cvss=8.1,
        remediation="Changer les identifiants par defaut immediatement, forcer un changement au premier login.",
        notes="Identifiants par defaut fonctionnels detectes.",
    ),
    "sql-injection": KbEntry(
        cve_refs=(),
        cwe_refs=("CWE-89",),
        mitre_refs=("T1190",),
        default_severity="critical",
        default_cvss=9.8,
        remediation="Utiliser des requetes parametrees/prepared statements, valider et echapper toutes les entrees utilisateur.",
        notes="Injection SQL confirmee par le template Nuclei.",
    ),
}

# Cles = nom de service Nmap en minuscules (correspondance moins precise, sert de filet)
BY_SERVICE_NAME: dict[str, KbEntry] = {
    "ftp": KbEntry(
        cve_refs=(),
        cwe_refs=("CWE-319",),
        mitre_refs=("T1040",),
        default_severity="medium",
        default_cvss=5.9,
        remediation="Preferer SFTP/FTPS ; si FTP doit rester, restreindre son exposition reseau.",
        notes="FTP transmet les identifiants en clair par defaut.",
    ),
    "telnet": KbEntry(
        cve_refs=(),
        cwe_refs=("CWE-319",),
        mitre_refs=("T1040",),
        default_severity="high",
        default_cvss=7.5,
        remediation="Desactiver Telnet, migrer vers SSH.",
        notes="Protocole non chiffre, obsolete pour l'administration a distance.",
    ),
    "ssh": KbEntry(
        cve_refs=(),
        cwe_refs=("CWE-1391",),
        mitre_refs=("T1110",),
        default_severity="info",
        default_cvss=None,
        remediation="Verifier que l'authentification par mot de passe est desactivee au profit des cles, limiter les tentatives (fail2ban).",
        notes="Service SSH expose -- surface d'attaque a evaluer selon la config (pas une vulnerabilite en soi).",
    ),
}


def lookup_by_template_id(template_id: str) -> KbEntry | None:
    return BY_NUCLEI_TEMPLATE.get(template_id)


def lookup_by_service_name(service_name: str | None) -> KbEntry | None:
    if not service_name:
        return None
    return BY_SERVICE_NAME.get(service_name.lower())


def build_kb_context(template_ids: list[str], service_names: list[str]) -> str:
    """Formate les entrees pertinentes en texte few-shot pour le prompt de correlation.

    Ne renvoie QUE les entrees qui correspondent effectivement a quelque
    chose dans le scan courant -- pas toute la table -- pour garder le
    prompt court et eviter de "suggerer" au LLM des vulnerabilites hors
    sujet.
    """
    lines: list[str] = []
    seen: set[str] = set()

    for tid in template_ids:
        entry = lookup_by_template_id(tid)
        if entry and tid not in seen:
            seen.add(tid)
            lines.append(_format_entry(f"template Nuclei '{tid}'", entry))

    for name in service_names:
        entry = lookup_by_service_name(name)
        key = f"service:{name}"
        if entry and key not in seen:
            seen.add(key)
            lines.append(_format_entry(f"service '{name}'", entry))

    if not lines:
        return "(Aucune entree de la base de connaissances statique ne correspond a ce scan.)"
    return "\n".join(lines)


def _format_entry(label: str, entry: KbEntry) -> str:
    cve = ", ".join(entry.cve_refs) or "aucun"
    cwe = ", ".join(entry.cwe_refs) or "aucun"
    mitre = ", ".join(entry.mitre_refs) or "aucun"
    cvss = str(entry.default_cvss) if entry.default_cvss is not None else "N/A"
    return (
        f"- {label} : severite habituelle={entry.default_severity}, CVSS habituel={cvss}, "
        f"CVE={cve}, CWE={cwe}, MITRE={mitre}. Note: {entry.notes} "
        f"Remediation type: {entry.remediation}"
    )
