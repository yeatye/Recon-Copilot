"""Generation du rapport au format Markdown."""

from __future__ import annotations

from recon_copilot.report.i18n import build_executive_summary, t
from recon_copilot.report.models import ReportContext


def generate_markdown(context: ReportContext, lang: str = "fr") -> str:
    lines: list[str] = []
    lines.append(f"# {t(lang, 'report_title')} -- {context.engagement}")
    lines.append("")
    lines.append(f"**{t(lang, 'engagement')}** : {context.engagement}  ")
    lines.append(f"**{t(lang, 'generated_at')}** : {context.generated_at}")
    lines.append("")

    lines.append(f"## {t(lang, 'exec_summary')}")
    lines.append("")
    lines.append(build_executive_summary(context.counts_by_severity(), lang))
    lines.append("")

    lines.append(f"## {t(lang, 'scope_section')}")
    lines.append("")
    if context.scope_allowed_targets or context.scope_excluded_targets:
        if context.scope_allowed_targets:
            lines.append(f"**{t(lang, 'scope_allowed')}** : {', '.join(context.scope_allowed_targets)}")
        if context.scope_excluded_targets:
            lines.append(f"**{t(lang, 'scope_excluded')}** : {', '.join(context.scope_excluded_targets)}")
    else:
        lines.append(t(lang, "scope_none"))
    lines.append("")

    lines.append(f"## {t(lang, 'methodology')}")
    lines.append("")
    lines.append(t(lang, "methodology_text"))
    lines.append("")

    lines.append(f"## {t(lang, 'findings_section')}")
    lines.append("")
    findings = context.sorted_by_severity()
    if not findings:
        lines.append(t(lang, "no_findings"))
    for f in findings:
        severity_label = t(lang, "severities")[f.severity]
        lines.append(f"### [{severity_label}] {f.title}")
        lines.append("")
        lines.append(f"- **{t(lang, 'target')}** : {f.target}")
        lines.append(f"- **{t(lang, 'severity')}** : {severity_label}")
        if f.risk_score is not None:
            lines.append(f"- **{t(lang, 'risk_score')}** : {f.risk_score}/10 ({f.risk_level})")
        if f.cve_refs:
            lines.append(f"- **{t(lang, 'cve_refs')}** : {', '.join(f.cve_refs)}")
        if f.cwe_refs:
            lines.append(f"- **{t(lang, 'cwe_refs')}** : {', '.join(f.cwe_refs)}")
        if f.mitre_refs:
            lines.append(f"- **{t(lang, 'mitre_refs')}** : {', '.join(f.mitre_refs)}")
        lines.append("")
        lines.append(f.description)
        lines.append("")
        if f.remediation:
            lines.append(f"**{t(lang, 'remediation')}** : {f.remediation}")
            lines.append("")
        if f.command_used:
            lines.append(f"**{t(lang, 'command_used')}** : `{f.command_used}`")
            lines.append("")
        lines.append(f"> **{t(lang, 'source_citation')}** : `{f.source_citation}`")
        if not f.citation_verified:
            lines.append(">")
            lines.append(f"> ⚠️ {t(lang, 'citation_unverified_warning')}")
        lines.append("")

    lines.append(f"## {t(lang, 'remediation_priorities')}")
    lines.append("")
    priority_findings = [f for f in findings if f.severity in ("critical", "high")]
    if not priority_findings:
        lines.append(t(lang, "no_findings"))
    for f in priority_findings:
        lines.append(f"- **{f.title}** ({t(lang, 'severities')[f.severity]}, {f.target}) -- {f.remediation}")

    return "\n".join(lines)
