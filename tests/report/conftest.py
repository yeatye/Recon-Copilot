from __future__ import annotations

import pytest

from recon_copilot.report.models import ReportContext, ReportFinding


@pytest.fixture
def sample_context() -> ReportContext:
    return ReportContext(
        engagement="eng-test",
        generated_at="2026-01-01T00:00:00Z",
        findings=(
            ReportFinding(
                target="10.0.0.5",
                title="Injection SQL",
                description="Une injection SQL a ete identifiee sur le parametre id.",
                severity="critical",
                risk_score=9.1,
                risk_level="critical",
                remediation="Utiliser des requetes parametrees.",
                cve_refs=(),
                cwe_refs=("CWE-89",),
                mitre_refs=("T1190",),
                source_citation="matched-at: http://10.0.0.5/item?id=1",
                citation_verified=True,
                command_used="nmap -T3 -Pn -sV -oX - 10.0.0.5",
            ),
            ReportFinding(
                target="10.0.0.5",
                title="TLS obsolete",
                description="TLS 1.0 est accepte.",
                severity="low",
                risk_score=2.9,
                risk_level="low",
                remediation="Desactiver TLS 1.0/1.1.",
                cve_refs=(),
                cwe_refs=("CWE-326",),
                mitre_refs=(),
                source_citation="ssl-enum-ciphers: TLSv1.0",
                citation_verified=False,
                command_used=None,
            ),
        ),
        scope_allowed_targets=("10.0.0.0/24",),
        scope_excluded_targets=("10.0.0.254",),
    )


@pytest.fixture
def empty_context() -> ReportContext:
    return ReportContext(engagement="eng-empty", generated_at="2026-01-01T00:00:00Z", findings=())
