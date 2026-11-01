"""CLI unique du pipeline : `recon-copilot scan|review|report`.

Trois sous-commandes distinctes plutot qu'une seule commande "tout faire"
-- c'est le reflet direct de la contrainte du cahier des charges : la
revue humaine est une etape a part entiere, jamais automatisee, et le
rapport ne doit jamais se generer avant qu'elle ait eu lieu.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from recon_copilot.db import get_connection
from recon_copilot.pipeline import load_engagement_config, run_pipeline
from recon_copilot.report import generate_report
from recon_copilot.review.cli import run_review_session
from recon_copilot.scoring import AssetCriticality


def _cmd_scan(args: argparse.Namespace) -> None:
    summary = asyncio.run(
        run_pipeline(
            config_path=args.config,
            target=args.target,
            chosen_by=args.analyst,
            aggressiveness=args.profile,
            comment=args.comment or "",
            port=args.port,
            asset_criticality=AssetCriticality(args.criticality),
            enable_fuzzing=args.fuzz,
        )
    )
    print(f"Engagement       : {summary.engagement}")
    print(f"Cible            : {summary.target}")
    print(f"Profil           : {summary.aggressiveness}")
    print(f"Hotes parses     : {summary.hosts_parsed}")
    print(f"Detections Nuclei: {summary.nuclei_detections_parsed}")
    print(f"Findings proposes: {summary.findings_proposed} (dont {summary.findings_unverified_citations} a citation non verifiee)")
    if args.fuzz:
        print(f"Requetes fuzzing : {summary.fuzz_hits} ({summary.fuzz_anomalies} anomalies)")
    if summary.warnings:
        print(f"\n{len(summary.warnings)} avertissement(s) -- voir la table parse_errors pour le detail :")
        for w in summary.warnings[:10]:
            print(f"  - {w}")
    print("\nProchaine etape : `recon-copilot review` pour valider les findings avant rapport.")


def _cmd_review(args: argparse.Namespace) -> None:
    config = load_engagement_config(args.config)
    conn = get_connection(config.db_path)
    if args.tui:
        from recon_copilot.review.tui import run_tui  # import tardif : textual n'est requis que pour --tui

        run_tui(conn, config.name, args.analyst)
    else:
        run_review_session(conn, config.name, args.analyst)


def _cmd_report(args: argparse.Namespace) -> None:
    config = load_engagement_config(args.config)
    conn = get_connection(config.db_path)
    formats = tuple(args.formats.split(","))
    langs = tuple(args.langs.split(","))
    paths = generate_report(conn, config.name, args.output, formats=formats, langs=langs, scope=config.scope)
    print(f"{len(paths)} fichier(s) genere(s) dans {args.output} :")
    for p in paths:
        print(f"  - {p}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="recon-copilot", description="Copilote de reconnaissance assiste par IA")
    parser.add_argument("--config", required=True, help="Chemin vers engagement.yaml")

    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Scan + parsing + correlation + scoring (+ fuzzing optionnel) sur une cible")
    scan_p.add_argument("--target", required=True)
    scan_p.add_argument("--analyst", required=True)
    scan_p.add_argument("--profile", choices=["furtif", "standard", "agressif"], default=None)
    scan_p.add_argument("--port", type=int, default=None)
    scan_p.add_argument("--comment", default="")
    scan_p.add_argument("--criticality", choices=["low", "medium", "high"], default="medium")
    scan_p.add_argument("--fuzz", action="store_true", help="Active le fuzzing (ignore si le profil le desactive par defaut)")
    scan_p.set_defaults(func=_cmd_scan)

    review_p = sub.add_parser("review", help="Revue interactive des findings en attente")
    review_p.add_argument("--analyst", required=True)
    review_p.add_argument("--tui", action="store_true", help="Interface visuelle (Textual) au lieu de la CLI texte")
    review_p.set_defaults(func=_cmd_review)

    report_p = sub.add_parser("report", help="Genere le rapport a partir des findings acceptes/edites")
    report_p.add_argument("--output", required=True, help="Dossier de sortie")
    report_p.add_argument("--formats", default="md,docx,pdf", help="Formats separes par des virgules (md,docx,pdf,sarif,vex)")
    report_p.add_argument("--langs", default="fr,en", help="Langues separees par des virgules")
    report_p.set_defaults(func=_cmd_report)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except Exception as exc:  # noqa: BLE001 -- CLI : on affiche une erreur propre, pas une trace Python brute
        print(f"Erreur : {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
