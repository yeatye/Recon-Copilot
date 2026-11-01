"""CLI de revue interactive.

Boucle simple : liste les findings 'pending' d'un engagement, un par un,
et demande a l'analyste d'accepter/editer/rejeter. Toute la logique
metier est dans review/__init__.py -- ce fichier ne fait que la saisie
utilisateur, pour rester facile a remplacer par une vraie interface web
plus tard sans toucher a la couche donnees.
"""

from __future__ import annotations

import argparse
import sqlite3

from recon_copilot.db import get_connection
from recon_copilot.review import accept_finding, edit_finding, get_pending_findings, reject_finding


def _prompt_decision() -> str:
    while True:
        choice = input("[a]ccepter / [e]diter / [r]ejeter / [s]auter -> ").strip().lower()
        if choice in ("a", "e", "r", "s"):
            return choice
        print("Choix invalide, reessaie (a/e/r/s).")


def run_review_session(conn: sqlite3.Connection, engagement: str, analyst: str) -> None:
    pending = get_pending_findings(conn, engagement)
    if not pending:
        print(f"Aucun finding en attente de revue pour l'engagement '{engagement}'.")
        return

    print(f"{len(pending)} finding(s) en attente pour '{engagement}'.\n")

    for finding in pending:
        print("=" * 70)
        print(f"[{finding.severity.upper()}] {finding.title}  (risk_score={finding.risk_score})")
        print(f"Cible : {finding.target}")
        print(f"Citation verifiee : {'oui' if finding.citation_verified else 'NON -- a verifier manuellement'}")
        print(f"Citation : {finding.source_citation[:200]}")
        print(f"\n{finding.description}\n")

        choice = _prompt_decision()
        if choice == "s":
            continue
        if choice == "a":
            comment = input("Commentaire (optionnel) : ").strip()
            accept_finding(conn, finding.id, analyst, comment)
        elif choice == "e":
            new_title = input(f"Nouveau titre (Entree pour garder '{finding.title}') : ").strip() or None
            new_desc = input("Nouvelle description (Entree pour garder l'actuelle) : ").strip() or None
            comment = input("Commentaire (optionnel) : ").strip()
            edit_finding(conn, finding.id, analyst, edited_title=new_title, edited_description=new_desc, comment=comment)
        elif choice == "r":
            comment = input("Raison du rejet (obligatoire) : ").strip()
            while not comment:
                comment = input("Raison du rejet (obligatoire, ne peut pas etre vide) : ").strip()
            reject_finding(conn, finding.id, analyst, comment)

    print("\nRevue terminee.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Revue interactive des findings recon-copilot")
    parser.add_argument("--db", required=True, help="Chemin vers la base SQLite de l'engagement")
    parser.add_argument("--engagement", required=True, help="Nom de l'engagement a revoir")
    parser.add_argument("--analyst", required=True, help="Ton nom (trace dans l'audit et review_log)")
    args = parser.parse_args()

    conn = get_connection(args.db)
    run_review_session(conn, args.engagement, args.analyst)


if __name__ == "__main__":
    main()
