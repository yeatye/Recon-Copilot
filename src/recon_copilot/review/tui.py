"""TUI (Textual) de revue -- alternative moderne a la CLI textuelle
(review/cli.py), pour le meme flux : accepter/editer/rejeter en 1-2
actions clavier, avec le statut `citation_verified` visible immediatement
(vert/rouge) sans avoir a ouvrir chaque finding.

Reutilise EXACTEMENT la meme couche de donnees que la CLI classique
(review/__init__.py) -- aucune logique metier ici, uniquement de
l'affichage et de la saisie. C'est ce qui garantit que TUI et CLI
produisent des resultats identiques en base (meme review_log, meme
review_status) quel que soit celui utilise.

Lancement : `recon-copilot review --tui` (voir cli.py). La CLI textuelle
classique reste le comportement par defaut (`recon-copilot review` sans
`--tui`) -- retrocompatibilite totale.
"""

from __future__ import annotations

import sqlite3

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, Footer, Header, Input, Static, TextArea

from recon_copilot.review import PendingFinding, accept_finding, edit_finding, get_pending_findings, reject_finding

_SEVERITY_COLOR = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "dim",
}


class CommentModal(ModalScreen[str | None]):
    """Modale generique pour saisir un commentaire (revue rapide) ou une
    raison de rejet (obligatoire). Retourne le texte saisi, ou None si
    annule (Escape) -- jamais un accept/reject silencieux sans confirmation
    explicite."""

    BINDINGS = [Binding("escape", "cancel", "Annuler")]

    def __init__(self, title: str, required: bool = False) -> None:
        super().__init__()
        self._title = title
        self._required = required

    def compose(self) -> ComposeResult:
        with Vertical(id="modal-box"):
            yield Static(self._title, id="modal-title")
            yield Input(placeholder="Commentaire..." if not self._required else "Raison (obligatoire)...", id="comment-input")
            with Vertical(id="modal-buttons"):
                yield Button("Valider", variant="primary", id="submit")
                yield Button("Annuler", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "submit":
            self._submit()
        else:
            self.dismiss(None)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Valide egalement sur Entree dans le champ -- pas seulement au clic
        sur le bouton, pour rester utilisable au clavier a 1-2 touches."""
        self._submit()

    def _submit(self) -> None:
        value = self.query_one("#comment-input", Input).value.strip()
        if self._required and not value:
            self.query_one("#comment-input", Input).placeholder = "Raison obligatoire -- ne peut pas etre vide !"
            return
        self.dismiss(value)

    def action_cancel(self) -> None:
        self.dismiss(None)


class EditModal(ModalScreen[tuple[str, str, str] | None]):
    """Modale d'edition : nouveau titre + nouvelle description + commentaire.
    Champs vides = on garde la valeur actuelle (voir review.edit_finding)."""

    BINDINGS = [Binding("escape", "cancel", "Annuler")]

    def __init__(self, current_title: str) -> None:
        super().__init__()
        self._current_title = current_title

    def compose(self) -> ComposeResult:
        with Vertical(id="modal-box"):
            yield Static(f"Editer : {self._current_title}", id="modal-title")
            yield Input(placeholder="Nouveau titre (vide = garder l'actuel)", id="edit-title")
            yield TextArea(id="edit-description")
            yield Input(placeholder="Commentaire...", id="edit-comment")
            with Vertical(id="modal-buttons"):
                yield Button("Valider", variant="primary", id="submit")
                yield Button("Annuler", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "submit":
            self._submit()
        else:
            self.dismiss(None)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self._submit()

    def _submit(self) -> None:
        title = self.query_one("#edit-title", Input).value.strip()
        description = self.query_one("#edit-description", TextArea).text.strip()
        comment = self.query_one("#edit-comment", Input).value.strip()
        self.dismiss((title, description, comment))

    def action_cancel(self) -> None:
        self.dismiss(None)


class ReviewApp(App):
    """Application Textual de revue. Une ligne par finding 'pending',
    triees par risk_score decroissant (meme ordre que la CLI classique)."""

    CSS = """
    #modal-box { width: 60; height: auto; border: thick $primary; padding: 1 2; background: $surface; }
    #modal-buttons { layout: horizontal; height: auto; align: right middle; }
    #modal-buttons Button { margin-left: 1; }
    #detail-panel { height: 1fr; border: round $primary; padding: 1 2; }
    DataTable { height: 60%; }
    """

    BINDINGS = [
        Binding("a", "accept", "Accepter"),
        Binding("e", "edit", "Editer"),
        Binding("r", "reject", "Rejeter"),
        Binding("q", "quit", "Quitter"),
    ]

    def __init__(self, conn: sqlite3.Connection, engagement: str, analyst: str) -> None:
        super().__init__()
        self._conn = conn
        self._engagement = engagement
        self._analyst = analyst
        self._findings: list[PendingFinding] = []

    def compose(self) -> ComposeResult:
        yield Header()
        yield DataTable(id="findings-table")
        with VerticalScroll(id="detail-panel"):
            yield Static("Selectionne un finding pour voir le detail.", id="detail-text")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("Severite", "Titre", "Score", "Citation", "Cible")
        table.cursor_type = "row"
        self.refresh_findings()

    def refresh_findings(self) -> None:
        self._findings = get_pending_findings(self._conn, self._engagement)
        table = self.query_one(DataTable)
        table.clear()
        for f in self._findings:
            color = _SEVERITY_COLOR.get(f.severity, "white")
            citation_marker = "[green]\u2713 verifiee[/]" if f.citation_verified else "[red]\u2717 NON verifiee[/]"
            score = f"{f.risk_score:.1f}" if f.risk_score is not None else "-"
            table.add_row(
                f"[{color}]{f.severity.upper()}[/]",
                f.title,
                score,
                citation_marker,
                f.target,
                key=str(f.id),
            )
        self._update_detail(None)
        if not self._findings:
            self.query_one("#detail-text", Static).update(
                f"Aucun finding en attente pour '{self._engagement}'."
            )

    def _selected_finding(self) -> PendingFinding | None:
        table = self.query_one(DataTable)
        if table.cursor_row is None or not self._findings:
            return None
        try:
            row_key = table.coordinate_to_cell_key(table.cursor_coordinate).row_key
            finding_id = int(row_key.value)
        except Exception:
            return None
        return next((f for f in self._findings if f.id == finding_id), None)

    def _update_detail(self, finding: PendingFinding | None) -> None:
        detail = self.query_one("#detail-text", Static)
        if finding is None:
            return
        verified = "[green]verifiee[/]" if finding.citation_verified else "[red]NON verifiee -- a confirmer manuellement[/]"
        detail.update(
            f"[bold]{finding.title}[/]\n\n"
            f"Cible : {finding.target}\n"
            f"Citation ({verified}) : {finding.source_citation[:300]}\n\n"
            f"{finding.description}\n\n"
            f"[dim]a=accepter  e=editer  r=rejeter  q=quitter[/]"
        )

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        self._update_detail(self._selected_finding())

    def action_accept(self) -> None:
        finding = self._selected_finding()
        if finding is None:
            return

        def _on_comment(comment: str | None) -> None:
            if comment is None:
                return
            accept_finding(self._conn, finding.id, self._analyst, comment)
            self.refresh_findings()

        self.push_screen(CommentModal(f"Accepter : {finding.title}"), _on_comment)

    def action_reject(self) -> None:
        finding = self._selected_finding()
        if finding is None:
            return

        def _on_comment(comment: str | None) -> None:
            if not comment:
                return  # annule OU commentaire vide -- un rejet exige une raison (voir review.reject_finding)
            reject_finding(self._conn, finding.id, self._analyst, comment)
            self.refresh_findings()

        self.push_screen(CommentModal(f"Rejeter : {finding.title}", required=True), _on_comment)

    def action_edit(self) -> None:
        finding = self._selected_finding()
        if finding is None:
            return

        def _on_result(result: tuple[str, str, str] | None) -> None:
            if result is None:
                return
            title, description, comment = result
            if not title and not description:
                return  # rien a editer -- pas d'appel inutile
            edit_finding(
                self._conn, finding.id, self._analyst,
                edited_title=title or None, edited_description=description or None, comment=comment,
            )
            self.refresh_findings()

        self.push_screen(EditModal(finding.title), _on_result)


def run_tui(conn: sqlite3.Connection, engagement: str, analyst: str) -> None:
    ReviewApp(conn, engagement, analyst).run()
