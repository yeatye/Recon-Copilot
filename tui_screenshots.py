"""Genere 2 captures nettes de la TUI (SVG -> PNG) a partir de ta vraie base."""
import asyncio
import sys
from recon_copilot.db import get_connection
from recon_copilot.pipeline import load_engagement_config
from recon_copilot.review.tui import ReviewApp

async def main(config_path):
    config = load_engagement_config(config_path)
    conn = get_connection(config.db_path)

    # --- Capture 1 : vue principale ---
    app = ReviewApp(conn, config.name, config.analyst)
    async with app.run_test(size=(110, 40)) as pilot:
        await pilot.pause()
        app.save_screenshot("tui_main_view.svg")
    print("tui_main_view.svg genere")

    # --- Capture 2 : modale de decision (accepter la 1ere ligne) ---
    app2 = ReviewApp(conn, config.name, config.analyst)
    async with app2.run_test(size=(110, 40)) as pilot:
        await pilot.pause()
        await pilot.press("a")   # ouvre la modale d'acceptation
        await pilot.pause()
        app2.save_screenshot("tui_modal.svg")
    print("tui_modal.svg genere")

asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else "config/engagement.yaml"))
