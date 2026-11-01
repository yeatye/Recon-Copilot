"""Compat : la base commune des wrappers a ete deplacee dans
`recon_copilot.external_tool` pour que le module `fuzzing` (ffuf) puisse
la reutiliser sans dependre du package `scanner`.

Ce fichier ne fait plus que reexporter, pour ne pas casser un import
existant qui viserait encore `recon_copilot.scanner.base`.
"""

from __future__ import annotations

from recon_copilot.external_tool import ExternalToolWrapper, ToolExecutionError, logger

__all__ = ["ExternalToolWrapper", "ToolExecutionError", "logger"]
