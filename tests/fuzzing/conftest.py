from __future__ import annotations

import json

import pytest

from tests.conftest import FakeProcess


@pytest.fixture
def fake_ffuf_subprocess(monkeypatch):
    """Simule un `ffuf` reel : ecrit un contenu JSON donne dans le fichier
    passe apres `-o` dans la commande, plutot que de simplement renvoyer un
    FakeProcess (ffuf ecrit ses resultats dans un fichier, pas sur stdout).
    """
    captured_commands: list[list[str]] = []
    holder = {"json_content": '{"results": []}', "returncode": 0}

    async def fake_create_subprocess_exec(*command, **kwargs):
        captured_commands.append(list(command))
        command_list = list(command)
        if "-o" in command_list:
            output_path = command_list[command_list.index("-o") + 1]
            with open(output_path, "w") as fh:
                fh.write(holder["json_content"])
        return FakeProcess(returncode=holder["returncode"])

    def configure(json_content: str, returncode: int = 0) -> None:
        holder["json_content"] = json_content
        holder["returncode"] = returncode

    monkeypatch.setattr(
        "recon_copilot.external_tool.asyncio.create_subprocess_exec",
        fake_create_subprocess_exec,
    )
    configure.captured_commands = captured_commands
    return configure
