from __future__ import annotations

import asyncio
import hashlib
import sqlite3

import pytest

from recon_copilot.audit import AuditTrail
from recon_copilot.db import get_connection
from recon_copilot.rag.embeddings import EmbeddingClient
from recon_copilot.scope import ScopeConfig, ScopeGuard


@pytest.fixture
def db_conn():
    conn = get_connection(":memory:")
    yield conn
    conn.close()


@pytest.fixture
def audit_trail(db_conn) -> AuditTrail:
    return AuditTrail(db_conn, chosen_by="test-analyst")


def make_scope_guard(
    allowed=("10.0.0.0/24", "target.example.local"),
    excluded=(),
    ports=(),
    on_violation=None,
) -> ScopeGuard:
    config = ScopeConfig(
        allowed_targets=tuple(allowed),
        excluded_targets=tuple(excluded),
        allowed_ports=tuple(ports),
    )
    return ScopeGuard(config, on_violation=on_violation)


@pytest.fixture
def scope_guard() -> ScopeGuard:
    return make_scope_guard()


class FakeProcess:
    """Remplace asyncio.subprocess.Process pour ne pas dependre d'un vrai nmap/nuclei/ffuf installe.

    Partage entre tests/scanner et tests/fuzzing : les deux wrappers passent
    par la meme base `ExternalToolWrapper` (recon_copilot.external_tool),
    donc le meme double de test convient aux deux.
    """

    def __init__(self, stdout: bytes = b"", stderr: bytes = b"", returncode: int = 0, hang: bool = False):
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode
        self._hang = hang
        self.killed = False

    async def communicate(self):
        if self._hang:
            await asyncio.sleep(9999)  # ne retourne jamais -> force le asyncio.wait_for a timeout
        return self._stdout, self._stderr

    def kill(self):
        self.killed = True
        self.returncode = -9

    async def wait(self):
        return self.returncode


@pytest.fixture
def fake_subprocess_exec(monkeypatch):
    """Retourne une fonction pour configurer ce que create_subprocess_exec doit renvoyer.

    Usage:
        set_result = fake_subprocess_exec
        set_result(FakeProcess(stdout=b"...", returncode=0))
    """
    holder: dict[str, FakeProcess] = {}
    captured_commands: list[list[str]] = []

    async def fake_create_subprocess_exec(*command, **kwargs):
        captured_commands.append(list(command))
        return holder["process"]

    def set_result(process: FakeProcess) -> None:
        holder["process"] = process

    monkeypatch.setattr(
        "recon_copilot.external_tool.asyncio.create_subprocess_exec",
        fake_create_subprocess_exec,
    )
    set_result.captured_commands = captured_commands
    return set_result


def _hash_embed(text: str, dim: int = 32) -> list[float]:
    """Embedding factice deterministe (sac-de-mots hache) -- pas d'IA, pas de
    reseau, mais des textes qui partagent des mots se retrouvent bien plus
    proches en cosinus que des textes sans rapport. Suffisant pour tester
    que la recherche par similarite retourne le bon ordre, sans dependre
    d'un vrai modele d'embedding. Partage entre tests/rag et
    tests/correlation (correlation consomme aussi le module RAG)."""
    vec = [0.0] * dim
    for word in text.lower().split():
        idx = int(hashlib.md5(word.encode()).hexdigest(), 16) % dim
        vec[idx] += 1.0
    norm = sum(v * v for v in vec) ** 0.5
    if norm > 0:
        vec = [v / norm for v in vec]
    return vec


class FakeEmbeddingClient(EmbeddingClient):
    def __init__(self, dim: int = 32):
        self.dim = dim
        self.calls: list[list[str]] = []

    async def embed(self, texts: list[str]) -> list[list[float]]:
        self.calls.append(list(texts))
        return [_hash_embed(t, self.dim) for t in texts]


@pytest.fixture
def fake_embedding_client() -> FakeEmbeddingClient:
    return FakeEmbeddingClient()

