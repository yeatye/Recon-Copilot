"""Compat : FakeEmbeddingClient et la fixture fake_embedding_client ont ete
remontees dans tests/conftest.py pour etre partagees avec tests/correlation
(correlation consomme aussi le module RAG desormais).
"""

from tests.conftest import FakeEmbeddingClient  # noqa: F401
