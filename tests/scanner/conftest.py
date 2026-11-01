"""Compat : FakeProcess et la fixture fake_subprocess_exec ont ete
remontees dans tests/conftest.py pour etre partagees avec tests/fuzzing
(les deux wrappers passent par la meme base ExternalToolWrapper).
"""

from tests.conftest import FakeProcess  # noqa: F401
