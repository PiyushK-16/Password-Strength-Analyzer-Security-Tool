"""Loads the small local word lists (cached, read-only)."""
from functools import lru_cache
from pathlib import Path

from backend.config import DATA_DIR


@lru_cache(maxsize=8)
def _load(path_str: str) -> frozenset:
    path = Path(path_str)
    if not path.exists():
        return frozenset()
    items = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            items.add(line)
    return frozenset(items)


def load_common_passwords() -> frozenset:
    return _load(str(DATA_DIR / "common_passwords.txt"))


def load_common_words() -> frozenset:
    return _load(str(DATA_DIR / "common_words.txt"))
