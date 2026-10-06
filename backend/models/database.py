"""
Analytics storage (SQLite) - SAFE AGGREGATE METADATA ONLY.

There is deliberately NO password column, NO password hash and NO reversible
form of the password anywhere in this schema. Even a hash of an arbitrary
user-typed password is unnecessary risk for this tool: people type their real
passwords into strength meters, and short or predictable passwords are easy to
recover from unsalted hashes.
"""
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from backend.config import CLASSIFICATIONS

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    analysis_id            INTEGER PRIMARY KEY AUTOINCREMENT,
    score                  INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
    classification         TEXT    NOT NULL,
    password_length        INTEGER NOT NULL,
    unique_character_ratio REAL    NOT NULL,
    weakness_count         INTEGER NOT NULL,
    created_at             TEXT    NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    finding_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id  INTEGER NOT NULL REFERENCES analyses(analysis_id) ON DELETE CASCADE,
    finding_type TEXT NOT NULL,
    severity     TEXT NOT NULL,
    description  TEXT NOT NULL
);
"""

PATTERN_TYPES = {"sequence", "keyboard_pattern", "repeated_character", "repeated_substring",
                 "common_word_pattern", "predictable_structure", "dictionary_word", "year_pattern"}
LENGTH_BINS = [("<8", 0, 7), ("8-11", 8, 11), ("12-15", 12, 15), ("16-19", 16, 19), ("20+", 20, 10**6)]
SCORE_BINS = [(f"{lo}-{lo + 9}" if lo else "0-10", lo, lo + 10 if lo == 0 else lo + 9) for lo in range(0, 100, 10)]


def _connect(path: str):
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with closing(_connect(path)) as conn, conn:
        conn.executescript(SCHEMA)


def save_analysis(path: str, result: dict) -> int:
    """Store ONLY metadata from an analysis result. The password is not an input here."""
    metrics = result["metrics"]
    with closing(_connect(path)) as conn, conn:
        cur = conn.execute(
            "INSERT INTO analyses (score, classification, password_length, unique_character_ratio, "
            "weakness_count, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (result["score"], result["classification"], metrics.get("length", 0),
             metrics.get("unique_character_ratio", 0.0), len(result["findings"]),
             datetime.now(timezone.utc).isoformat(timespec="seconds")))
        analysis_id = cur.lastrowid
        conn.executemany(
            "INSERT INTO findings (analysis_id, finding_type, severity, description) VALUES (?, ?, ?, ?)",
            [(analysis_id, f["type"], f["severity"], f["description"]) for f in result["findings"]])
    return analysis_id


def get_stats(path: str) -> dict:
    with closing(_connect(path)) as conn:
        rows = conn.execute("SELECT score, classification, password_length FROM analyses").fetchall()
    total = len(rows)
    by_class = {c: 0 for c in CLASSIFICATIONS}
    for _, cls, _ in rows:
        by_class[cls] = by_class.get(cls, 0) + 1
    return {
        "total_analyses": total,
        "by_classification": by_class,
        "average_score": round(sum(r[0] for r in rows) / total, 1) if total else 0,
        "score_distribution": {label: sum(1 for r in rows if lo <= r[0] <= hi) for label, lo, hi in SCORE_BINS},
        "length_distribution": {label: sum(1 for r in rows if lo <= r[2] <= hi) for label, lo, hi in LENGTH_BINS},
    }


def get_weakness_stats(path: str) -> list:
    with closing(_connect(path)) as conn:
        rows = conn.execute(
            "SELECT finding_type, COUNT(*) FROM findings WHERE finding_type NOT IN ('empty') "
            "GROUP BY finding_type ORDER BY COUNT(*) DESC").fetchall()
    return [{"type": t, "count": c, "category": "pattern" if t in PATTERN_TYPES else "content"} for t, c in rows]
