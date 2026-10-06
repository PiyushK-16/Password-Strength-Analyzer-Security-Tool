"""Shared helpers for tests and the test-matrix report script."""
import contextlib
import io
import logging
import sqlite3
from pathlib import Path

from backend.app import create_app


def make_client(tmpdir):
    db_path = str(Path(tmpdir) / "test_analytics.db")
    app = create_app({"TESTING": True, "DATABASE_PATH": db_path, "RATE_LIMIT_PER_MINUTE": 100000})
    return app.test_client(), db_path


def db_columns(db_path):
    with sqlite3.connect(db_path) as conn:
        out = {}
        for (table,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"):
            out[table] = [row[1] for row in conn.execute(f"PRAGMA table_info({table})")]
    return out


class LogCapture(logging.Handler):
    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.messages = []

    def emit(self, record):
        self.messages.append(record.getMessage())


@contextlib.contextmanager
def capture_all_output():
    """Capture root-logger records plus stdout/stderr while a block runs."""
    handler, out, err = LogCapture(), io.StringIO(), io.StringIO()
    root = logging.getLogger()
    old_level = root.level
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            yield lambda: "\n".join(handler.messages) + out.getvalue() + err.getvalue()
    finally:
        root.removeHandler(handler)
        root.setLevel(old_level)
