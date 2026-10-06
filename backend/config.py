"""
Central configuration.

Everything that a teacher / administrator might want to tune lives here:
length bands, classification bands and the password policy. Values can be
overridden with environment variables (see .env.example).
"""
import os
from pathlib import Path

try:  # python-dotenv is optional; the app works without it.
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover
    pass

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
FRONTEND_DIR = BASE_DIR / "frontend"


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


# --- Educational length bands: (exclusive upper bound, label) -----------------
LENGTH_BANDS = [
    (8, "Very short"),
    (12, "Short"),
    (16, "Better length"),
    (10**9, "Strong length contribution"),
]

# --- Project-defined classification bands: (inclusive upper bound, label) -----
# These are NOT universal security standards. They are teaching bands.
CLASSIFICATION_BANDS = [
    (20, "VERY WEAK"),
    (40, "WEAK"),
    (60, "MODERATE"),
    (80, "STRONG"),
    (100, "VERY STRONG"),
]

CLASSIFICATIONS = [label for _, label in CLASSIFICATION_BANDS]


def default_policy() -> dict:
    """Administrator-configurable password policy (separate from the score)."""
    return {
        "minimum_length": _int("POLICY_MIN_LENGTH", 12),
        "maximum_length": _int("MAX_PASSWORD_LENGTH", 128),
        "common_password_check": _bool("POLICY_COMMON_CHECK", True),
        "personal_info_check": _bool("POLICY_PERSONAL_INFO_CHECK", True),
        "allow_spaces": _bool("POLICY_ALLOW_SPACES", True),
    }


class Config:
    """Flask configuration object."""

    MAX_PASSWORD_LENGTH = _int("MAX_PASSWORD_LENGTH", 128)
    MAX_CONTENT_LENGTH = 16 * 1024  # reject request bodies larger than 16 KB
    DATABASE_PATH = os.environ.get("DATABASE_PATH", str(DATA_DIR / "analytics.db"))
    ANALYTICS_ENABLED = _bool("ANALYTICS_ENABLED", True)
    RATE_LIMIT_PER_MINUTE = _int("RATE_LIMIT_PER_MINUTE", 600)
    HOST = os.environ.get("HOST", "127.0.0.1")
    PORT = _int("PORT", 5000)
