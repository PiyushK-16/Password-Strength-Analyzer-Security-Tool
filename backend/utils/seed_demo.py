"""
Fills the analytics database with SYNTHETIC demo analyses so the dashboard has
something to show. Only demo passwords generated/typed here are analysed, and only
metadata is stored.

Run:  python -m backend.utils.seed_demo
"""
from backend.config import Config
from backend.models import database
from backend.services.password_analyzer import analyze_password
from backend.services.password_generator import generate_password

DEMO_PASSWORDS = [
    "123456", "password", "qwerty123", "Password123!", "aaaaaaaaaaaaaaaa", "qwerty2026!", "welcome123",
    "summer2026", "abcd1234", "letmein", "Admin@2024", "hello1234", "abcabcabc", "111111", "iloveyou",
    "Tx1aaaaZ9", "mq9876tw", "739402581637", "kqzvmxwpltrb", "violet-anchor-pepper-glacier-moss",
    "tiny orbit lantern 4 meadow", "k7#Qm2!vXr9$",
]


def main() -> None:
    database.init_db(Config.DATABASE_PATH)
    samples = DEMO_PASSWORDS + [generate_password(n) for n in (16, 20, 24, 16, 20)]
    for sample in samples:
        database.save_analysis(Config.DATABASE_PATH, analyze_password(sample))  # metadata only
    print(f"Seeded {len(samples)} synthetic analyses into {Config.DATABASE_PATH}")


if __name__ == "__main__":
    main()
