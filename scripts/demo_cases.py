"""
Prints the 5 safe demonstration cases. TEST 5 generates a fresh random synthetic
password at runtime (different every run). Do NOT reuse any of these passwords.

    python scripts/demo_cases.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.services.password_analyzer import analyze_password  # noqa: E402
from backend.services.password_generator import generate_password  # noqa: E402

CASES = [("TEST 1", "123456"), ("TEST 2", "Password123!"), ("TEST 3", "aaaaaaaaaaaaaaaa"),
         ("TEST 4", "qwerty2026!"), ("TEST 5 (random, generated now)", generate_password(20))]

for name, pw in CASES:
    r = analyze_password(pw)
    print(f"{name}: {pw}\n  score={r['score']} -> {r['classification']}")
    for f in r["findings"][:4]:
        print("  -", f["description"])
    print(f"  entropy: theoretical={r['metrics']['theoretical_entropy_bits']} bits, "
          f"adjusted={r['metrics']['adjusted_entropy_bits']} bits (educational estimate only)\n")
