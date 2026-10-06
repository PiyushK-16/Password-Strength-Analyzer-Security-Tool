"""
Runs the 30 scenarios and writes reports/test_matrix.md with REAL actual results.

    python scripts/run_test_matrix.py
"""
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tests.scenarios import SCENARIOS  # noqa: E402


def main() -> None:
    lines = ["# Test matrix (generated)", "",
             "All inputs are synthetic demo values. Regenerate with `python scripts/run_test_matrix.py`.", "",
             "| Test ID | Scenario | Input | Expected result | Actual result | Pass/Fail |",
             "|---|---|---|---|---|---|"]
    failures = 0
    for tid, scenario, inp, expected, check in SCENARIOS:
        with tempfile.TemporaryDirectory() as tmp:
            actual, ok = check(tmp)
        failures += not ok
        lines.append(f"| {tid} | {scenario} | `{inp}` | {expected} | {actual} | {'PASS' if ok else 'FAIL'} |".replace("|`|", "| |"))
    lines += ["", f"**{len(SCENARIOS) - failures}/{len(SCENARIOS)} passed.**"]
    out = ROOT / "reports" / "test_matrix.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[-3:]))
    print(f"Wrote {out}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
