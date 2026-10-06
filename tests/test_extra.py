"""Extra tests: detectors, policy, hashing demo, API behaviour, frontend privacy checks."""
import re
import sys
from pathlib import Path

import pytest

from backend.services import pattern_detector as pd
from backend.services.entropy_estimator import estimate_theoretical_entropy, estimate_adjusted_entropy
from backend.services.password_analyzer import analyze_characters, analyze_length, analyze_password
from backend.services.password_generator import generate_password
from backend.services.policy_checker import evaluate_policy
from tests.helpers import make_client

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "demos"))
import hashing_demo  # noqa: E402


# ---- analyzers ----
def test_length_bands():
    assert analyze_length("a" * 5)["band"] == "Very short"
    assert analyze_length("a" * 9)["band"] == "Short"
    assert analyze_length("a" * 13)["band"] == "Better length"
    assert analyze_length("a" * 20)["band"].startswith("Strong")


def test_character_analysis():
    info = analyze_characters("Ab1!Ab1!")
    assert info["character_type_count"] == 4 and info["unique_character_count"] == 4
    assert info["unique_character_ratio"] == 0.5


@pytest.mark.parametrize("pw,kind", [("1234", "ascending"), ("9876", "descending"), ("abcd", "ascending"), ("dcba", "descending")])
def test_sequence_directions(pw, kind):
    assert kind in pd.detect_sequences(pw)[0]["description"]


def test_three_chars_is_not_a_sequence():
    assert pd.detect_sequences("abc") == []


@pytest.mark.parametrize("pw", ["qwerty", "asdf", "zxcv", "ytrewq"])
def test_keyboard_patterns(pw):
    assert pd.detect_keyboard_patterns(pw)


def test_repetition_variants():
    assert pd.detect_repetition("aaaa")
    assert pd.detect_repetition("ababab")
    assert pd.detect_repetition("abcabcabc")
    assert not pd.detect_repetition("abab")  # too short to flag


def test_common_password_variants():
    assert pd.is_common_password("PASSWORD")
    assert pd.is_common_password("p@ssw0rd")
    assert not pd.is_common_password("k7#Qm2!vXr9$")


def test_composition_rules_are_not_enough():
    r = analyze_password("Password123!")
    assert r["metrics"]["character_type_count"] == 4 and r["classification"] in ("VERY WEAK", "WEAK")


def test_entropy_is_optimistic_for_predictable_passwords():
    pw = "Password123!"
    theoretical = estimate_theoretical_entropy(pw)
    adjusted = analyze_password(pw)["metrics"]["adjusted_entropy_bits"]
    assert theoretical > 70 and adjusted < 30 < theoretical
    assert estimate_adjusted_entropy("x", [], is_common=True) == 8.0


def test_context_ignored_when_absent_and_short_names_skipped():
    assert pd.detect_context_overlap("anything", {}) == []
    assert pd.detect_context_overlap("xyabx", {"first_name": "ab"}) == []  # <3 chars ignored


def test_suggestions_never_contain_the_password():
    secret = "Zebra-Moon-Qx7"
    r = analyze_password(secret, {"first_name": "Zebra"})
    assert secret not in " ".join(r["suggestions"]) + " ".join(f["description"] for f in r["findings"])
    assert "spans" not in r["findings"][0] if r["findings"] else True


def test_non_string_rejected():
    with pytest.raises(TypeError):
        analyze_password(12345)


# ---- generator ----
@pytest.mark.parametrize("length", [16, 20, 24])
def test_generator_lengths(length):
    assert len(generate_password(length)) == length


def test_generator_validation():
    for bad in (5, 500, True, "20"):
        with pytest.raises(ValueError):
            generate_password(bad)
    with pytest.raises(ValueError):
        generate_password(20, False, False, False, False)


# ---- policy ----
def test_policy_pass_and_fail_are_separate_from_score(tmp_path):
    weak_but_compliant = "Welcome12345!"
    r = analyze_password(weak_but_compliant)
    assert evaluate_policy(weak_but_compliant, r)["passed"] is True or r["score"] < 61
    short = "Ab1!"
    assert evaluate_policy(short, analyze_password(short))["result"] == "POLICY FAIL"


def test_policy_configurable():
    r = analyze_password("Zq7-long-enough-pw")
    assert evaluate_policy("Zq7-long-enough-pw", r, {"minimum_length": 40})["passed"] is False
    assert evaluate_policy("a b", analyze_password("a b"), {"minimum_length": 1, "allow_spaces": False})["passed"] is False


def test_policy_personal_info_toggle():
    r = analyze_password("Rahul-xk29-demo-pw", {"first_name": "Rahul"})
    assert evaluate_policy("Rahul-xk29-demo-pw", r, {"minimum_length": 8})["passed"] is False
    assert evaluate_policy("Rahul-xk29-demo-pw", r, {"minimum_length": 8, "personal_info_check": False})["passed"] is True


# ---- hashing demo ----
def test_hashing_demo():
    demo = "Demo-Only-Synthetic-Pw-1"
    a, b = hashing_demo.hash_password(demo), hashing_demo.hash_password(demo)
    assert a != b and demo not in a
    assert hashing_demo.verify_password(demo, a) and not hashing_demo.verify_password("wrong", a)
    assert hashing_demo.verify_password(demo, "garbage") is False


# ---- API ----
def test_api_validation_and_status_codes(tmp_path):
    client, _ = make_client(tmp_path)
    assert client.post("/api/analyze", data="nope").status_code == 400
    assert client.post("/api/analyze", json={"password": 123}).status_code == 400
    assert client.post("/api/analyze", json={}).status_code == 400
    assert client.get("/api/analyze").status_code in (404, 405)
    assert client.get("/api/missing").status_code == 404
    assert client.post("/api/analyze", data="x" * 20000, content_type="application/json").status_code == 413


def test_api_never_returns_password_or_internal_spans(tmp_path):
    client, _ = make_client(tmp_path)
    secret = "Qx-Unique-Demo-Marker-55"
    body = client.post("/api/analyze", json={"password": secret}).get_data(as_text=True)
    assert secret not in body and '"spans"' not in body


def test_security_headers_and_no_store(tmp_path):
    client, _ = make_client(tmp_path)
    resp = client.post("/api/analyze", json={"password": "abc"})
    assert "script-src 'self'" in resp.headers["Content-Security-Policy"]
    assert resp.headers["Cache-Control"] == "no-store" and resp.headers["Referrer-Policy"] == "no-referrer"


def test_rate_limiting(tmp_path):
    from backend.app import create_app
    app = create_app({"TESTING": True, "DATABASE_PATH": str(tmp_path / "r.db"), "RATE_LIMIT_PER_MINUTE": 3})
    client = app.test_client()
    codes = [client.post("/api/analyze", json={"password": "abc"}).status_code for _ in range(5)]
    assert codes[:3] == [200, 200, 200] and codes[3] == 429


def test_record_flag_off_by_default(tmp_path):
    client, _ = make_client(tmp_path)
    client.post("/api/analyze", json={"password": "abc"})
    assert client.get("/api/dashboard/stats").get_json()["total_analyses"] == 0


def test_generate_endpoint(tmp_path):
    client, _ = make_client(tmp_path)
    ok = client.post("/api/generate-password", json={"length": 24}).get_json()
    assert len(ok["password"]) == 24
    assert client.post("/api/generate-password", json={"length": 3}).status_code == 400


# ---- frontend privacy checks (static) ----
JS = (ROOT / "frontend/js/app.js").read_text(encoding="utf-8")
HTML = (ROOT / "frontend/index.html").read_text(encoding="utf-8")


def test_frontend_uses_password_field_and_hides_by_default():
    assert re.search(r'<input id="password" type="password"', HTML)
    assert 'autocomplete="off"' in HTML


def test_frontend_does_not_persist_or_log():
    code = re.sub(r"/\*.*?\*/", "", JS, flags=re.S)  # ignore comments
    for forbidden in ("localStorage", "sessionStorage", "document.cookie", "console.log", "indexedDB", "innerHTML"):
        assert forbidden not in code, forbidden
    assert "?password" not in code and "password=" not in code


def test_frontend_has_no_external_requests():
    assert not re.search(r'(src|href)="https?://', HTML)
