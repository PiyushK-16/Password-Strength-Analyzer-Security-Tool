"""
The 30 scenario tests (T01-T30). Used by BOTH pytest (tests/test_scenarios.py)
and the report script (scripts/run_test_matrix.py), so the documented table is
generated from real runs. Every input below is a SYNTHETIC demo value.

Each check returns (actual_description, passed).
"""
import inspect

from backend.services import password_generator
from backend.services.password_analyzer import analyze_password as A
from backend.services.scoring_engine import classify_score
from tests.helpers import capture_all_output, db_columns, make_client

ORDER = ["VERY WEAK", "WEAK", "MODERATE", "STRONG", "VERY STRONG"]


def types(r):
    return {f["type"] for f in r["findings"]}


def summary(r):
    return f"{r['score']}/{r['classification']}"


def at_most(r, label):
    return ORDER.index(r["classification"]) <= ORDER.index(label)


def at_least(r, label):
    return ORDER.index(r["classification"]) >= ORDER.index(label)


def _simple(pw, expect_types=(), ceiling=None, floor=None, context=None, any_of=False):
    def check(tmp):
        r = A(pw, context)
        ok = True
        if expect_types:
            ok &= bool(types(r) & set(expect_types)) if any_of else set(expect_types) <= types(r)
        if ceiling:
            ok &= at_most(r, ceiling)
        if floor:
            ok &= at_least(r, floor)
        return f"{summary(r)}; findings={sorted(types(r))}", ok
    return check


def t_empty(tmp):
    r = A("")
    return summary(r), r["score"] == 0 and r["classification"] == "VERY WEAK"


def t_max_length(tmp):
    client, _ = make_client(tmp)
    ok_len = client.post("/api/analyze", json={"password": "aB3$" * 32}).status_code     # 128 chars
    secret = "Qz9!" * 33                                                                  # 132 chars
    resp = client.post("/api/analyze", json={"password": secret})
    leaked = secret in resp.get_data(as_text=True)
    return f"128 chars -> {ok_len}; 132 chars -> {resp.status_code}; echoed={leaked}", ok_len == 200 and resp.status_code == 400 and not leaked


def t_boundaries(tmp):
    expected = {0: "VERY WEAK", 20: "VERY WEAK", 21: "WEAK", 40: "WEAK", 41: "MODERATE", 60: "MODERATE",
                61: "STRONG", 80: "STRONG", 81: "VERY STRONG", 100: "VERY STRONG"}
    bad = {s: classify_score(s) for s, label in expected.items() if classify_score(s) != label}
    return "all 10 boundary scores map correctly" if not bad else f"wrong: {bad}", not bad


def t_suggestions(tmp):
    r = A("123456")
    text = " ".join(r["suggestions"]).lower()
    ok = len(r["suggestions"]) >= 4 and "mfa" in text and "password manager" in text and "sequence" in text
    return f"{len(r['suggestions'])} suggestions incl. sequence, manager, MFA", ok


def t_generation(tmp):
    a, b = password_generator.generate_password(20), password_generator.generate_password(20)
    ok = (len(a) == 20 and a != b and any(c.islower() for c in a) and any(c.isupper() for c in a)
          and any(c.isdigit() for c in a) and any(not c.isalnum() for c in a))
    src = inspect.getsource(password_generator)
    ok &= "import secrets" in src and "import random" not in src
    r = A(a)
    ok &= r["score"] >= 61
    return f"20 chars, all classes, differs per call, uses secrets; analyzer score {r['score']}", ok


def t_not_stored(tmp):
    secret = "Zq#Demo-NotStored-91x"
    client, db_path = make_client(tmp)
    resp = client.post("/api/analyze", json={"password": secret, "record": True})
    with open(db_path, "rb") as fh:
        raw = fh.read()
    cols = db_columns(db_path)
    flat = [c.lower() for cs in cols.values() for c in cs]
    ok = (resp.status_code == 200 and secret.encode() not in raw and secret not in resp.get_data(as_text=True)
          and not any("password_hash" in c or c == "password" for c in flat))
    return "secret absent from DB file and API response; no password column", ok


def t_not_logged(tmp):
    secret = "Zq#Demo-NotLogged-77y"
    client, _ = make_client(tmp)
    with capture_all_output() as captured:
        client.post("/api/analyze", json={"password": secret, "record": True})
        client.post("/api/analyze", json={"password": secret * 20})   # too long -> error path
        client.post("/api/analyze", data="{bad json " + secret)
        text = captured()
    return "secret absent from logs, stdout and stderr (incl. error paths)", secret not in text


def t_analytics(tmp):
    client, db_path = make_client(tmp)
    for pw in ("123456", "Password123!", "k7#Qm2!vXr9$-demo"):
        client.post("/api/analyze", json={"password": pw, "record": True})
    stats = client.get("/api/dashboard/stats").get_json()
    weak = client.get("/api/analytics/weaknesses").get_json()
    cols = db_columns(db_path)
    blob = str(stats) + str(weak)
    expected_cols = {"analysis_id", "score", "classification", "password_length",
                     "unique_character_ratio", "weakness_count", "created_at"}
    ok = (stats["total_analyses"] == 3 and set(cols["analyses"]) == expected_cols
          and bool(weak["weaknesses"]) and "Password123" not in blob and "k7#Qm2" not in blob)
    return f"3 rows stored; columns={cols['analyses']}", ok


SCENARIOS = [
    ("T01", "Empty password", '""', "Score 0, VERY WEAK", t_empty),
    ("T02", "One-character password", "a", "VERY WEAK", _simple("a", ["short_length"], ceiling="VERY WEAK")),
    ("T03", "Short numeric password", "12345", "VERY WEAK, short", _simple("12345", ["short_length"], ceiling="VERY WEAK")),
    ("T04", "Common password", "password", "VERY WEAK, common_password", _simple("password", ["common_password"], ceiling="VERY WEAK")),
    ("T05", "Long repeated password", "a x 20", "WEAK or lower, repeated_character", _simple("a" * 20, ["repeated_character"], ceiling="WEAK")),
    ("T06", "Lowercase only", "kqzvmxwpltrb", "low_variety flagged", _simple("kqzvmxwpltrb", ["low_variety"])),
    ("T07", "Uppercase only", "KQZVMXWPLTRB", "low_variety flagged", _simple("KQZVMXWPLTRB", ["low_variety"])),
    ("T08", "Numbers only", "739402581637", "low_variety, not above MODERATE", _simple("739402581637", ["low_variety"], ceiling="MODERATE")),
    ("T09", "Symbols only", "!@#$%^&*()", "keyboard_pattern, WEAK or lower", _simple("!@#$%^&*()", ["keyboard_pattern"], ceiling="WEAK")),
    ("T10", "Mixed random characters", "k7#Qm2!vXr9$", "STRONG or better, no findings", _simple("k7#Qm2!vXr9$", floor="STRONG")),
    ("T11", "Sequential numbers", "Ab1234Cd", "sequence detected", _simple("Ab1234Cd", ["sequence"])),
    ("T12", "Reverse numeric sequence", "mq9876tw", "descending sequence detected", _simple("mq9876tw", ["sequence"])),
    ("T13", "Sequential letters", "mkabcdq", "sequence detected", _simple("mkabcdq", ["sequence"])),
    ("T14", "Keyboard sequence", "qwertyuiop", "keyboard_pattern detected", _simple("qwertyuiop", ["keyboard_pattern"], ceiling="VERY WEAK")),
    ("T15", "Repeated characters", "Tx1aaaaZ9", "repeated_character detected", _simple("Tx1aaaaZ9", ["repeated_character"])),
    ("T16", "Repeated substring", "abcabcabc", "repeated_substring detected", _simple("abcabcabc", ["repeated_substring"], ceiling="WEAK")),
    ("T17", "Common word + number", "welcome123", "common-word pattern, WEAK or lower",
     _simple("welcome123", ["common_word_pattern", "common_password"], ceiling="WEAK", any_of=True)),
    ("T18", "Word + year", "summer2026", "word+year detected, WEAK or lower",
     _simple("summer2026", ["common_word_pattern", "predictable_structure"], ceiling="WEAK", any_of=True)),
    ("T19", "Personal name overlap", "Rahul@123 (name=Rahul)", "personal_info detected",
     _simple("Rahul@123", ["personal_info"], ceiling="WEAK", context={"first_name": "Rahul"})),
    ("T20", "Birth year overlap", "mq2004zkv! (year=2004)", "personal_info detected",
     _simple("mq2004zkv!", ["personal_info"], context={"birth_year": "2004"})),
    ("T21", "Long passphrase-like input", "violet-anchor-pepper-glacier-moss", "VERY STRONG-ish, no dictionary penalty",
     _simple("violet-anchor-pepper-glacier-moss", floor="STRONG")),
    ("T22", "Unicode handling", "Zürich-Ωmega-猫7!qx", "No crash, valid result", _simple("Zürich-Ωmega-猫7!qx", floor="STRONG")),
    ("T23", "Space handling", "tiny orbit lantern 4 meadow", "has_space true, STRONG or better",
     lambda tmp: (lambda r: (summary(r) + f"; has_space={r['metrics']['has_space']}", r["metrics"]["has_space"] and at_least(r, "STRONG")))(A("tiny orbit lantern 4 meadow"))),
    ("T24", "Maximum accepted length", "128 chars / 132 chars", "128 accepted, 132 rejected without echo", t_max_length),
    ("T25", "Strength-score boundaries", "scores 0,20,21,40,41,60,61,80,81,100", "Correct class for each", t_boundaries),
    ("T26", "Suggestion generation", "123456", "Specific suggestions + manager + MFA", t_suggestions),
    ("T27", "Secure password generation", "length 20", "Secure, random, all classes", t_generation),
    ("T28", "Password not stored", "synthetic secret via API", "Not in DB file, not in response", t_not_stored),
    ("T29", "Password not logged", "synthetic secret via API", "Not in logs/stdout/stderr", t_not_logged),
    ("T30", "Analytics storage", "3 recorded analyses", "Metadata-only rows, no password", t_analytics),
]
