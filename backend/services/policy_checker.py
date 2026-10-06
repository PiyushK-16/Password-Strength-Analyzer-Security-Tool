"""
Password POLICY evaluation - deliberately separate from the strength SCORE.

Policy = "does it satisfy the organisation's rules?"  (PASS / FAIL)
Score  = "how hard is it to guess?"                    (0-100)

A password can pass policy and still be weak (e.g. 'Welcome12345!'), and a long
passphrase can be strong while failing an outdated composition rule.

Modern guidance (e.g. NIST SP 800-63B) favours: minimum length, allowing long
passwords and spaces, blocking common/compromised passwords, and NOT forcing
arbitrary composition rules or periodic changes.
"""
from backend.config import default_policy


def evaluate_policy(password: str, analysis: dict, policy: dict | None = None) -> dict:
    policy = {**default_policy(), **(policy or {})}
    finding_types = {f["type"] for f in analysis["findings"]}
    rules = []

    def add(name, passed, detail):
        rules.append({"rule": name, "passed": bool(passed), "detail": detail})

    add("minimum_length", len(password) >= policy["minimum_length"],
        f"At least {policy['minimum_length']} characters")
    add("maximum_length", len(password) <= policy["maximum_length"],
        f"No more than {policy['maximum_length']} characters supported")
    if policy["common_password_check"]:
        add("common_password_check", not ({"common_password", "common_variant"} & finding_types),
            "Must not be a commonly used password")
    if policy["personal_info_check"]:
        add("personal_info_check", "personal_info" not in finding_types,
            "Must not contain the personal details provided")
    if not policy["allow_spaces"]:
        add("no_spaces", " " not in password, "Spaces are not allowed by this policy")

    passed = all(r["passed"] for r in rules)
    return {"result": "POLICY PASS" if passed else "POLICY FAIL", "passed": passed, "rules": rules,
            "note": "Policy compliance and password strength are different concepts."}
