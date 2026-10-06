"""
The analysis engine.

analyze_password(password, context=None) runs every analyzer IN MEMORY and
returns:
    {"score", "classification", "findings", "suggestions", "strengths", "metrics"}

The password is never written anywhere by this module.
"""
from backend.config import LENGTH_BANDS
from backend.services import pattern_detector as pd
from backend.services.entropy_estimator import (
    EDUCATIONAL_NOTE, estimate_adjusted_entropy, estimate_theoretical_entropy, guess_resistance_label)
from backend.services.scoring_engine import classify_score, compute_score
from backend.services.suggestion_engine import generate_suggestions

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def analyze_length(password: str) -> dict:
    """Length band + educational note. Length helps but is never enough alone."""
    length = len(password)
    label = next(lbl for upper, lbl in LENGTH_BANDS if length < upper)
    return {"length": length, "band": label,
            "note": "Length helps, but a long password can still be predictable (e.g. one repeated letter)."}


def analyze_characters(password: str) -> dict:
    """Which character types are present and how varied the characters are."""
    unique = len(set(password))
    flags = {
        "has_lowercase": any(c.islower() for c in password),
        "has_uppercase": any(c.isupper() for c in password),
        "has_digit": any(c.isdigit() for c in password),
        "has_symbol": any(not c.isalnum() for c in password),
        "has_space": " " in password,
    }
    return {**flags,
            "character_type_count": sum(flags[k] for k in ("has_lowercase", "has_uppercase", "has_digit", "has_symbol")),
            "unique_character_count": unique,
            "unique_character_ratio": round(unique / len(password), 3) if password else 0.0}


def _public(finding: dict) -> dict:
    return {k: finding[k] for k in ("type", "severity", "description")}


def _empty_result() -> dict:
    return {"score": 0, "classification": "VERY WEAK",
            "findings": [{"type": "empty", "severity": "info", "description": "No password entered yet."}],
            "suggestions": ["Type a password to see its analysis."], "strengths": [],
            "metrics": {"length": 0}}


def analyze_password(password: str, context: dict | None = None) -> dict:
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    if password == "":
        return _empty_result()

    length_info = analyze_length(password)
    chars = analyze_characters(password)
    length, types = length_info["length"], chars["character_type_count"]
    common_kind = pd.common_match_kind(password)
    passphrase = pd.looks_like_passphrase(password)

    raw = []
    if common_kind:
        kind_type = "common_password" if common_kind == "exact" else "common_variant"
        raw.append(pd._finding(kind_type, "high",
                               "Your password matches a commonly used password pattern and should not be used."))
    if length < 12:
        raw.append(pd._finding("short_length", "high" if length < 8 else "medium",
                               f"Password is {length_info['band'].lower()} ({length} characters)."))
    if types == 1 and length < 16 and not passphrase:
        raw.append(pd._finding("low_variety", "low", "Uses only one type of character."))

    raw += pd.detect_sequences(password)
    raw += pd.detect_keyboard_patterns(password)
    raw += pd.detect_repetition(password)
    structure = pd.detect_predictable_structure(password)
    raw += structure
    raw += pd.detect_year_pattern(password)
    if not structure and not passphrase:
        raw += pd.detect_dictionary_words(password)
    raw += pd.detect_context_overlap(password, context or {})

    # --- coverage of the password by detected patterns ---
    covered = set()
    for f in raw:
        for s, e in f.get("spans", []):
            covered.update(range(s, e))
    coverage = 1.0 if common_kind else len(covered) / length
    pattern_spans = [(s, e, f["bits"]) for f in raw for (s, e) in f.get("spans", [])]
    pattern_count = sum(1 for f in raw if f.get("spans"))

    theoretical = estimate_theoretical_entropy(password)
    adjusted = estimate_adjusted_entropy(password, pattern_spans, is_common=bool(common_kind))

    score, breakdown = compute_score(length=length, char_info=chars, findings=raw, coverage=coverage,
                                     adjusted_bits=adjusted, common_kind=common_kind)

    strengths = []
    if length >= 12:
        strengths.append(f"Good length ({length} characters).")
    if types >= 3:
        strengths.append("Good character variety.")
    if chars["unique_character_ratio"] >= 0.7 and length >= 8:
        strengths.append("Characters are varied rather than repeated.")
    if passphrase:
        strengths.append("Looks like a multi-word passphrase, which is a good approach if the words are random.")
    if not common_kind and pattern_count == 0:
        strengths.append("No common-password match or predictable pattern detected.")

    raw.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))
    public_findings = [_public(f) for f in raw]
    metrics = {
        **length_info, **chars,
        "pattern_count": pattern_count,
        "weakness_count": len(public_findings),
        "pattern_coverage": round(coverage, 2),
        "theoretical_entropy_bits": round(theoretical, 1),
        "adjusted_entropy_bits": round(adjusted, 1),
        "guess_resistance": guess_resistance_label(adjusted),
        "entropy_note": EDUCATIONAL_NOTE,
        "score_breakdown": breakdown,
    }
    return {"score": score, "classification": classify_score(score), "findings": public_findings,
            "suggestions": generate_suggestions(public_findings, metrics, score),
            "strengths": strengths, "metrics": metrics}
