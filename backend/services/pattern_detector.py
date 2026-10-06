"""
Pattern detectors.

Every detector returns a list of "finding" dicts:
    {"type", "severity", "description", "spans": [(start, end)], "bits": float}

`spans` and `bits` are INTERNAL (used for scoring/entropy) and are stripped
before anything is returned by the API. Descriptions never echo the password.
"""
import re

from backend.utils.data_loader import load_common_passwords, load_common_words

# Leetspeak normalisation (1-to-1 character mapping, so indexes stay aligned).
_LEET_BASE = {"@": "a", "4": "a", "3": "e", "!": "i", "0": "o", "$": "s", "5": "s", "7": "t", "+": "t"}
LEET_I = str.maketrans({**_LEET_BASE, "1": "i"})
LEET_L = str.maketrans({**_LEET_BASE, "1": "l"})

KEYBOARD_ROWS = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",           # letter rows
    "!@#$%^&*()",                                   # shifted number row
    "qazwsxedc", "1qaz2wsx", "zaq12wsx", "1q2w3e4r", "qweasdzxc",  # common "walks"
]
KEYBOARD_PATTERNS = KEYBOARD_ROWS + [row[::-1] for row in KEYBOARD_ROWS]

# Suffixes people add to a word to "make it strong" (123, @123, 2024!, ...)
_COMMON_SUFFIX = re.compile(
    r"^[@#!$_.\-]?(123456|12345|1234|123|321|007|000|111|12|01|1|99|69|(19|20)\d\d)[!@#$%^&*._\-]?$"
)
_YEAR = re.compile(r"(?<!\d)((?:19|20)\d{2})(?!\d)")


def _finding(ftype, severity, description, spans=None, bits=0.0):
    return {"type": ftype, "severity": severity, "description": description,
            "spans": list(spans or []), "bits": bits}


# ------------------------------------------------------------------ common --
def common_match_kind(password: str):
    """Return 'exact', 'variant' (leetspeak) or None."""
    commons = load_common_passwords()
    lowered = password.lower()
    if lowered in commons:
        return "exact"
    if lowered.translate(LEET_I) in commons or lowered.translate(LEET_L) in commons:
        return "variant"
    return None


def is_common_password(password: str) -> bool:
    """True if the password (or a simple leetspeak variant) is in the local list."""
    return common_match_kind(password) is not None


# --------------------------------------------------------------- sequences --
def _same_class(a: str, b: str) -> bool:
    return (a.isdigit() and b.isdigit()) or (a.isascii() and a.isalpha() and b.isascii() and b.isalpha())


def detect_sequences(password: str, min_length: int = 4) -> list:
    """Ascending/descending runs such as 1234, abcd, 9876, dcba."""
    s, n, i = password.lower(), len(password), 0
    findings = []
    while i < n - 1:
        step = ord(s[i + 1]) - ord(s[i])
        if step in (1, -1) and _same_class(s[i], s[i + 1]):
            j = i + 1
            while j + 1 < n and ord(s[j + 1]) - ord(s[j]) == step and _same_class(s[j], s[j + 1]):
                j += 1
            run = j - i + 1
            if run >= min_length:
                direction = "ascending" if step == 1 else "descending"
                findings.append(_finding(
                    "sequence", "medium",
                    f"Contains a predictable {direction} sequence of {run} characters.",
                    [(i, j + 1)], bits=6.0))
            i = j
        else:
            i += 1
    return findings


# ---------------------------------------------------------------- keyboard --
def _merge(spans):
    merged = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def detect_keyboard_patterns(password: str, min_length: int = 4) -> list:
    """Keyboard walks such as qwerty, asdf, zxcv (forward or backward)."""
    s, spans = password.lower(), []
    for i in range(len(s)):
        best = 0
        for pattern in KEYBOARD_PATTERNS:
            k = min_length
            while i + k <= len(s) and s[i:i + k] in pattern:
                best = max(best, k)
                k += 1
        if best >= min_length:
            spans.append((i, i + best))
    return [
        _finding("keyboard_pattern", "medium",
                 f"Contains a keyboard pattern ({end - start} characters that follow adjacent keys).",
                 [(start, end)], bits=6.0)
        for start, end in _merge(spans)
    ]


# -------------------------------------------------------------- repetition --
def detect_repetition(password: str) -> list:
    """Repeated characters (aaaa) and repeated blocks (ababab, abcabcabc)."""
    findings = []
    for m in re.finditer(r"(.)\1{2,}", password):
        findings.append(_finding(
            "repeated_character", "medium",
            f"Repeats the same character {len(m.group(0))} times in a row.",
            [(m.start(), m.end())], bits=4.0))
    for m in re.finditer(r"(.{2,8}?)\1+", password):
        block = m.group(1)
        if len(set(block)) == 1 or len(m.group(0)) < 6:
            continue  # single-char runs are handled above; ignore tiny repeats
        findings.append(_finding(
            "repeated_substring", "medium",
            f"A {len(block)}-character block repeats {len(m.group(0)) // len(block)} times.",
            [(m.start(), m.end())], bits=8.0))
    return findings


# -------------------------------------------------------------------- years --
def detect_year_pattern(password: str) -> list:
    return [
        _finding("year_pattern", "low", "Contains a year-like number (19xx or 20xx), which is easy to guess.",
                 [(m.start(1), m.end(1))], bits=7.0)
        for m in _YEAR.finditer(password)
    ]


# ------------------------------------------------------------- dictionary --
def _dictionary() -> frozenset:
    pool = load_common_words() | load_common_passwords()
    return frozenset(w for w in pool if w.isalpha() and len(w) >= 4)


def detect_dictionary_words(password: str, min_word_length: int = 4) -> list:
    """Finds common words (also with simple leetspeak) and reports coverage."""
    words, text = _dictionary(), password.lower().translate(LEET_I)
    spans, i = [], 0
    while i < len(text):
        hit = 0
        for size in range(min(14, len(text) - i), min_word_length - 1, -1):
            if text[i:i + size] in words:
                hit = size
                break
        if hit:
            spans.append((i, i + hit))
            i += hit
        else:
            i += 1
    covered = sum(e - s for s, e in spans)
    if spans and covered / max(len(password), 1) >= 0.5:
        pct = round(100 * covered / len(password))
        return [_finding("dictionary_word", "medium",
                         f"Built mostly from common dictionary words (about {pct}% of the password).",
                         spans, bits=14.0 * len(spans))]
    return []


# ------------------------------------------------- predictable structure --
def detect_predictable_structure(password: str) -> list:
    """
    word + number/symbol patterns such as welcome123, admin2026, Rahul@123.

    Adding a predictable number to a common word does not make a strong password.
    """
    match = re.match(r"^([\d!@#$%^&*._\-]*)(.*?)([\d\W_]*)$", password, re.DOTALL)
    prefix, core, suffix = match.group(1), match.group(2), match.group(3)
    if not core or not (prefix or suffix):
        return []
    commons, words = load_common_passwords(), _dictionary() | load_common_words()
    variants = {core.lower(), core.lower().translate(LEET_I), core.lower().translate(LEET_L)}
    n = len(password)
    if variants & commons:
        return [_finding("common_word_pattern", "high",
                         "A very common password word with a number/symbol added; this is one of the "
                         "first patterns attackers try.",
                         [(0, n)], bits=10.0 + 8.0 * bool(suffix) + 6.0 * bool(prefix))]
    if variants & words:
        return [_finding("predictable_structure", "medium",
                         "A common word with a predictable number/symbol added at the start or end.",
                         [(0, n)], bits=14.0 + 8.0 * bool(suffix) + 6.0 * bool(prefix))]
    if core.isalpha() and len(core) >= 3 and suffix and not prefix and _COMMON_SUFFIX.match(suffix):
        start = n - len(suffix)
        return [_finding("predictable_structure", "medium",
                         "A word followed by a very common number/symbol ending (such as 123 or a year).",
                         [(start, n)], bits=8.0)]
    return []


# ----------------------------------------------------------------- context --
def detect_context_overlap(password: str, context: dict) -> list:
    """
    Optional check against details the user typed in (first name, birth year,
    organisation). Compared in memory only - never stored or logged.
    """
    if not context:
        return []
    lowered = password.lower()
    candidates = []
    name = (context.get("first_name") or "").strip().lower()
    if len(name) >= 3:
        candidates.append(name)
    org = (context.get("organization") or "").strip().lower()
    if org:
        candidates.extend(t for t in re.split(r"\W+", org) if len(t) >= 3)
        joined = re.sub(r"\W+", "", org)
        if len(joined) >= 3:
            candidates.append(joined)
    year = re.sub(r"\D", "", str(context.get("birth_year") or ""))
    if len(year) == 4:
        candidates.append(year)

    spans = []
    for candidate in set(candidates):
        for text in (lowered, lowered.translate(LEET_I), lowered.translate(LEET_L)):
            idx = text.find(candidate)
            if idx != -1:
                spans.append((idx, idx + len(candidate)))
                break
    if spans:
        return [_finding("personal_info", "high",
                         "Password appears to contain personal information you provided "
                         "(attackers often try names, birth years and organisations).",
                         _merge(spans), bits=8.0)]
    return []


def looks_like_passphrase(password: str) -> bool:
    """Four or more separate words and 20+ characters: treat as a passphrase."""
    return len(re.findall(r"[^\W\d_]{3,}", password)) >= 4 and len(password) >= 20
