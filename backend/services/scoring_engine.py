"""
Strength scoring (0-100) - a PROJECT-DEFINED teaching model, not a standard.

  Length                      up to 35
  Character diversity         up to 15
  Unique-character ratio      up to 10
  Pattern resistance          up to 20
  Not a common password       up to 10
  Extra unpredictability      up to 10   (from the pattern-adjusted entropy)
  ------------------------------------
  Penalties subtract points; small-search-space and very-short-length caps limit the final score.
"""
from backend.config import CLASSIFICATION_BANDS

LENGTH_MAX, DIVERSITY_MAX, UNIQUE_MAX, PATTERN_MAX, COMMON_MAX, UNPRED_MAX = 35, 15, 10, 20, 10, 10

# finding type -> (penalty per finding, penalty group, cap for the group)
PENALTIES = {
    "common_password": (50, "common", 50),
    "common_variant": (35, "common", 50),
    "common_word_pattern": (15, "structure", 25),
    "predictable_structure": (10, "structure", 25),
    "dictionary_word": (8, "structure", 25),
    "keyboard_pattern": (10, "keyboard", 20),
    "sequence": (8, "sequence", 16),
    "repeated_character": (8, "repetition", 16),
    "repeated_substring": (8, "repetition", 16),
    "year_pattern": (8, "year", 8),
    "personal_info": (15, "personal", 15),
}
# These finding types describe *the same characters* as a bigger structure finding,
# so we do not charge for them twice.
DEDUP_TYPES = {"sequence", "keyboard_pattern", "repeated_character", "repeated_substring", "year_pattern"}
STRUCTURE_TYPES = {"common_word_pattern", "predictable_structure", "dictionary_word"}
TOTAL_PENALTY_CAP = 60
DOMINANCE_PENALTY = 8  # when patterns cover >= 80% of the password


def length_points(length: int) -> float:
    if length < 8:
        return length * 1.5
    if length < 12:
        return 12 + (length - 8) * 3
    if length < 16:
        return 24 + (length - 12) * 2.5
    return float(LENGTH_MAX)


def classify_score(score: int) -> str:
    for upper, label in CLASSIFICATION_BANDS:
        if score <= upper:
            return label
    return CLASSIFICATION_BANDS[-1][1]


def _range(finding):
    spans = finding.get("spans") or []
    return (min(s for s, _ in spans), max(e for _, e in spans)) if spans else None


def compute_penalties(findings: list) -> float:
    groups = {}
    structure_ranges = [_range(f) for f in findings if f["type"] in STRUCTURE_TYPES and _range(f)]
    for f in findings:
        if f["type"] not in PENALTIES:
            continue
        rng = _range(f)
        if f["type"] in DEDUP_TYPES and rng and any(s <= rng[0] and rng[1] <= e for s, e in structure_ranges):
            continue
        per, group, cap = PENALTIES[f["type"]]
        groups[group] = min(groups.get(group, 0) + per, cap)
    return min(sum(groups.values()), TOTAL_PENALTY_CAP)


def compute_score(*, length, char_info, findings, coverage, adjusted_bits, common_kind):
    """Returns (score:int, breakdown:dict)."""
    types = char_info["character_type_count"]
    ratio = char_info["unique_character_ratio"]
    has_common_word = any(f["type"] == "common_word_pattern" for f in findings)

    points = {
        "length": length_points(length),
        "diversity": types * DIVERSITY_MAX / 4,
        "unique_ratio": min(UNIQUE_MAX, ratio / 0.8 * UNIQUE_MAX),
        "pattern_resistance": PATTERN_MAX * (1 - coverage),
        "non_common": 0 if common_kind else (0 if has_common_word else COMMON_MAX),
        "unpredictability": min(UNPRED_MAX, adjusted_bits / 80 * UNPRED_MAX),
    }
    penalties = compute_penalties(findings)
    pattern_found = any(f.get("spans") for f in findings)
    dominance = DOMINANCE_PENALTY if (coverage >= 0.8 and pattern_found) else 0

    score = sum(points.values()) - penalties - dominance

    # Small-search-space caps: few effective bits means guessable, whatever the composition.
    if adjusted_bits < 30:
        score = min(score, 40)
    elif adjusted_bits < 45:
        score = min(score, 60)
    if length < 8:
        score = min(score, 20)  # "very short" band: too small a search space to rate higher
    if common_kind == "exact":
        score = min(score, 15)
    elif common_kind == "variant":
        score = min(score, 25)

    final = int(round(max(0, min(100, score))))
    breakdown = {k: round(v, 1) for k, v in points.items()}
    breakdown["penalties"] = round(-(penalties + dominance), 1)
    return final, breakdown
