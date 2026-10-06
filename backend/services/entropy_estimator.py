"""
Entropy-style estimation.

Theoretical entropy:  H = L * log2(N)
  L = password length, N = size of the character pool that appears in it.

LIMITATION (important, say this in your viva): the formula assumes every
character was picked uniformly at random. Humans do not pick like that, so
"Password123!" gets an optimistic ~79 bits even though it is guessable almost
immediately. That is why this project also computes an *adjusted* estimate that
charges only a few bits for each detected predictable pattern.

All numbers are EDUCATIONAL ESTIMATES, not guarantees.
"""
import math
import string

SYMBOLS = set(string.punctuation)


def character_pool_size(password: str) -> int:
    """Estimate N from the kinds of characters present."""
    pool = 0
    if any(c.islower() and c.isascii() for c in password):
        pool += 26
    if any(c.isupper() and c.isascii() for c in password):
        pool += 26
    if any(c.isdigit() and c.isascii() for c in password):
        pool += 10
    if any(c in SYMBOLS for c in password):
        pool += len(SYMBOLS)  # 32
    if any(c == " " for c in password):
        pool += 1
    if any(not c.isascii() for c in password):
        pool += 100  # rough allowance for non-ASCII characters
    return max(pool, 1)


def estimate_theoretical_entropy(password: str) -> float:
    """H = L * log2(N). Optimistic: assumes random selection."""
    if not password:
        return 0.0
    return len(password) * math.log2(character_pool_size(password))


def estimate_adjusted_entropy(password: str, pattern_spans: list, is_common: bool = False) -> float:
    """
    Pattern-adjusted estimate.

    pattern_spans: list of (start, end, bits). Characters inside a detected
    pattern are charged the pattern's small `bits` cost instead of log2(N) each.
    A password that is an exact common password is charged a flat 8 bits.
    """
    if not password:
        return 0.0
    if is_common:
        return 8.0
    per_char = math.log2(character_pool_size(password))
    covered = [False] * len(password)
    total = 0.0
    for start, end, bits in sorted(pattern_spans, key=lambda s: s[0]):
        size = max(end - start, 1)
        fresh = sum(1 for i in range(start, min(end, len(password))) if not covered[i])
        if fresh:
            total += bits * (fresh / size)
            for i in range(start, min(end, len(password))):
                covered[i] = True
    total += per_char * sum(1 for flag in covered if not flag)
    return total


def guess_resistance_label(bits: float) -> str:
    """Qualitative tier. Deliberately NOT a 'time to crack' number."""
    if bits < 28:
        return "Very low"
    if bits < 36:
        return "Low"
    if bits < 60:
        return "Moderate"
    if bits < 80:
        return "High"
    return "Very high"


EDUCATIONAL_NOTE = (
    "Educational estimate only. Real guessing resistance depends on the attacker model, "
    "how predictable the password is, the hashing algorithm and work factor, rate limiting, "
    "and whether the attack is online or offline."
)
