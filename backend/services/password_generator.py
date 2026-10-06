"""
Secure password generator.

Uses Python's `secrets` module (backed by the operating system's cryptographically
secure random source). The `random` module is a predictable pseudo-random generator
meant for simulations and games, so it must NOT be used for passwords or tokens.

Generated passwords are returned to the caller and never stored or logged.
"""
import secrets
import string

UPPER, LOWER, DIGITS = string.ascii_uppercase, string.ascii_lowercase, string.digits
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"
MIN_LENGTH, MAX_LENGTH = 12, 128


def generate_password(length: int = 20, upper: bool = True, lower: bool = True,
                      digits: bool = True, symbols: bool = True) -> str:
    if not isinstance(length, int) or isinstance(length, bool):
        raise ValueError("length must be an integer")
    if not (MIN_LENGTH <= length <= MAX_LENGTH):
        raise ValueError(f"length must be between {MIN_LENGTH} and {MAX_LENGTH}")
    pools = [p for enabled, p in ((upper, UPPER), (lower, LOWER), (digits, DIGITS), (symbols, SYMBOLS)) if enabled]
    if not pools:
        raise ValueError("select at least one character type")

    # Guarantee one character from every selected pool, fill the rest from the union.
    chars = [secrets.choice(pool) for pool in pools]
    union = "".join(pools)
    chars += [secrets.choice(union) for _ in range(length - len(chars))]

    # Fisher-Yates shuffle driven by secrets.randbelow (unbiased and secure).
    for i in range(len(chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]
    return "".join(chars)
