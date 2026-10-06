"""
EDUCATIONAL DEMO: how a login system should store passwords.

This file is SEPARATE from the analyzer on purpose. The analyzer never hashes or
stores what users type. Run this demo with a synthetic password only:

    python demos/hashing_demo.py

Flow:  password -> + random salt -> slow password-hashing function -> stored record

Uses scrypt from Python's standard library (a memory-hard password-hashing
function). In production prefer Argon2id (argon2-cffi) or bcrypt; the idea is the same.
Hashing is one-way verification. Encryption is reversible. They are not the same.
"""
import base64
import hashlib
import hmac
import secrets

# Work-factor parameters. Raising N makes every guess more expensive for an attacker.
N, R, P, SALT_BYTES, KEY_BYTES = 2**14, 8, 1, 16, 32


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(SALT_BYTES)              # unique per password
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=N, r=R, p=P, dklen=KEY_BYTES)
    b64 = lambda raw: base64.b64encode(raw).decode()
    return f"scrypt${N}${R}${P}${b64(salt)}${b64(digest)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_b64, digest_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt, expected = base64.b64decode(salt_b64), base64.b64decode(digest_b64)
        candidate = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=int(n), r=int(r), p=int(p), dklen=len(expected))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(candidate, expected)      # constant-time comparison


if __name__ == "__main__":
    demo = "Demo-Only-Not-A-Real-Password-42"
    first, second = hash_password(demo), hash_password(demo)
    print("Stored record 1:", first)
    print("Stored record 2:", second)
    print("Same password, different salts -> different records:", first != second)
    print("Correct password verifies:", verify_password(demo, first))
    print("Wrong password verifies:  ", verify_password("wrong-guess", first))
