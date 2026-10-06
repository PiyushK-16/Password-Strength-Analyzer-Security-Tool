# 1. Concepts and Fundamentals

## A. Simple explanation
A password is a secret that proves you are you. A strong one is **long**, **hard to predict**, and **used on only one account**. Attackers do not try every combination first; they try the likely ones: common passwords, names, years, keyboard patterns and "word + number" habits. So `Password123!` (capital, number, symbol) is weak, while a long random passphrase is strong.

## B. Technical explanation
Strength is the difficulty of guessing a password under a given attacker model. This tool approximates it with `length + unpredictability + pattern resistance + common-password checks + context = better assessment`, combining a pool-based entropy formula with pattern detection because the formula alone assumes randomness humans do not have.

## Workflow
```
User enters password -> local input validation -> analyzer
  [length | characters | common | patterns | sequences | repetition | context | entropy]
-> risk/strength engine -> score -> classification -> suggestions -> awareness dashboard
```

## Key terms
- **Password strength** - resistance to guessing. Cannot be perfectly determined by one formula.
- **Why length matters** - each extra random character multiplies the search space.
- **Why predictability matters** - guesses are ordered by likelihood; predictable passwords fall early.
- **Entropy** - a measure of unpredictability in bits; `H = L x log2(N)` only for truly random choices.
- **Dictionary weakness** - passwords built from words or common substitutions (`p@ssw0rd`).
- **Password reuse** - using one password on several sites, so one breach exposes all.
- **Credential stuffing** (high level) - automated replay of leaked username/password pairs against other sites; unique passwords defeat it.
- **Composition rules are insufficient** - they force character types, not unpredictability.
- **Passphrases** - several random words; long, memorable, and strong when the words are truly random.
- **MFA** - a second factor means a stolen password alone is not enough (it does not stop real-time phishing for weaker factors, so prefer passkeys/security keys).

## Authentication fundamentals
- **Authentication** - proving identity. **Authorization** - deciding what that identity may do.
- **Plaintext password vs password hash** - plaintext is readable by anyone who reads the database; a hash is a one-way fingerprint used to verify. Systems must not store plaintext: a database leak would expose every account (and reused passwords elsewhere).
- **Salt** - random per-password value mixed in before hashing, so identical passwords produce different hashes and precomputed tables fail.
- **Key stretching / password hashing functions** - deliberately slow (and for some, memory-hard) functions that raise the cost of each guess.
  - **Argon2id** - modern first choice, memory-hard.
  - **bcrypt** - long-established, widely supported.
  - **scrypt** - memory-hard.
  - **PBKDF2** - standards-friendly, needs high iteration counts.
- Fast general-purpose hashes (MD5, SHA-1, plain SHA-256) are designed to be quick, which helps attackers who obtain a hash database. They are not suitable alone for password storage.
- **Hashing vs encryption** - hashing is one-way verification; encryption is reversible with a key.
- **Password managers** - generate and store unique passwords so users remember only one strong secret.
- Demo: `demos/hashing_demo.py` (synthetic password only, separate from the analyzer).

## Entropy and its limits
`Password123!` has 12 characters from a 94-symbol pool: about 79 bits "theoretically". But it is a common word + a predictable suffix, so an attacker's real effort is tiny. This project therefore shows theoretical entropy next to a pattern-adjusted estimate (about 18 bits). Both are **educational estimates**.

## Guess-resistance concept (no cracking)
Longer, less predictable passwords generally increase guessing difficulty. Real resistance depends on the attacker model, password predictability, hashing algorithm, work factor, rate limiting and online vs offline scenario. The tool shows only a qualitative tier ("Educational estimate only") and never a guaranteed "time to crack". It contains no cracking or guessing functionality.

## Modern password policy principles
Minimum length (e.g. 12+), allow long passwords (128+) and spaces, block common/compromised passwords, avoid arbitrary composition rules, do not force periodic changes without evidence of compromise, support password managers (allow paste), and add MFA. Policy PASS/FAIL is separate from strength score: a password can comply and still be weak.

## 10 password security rules
1. Use a unique password for every account.
2. Prefer long passwords or passphrases.
3. Avoid predictable personal information.
4. Avoid common passwords.
5. Never reuse passwords.
6. Use a password manager.
7. Enable MFA.
8. Never share passwords.
9. Be cautious of phishing; check the address first.
10. Change a password when compromise is suspected or confirmed.

## Real-world login security
`Password + MFA + rate limiting + secure password hashing + lockout/abuse protection + session security + phishing protection + monitoring`. A very strong password alone cannot stop phishing, malware on the device, session theft, server-side breaches that expose weak hashing, or reuse elsewhere.

## Industry relevance
Authentication systems, banking apps, e-commerce, enterprise portals, cloud apps, IAM systems, employee security, customer accounts, password managers and registration forms all apply the same controls (length minimums, common-password blocking, strength feedback, MFA).

| Role | Skills this project shows |
|---|---|
| Cybersecurity Analyst | Risk scoring, explaining findings, awareness content |
| Application Security Analyst | Secure input handling, no-secret logging, security headers, security tests |
| IAM Analyst | Password policy design, policy vs strength, MFA/passkey awareness |
| Security Engineer | Secure randomness, hashing concepts, rate limiting, privacy-by-design |
| SOC Analyst | Understanding credential attacks (stuffing, guessing) and monitoring needs |
| Secure Software Developer | Modular Python, REST design, automated tests, defensive coding |
