# 5. Resume, LinkedIn and Interview Preparation

## A. Resume bullets
- Built a privacy-first password strength analyzer (Python/Flask) that scores passwords 0-100 using length, entropy, common-password checks and pattern detection (sequences, keyboard walks, repetition, word+number, personal-info overlap).
- Designed zero-retention handling of secrets: no password logging or storage, metadata-only SQLite analytics, strict CSP, rate limiting and a secure `secrets`-based generator, verified by 65 automated tests including privacy tests.
- Delivered a real-time dashboard, configurable policy checker and educational password-hashing demo, documented with architecture, API docs, test matrix and report.

## B. Two-line description
Defensive password-strength tool that scores passwords locally using length, predictability and pattern analysis, then gives specific advice without storing or transmitting them. Includes a secure generator, policy checker, privacy-safe analytics and 65 automated tests.

## C. LinkedIn project description
I built the Password Strength Analyzer & Security Suggestion Tool for my cybersecurity course. Instead of relying on "one capital, one number, one symbol", it combines length, unpredictability, common-password checks, pattern detection (sequences, keyboard walks, repetition, word+year) and optional personal-context checks. It explains its findings, separates password policy PASS/FAIL from strength, and includes a `secrets`-based generator and a metadata-only analytics dashboard. Privacy was a design goal: passwords are processed in memory, never stored or logged, and automated tests check this. Stack: Python, Flask, SQLite, JavaScript, Chart.js, pytest. Code and docs on GitHub: <link>.

## D. Skills demonstrated
Cybersecurity, password security, application security, IAM concepts, Python, secure coding, pattern detection, authentication security, password hashing concepts, security awareness, privacy engineering, REST API design, security testing, technical documentation.

## E. GitHub description
Privacy-focused cybersecurity tool for evaluating password strength using length, predictability, common-password checks, pattern analysis, entropy concepts, and personalized security recommendations.

## Interview preparation (10 questions)
Replace numbers with your own results if you change the scoring.

**1. Explain your project.**
I built a password strength analyzer that runs locally. You type a password and it returns a 0-100 score, a class from VERY WEAK to VERY STRONG, the reasons, and specific suggestions. I avoided judging by composition rules because `Password123!` passes them but is predictable. The engine combines length, character variety, common-password and pattern checks, an entropy-style estimate and optional personal-info checks. The password is processed in memory only, never stored or logged, and I wrote automated tests to prove that.

**2. How do you measure password strength, and why isn't one formula enough?**
I use a weighted model: length (35), diversity (15), unique ratio (10), pattern resistance (20), not-common (10) and unpredictability (10), minus penalties for patterns. No formula captures attacker knowledge: a password's real strength depends on how likely it is to be guessed, so the bands are project-defined teaching bands, not a standard.

**3. What is entropy and what are its limits?**
Entropy measures unpredictability in bits; for random characters it is L x log2(N). The catch is that humans don't choose randomly. `Password123!` gets about 79 theoretical bits but is guessable fast. So I also compute a pattern-adjusted estimate (about 18 bits for that password) and show both, labelled as educational estimates.

**4. How does your pattern detection work?**
Sequences scan for runs where adjacent characters differ by +1 or -1 (1234, dcba). Keyboard walks check substrings against forward and reversed keyboard rows. Repetition uses regular expressions for repeated characters and repeated blocks. Word+number logic strips leading/trailing digits and symbols, normalizes leetspeak, and checks the core against local word lists. Each detector returns the character positions it covered so I can compute how much of the password is predictable.

**5. Why is length not enough? Give an example.**
`aaaaaaaaaaaaaaaa` is 16 characters but has almost no unpredictability; my tool scores it WEAK because repetition collapses its adjusted entropy to a few bits. Length helps most when the characters are random or the words are chosen randomly.

**6. How should a real system store passwords? Explain hashing and salting.**
Never plaintext. Store a salted hash made with a slow password-hashing function such as Argon2id, bcrypt, scrypt or PBKDF2. A unique random salt per password means identical passwords produce different hashes and precomputed tables fail; the slow work factor makes each guess costly. I wrote a separate scrypt demo with `hash_password` and `verify_password` using constant-time comparison. My analyzer deliberately does not hash or store what users type.

**7. Hashing vs encryption, and why not plain SHA-256?**
Hashing is one-way verification; encryption is reversible with a key. Plain SHA-256 is designed to be fast, which helps an attacker who steals a hash database test guesses quickly, so it is not suitable alone for passwords.

**8. What is the difference between a password policy and password strength?**
Policy is a pass/fail check against organizational rules (minimum length, blocking common passwords). Strength is how hard the password is to guess. I show them separately because a password can pass policy and still be weak, such as `Welcome12345!`. My checker follows modern guidance: minimum length, allow long passwords and spaces, block common passwords, no forced periodic changes.

**9. How did you protect privacy in the application?**
The password goes only in a POST body over the same origin, never the URL. Logging never receives it and a log filter acts as a backstop; errors are generic; `debug=False`; responses use `no-store`; the browser code avoids localStorage, sessionStorage, cookies and `console.log`. The database has no password or hash column, and analytics save only on an explicit click. Tests search the DB file bytes, logs, stdout/stderr and responses for a synthetic secret.

**10. Why does MFA matter if the password is strong, and how would you improve the project?**
A strong password can still be phished, reused, or stolen by malware, so MFA (ideally passkeys or security keys) adds a second barrier. For improvements I would add zxcvbn-style estimation, a privacy-preserving breach check using k-anonymity, enterprise policy profiles, passkey education, and accessibility and localization work.
