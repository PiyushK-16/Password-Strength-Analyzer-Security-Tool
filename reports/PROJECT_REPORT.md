# Project Report: Password Strength Analyzer & Security Suggestion Tool

## Abstract
This project is a defensive, privacy-focused web tool that assesses password strength locally. It combines length, character variety, common-password detection, pattern analysis (sequences, keyboard walks, repetition, word+number structures), optional personal-context checks and an entropy-style estimate into a 0-100 score with five classes, specific suggestions, a secure generator, a policy checker and a metadata-only analytics dashboard. Passwords are never stored, logged or transmitted to external services. Sixty-five automated tests, including privacy tests, pass.

## Introduction
Passwords remain a primary authentication method. Users are often guided by composition rules that reward predictable choices. This project demonstrates a more realistic approach and the engineering discipline needed to handle secrets safely.

## Problem Statement
Existing "must contain a capital, number and symbol" meters misjudge strength (for example `Password123!`), and many online meters ask users to trust a remote service with real passwords. A transparent, local, explainable analyzer is needed for learning and awareness.

## Objectives
Build a modular analysis engine; explain every score; detect common human patterns; preserve privacy; teach hashing, MFA and hygiene; and prove behaviour with automated tests.

## Password Security Background
Strength is resistance to guessing. Guessing attacks prioritize likely candidates (common passwords, names, dates, keyboard patterns, word+number habits), so predictability matters as much as length. Reuse enables credential stuffing, where leaked credentials are replayed on other sites.

## Authentication Security
Passwords are one control among several: MFA, rate limiting, secure hashing, abuse protection, session security, phishing resistance and monitoring. A very strong password does not stop phishing, malware, session theft or server-side breaches.

## Existing Approaches
Composition-rule meters (simple, misleading); entropy-only meters (assume randomness); pattern-aware estimators such as zxcvbn (better, more complex); breach-corpus checks (powerful, need privacy-preserving design).

## Proposed System
A Flask backend exposes `/api/analyze`; a vanilla JavaScript frontend calls it as the user types (debounced). Services are separated by responsibility so each can be tested and explained alone.

## Architecture
Web UI -> API -> in-memory analyzers -> scoring -> classification -> suggestions -> response. Optional, user-triggered storage of safe aggregate metadata in SQLite feeds a dashboard. See `docs/02_ARCHITECTURE_AND_DESIGN.md`.

## Password Analysis
`analyze_password` orchestrates `analyze_length`, `analyze_characters`, `is_common_password`, `detect_sequences`, `detect_keyboard_patterns`, `detect_repetition`, `detect_predictable_structure`, `detect_year_pattern`, `detect_dictionary_words`, `detect_context_overlap` and `estimate_theoretical_entropy`.

## Feature Extraction
Length, character-type flags, unique character count and ratio, pattern spans and coverage, adjusted entropy bits. Detector spans are internal and removed from API output.

## Pattern Detection
Sequences: runs with step +1/-1 over digits or letters (min 4). Keyboard: substrings of forward/reversed rows and common walks. Repetition: repeated characters (3+) and repeated blocks (6+ characters total). Structure: word core with leetspeak normalisation plus predictable prefix/suffix. Dictionary: greedy longest word match with coverage threshold; passphrase-like inputs are exempt.

## Common Password Detection
Case-insensitive lookup in a small public educational list, plus two leetspeak normalisations. Exact matches are capped at a score of 15.

## Entropy Concepts
`H = L x log2(N)` is reported as an optimistic theoretical value. The adjusted estimate charges a small fixed number of bits per detected pattern. Example: `Password123!` is about 79 theoretical vs about 18 adjusted bits. Both are educational.

## Strength Scoring
Weighted components (35/15/10/20/10/10), penalties with group caps and overlap de-duplication, a dominance penalty when patterns cover most of the password, and caps for small search spaces. Bands are project-defined, not a standard.

## Recommendation Engine
Maps finding types to specific, actionable messages; always adds unique-password, password-manager and MFA advice; never repeats the password.

## Password Generator
Uses `secrets` for cryptographically secure randomness, guarantees one character per selected class, and shuffles with `secrets.randbelow`. Generated values are shown once and never stored.

## Policy Checker
Configurable minimum/maximum length, common-password check, personal-info check and space handling; reports POLICY PASS/FAIL separately from the score, following modern guidance (no forced composition rules or periodic changes).

## Secure Password Storage Concepts
Separate demo (`demos/hashing_demo.py`): random salt + scrypt + constant-time verification. The analyzer deliberately never hashes or stores user input. Production systems should prefer Argon2id or bcrypt and tune work factors.

## Privacy Design
Body-only transport; no logging (log filter, generic errors, no debug); no storage (no password or hash columns); no response echo; no browser persistence; `no-store`, CSP and `no-referrer` headers; analytics only on explicit action.

## Dashboard
Totals, class counts, average score and five charts: strength distribution, score distribution, common weaknesses, length distribution and pattern frequency. Demo data is loaded with `python -m backend.utils.seed_demo` using synthetic passwords.

## Testing
65 tests: 30 scenario tests (T01-T30) plus detector, generator, policy, hashing, API and frontend checks. The matrix with actual results is generated to `reports/test_matrix.md`.

## Security Testing
Verified that a synthetic secret is absent from the database file, API responses (including errors), logs, stdout/stderr and browser-side code; that the input is a password field; that analytics hold only metadata; and that rate limiting and security headers work.

## Results
All scenarios pass. Demonstration results: `123456` 0 VERY WEAK; `Password123!` 28 WEAK; `aaaaaaaaaaaaaaaa` 34 WEAK; `qwerty2026!` 21 WEAK; runtime-generated 20-character password about 100 VERY STRONG.

## Limitations
Small word lists; no breach-corpus check; heuristic weights chosen by judgment; entropy is approximate; names and cultural words outside the lists are not detected; an in-memory rate limiter does not scale across servers; the tool cannot assess phishing, reuse or device compromise.

## Future Scope
zxcvbn-style estimation, privacy-preserving breach checks (k-anonymity), configurable enterprise policy profiles, password-manager and IAM integration, MFA/SSO/passkey education, localisation, accessibility audit, organisation-level aggregate reporting without collecting passwords.

## Conclusion
The project shows that useful strength feedback can be given locally, explained clearly and built with privacy as a requirement, not an afterthought. It highlights that strength comes from length and unpredictability, that composition rules are insufficient, and that passwords work best alongside MFA and sound storage practices.
