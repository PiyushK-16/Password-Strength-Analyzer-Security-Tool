# Password Strength Analyzer & Security Suggestion Tool

A privacy-focused, **defensive** cybersecurity tool that evaluates password strength from length, predictability, common-password checks, pattern analysis and entropy concepts, then gives specific advice. Everything runs locally; passwords are processed in memory and are never stored, logged or sent to another service.

## Overview
Type a password and get, without a page refresh: a 0-100 score, a classification (VERY WEAK to VERY STRONG), the reasons behind it, and concrete suggestions. A separate policy checker shows POLICY PASS/FAIL, a secure generator creates random passwords, and a dashboard shows aggregate, password-free statistics.

## Problem Statement
Composition rules ("1 capital, 1 number, 1 symbol") reward passwords like `Password123!` that attackers guess immediately. Users need feedback based on **length + unpredictability + pattern resistance + common-password checks + context**.

## Objectives
- Build a modular analysis engine with explainable scoring.
- Detect sequences, keyboard walks, repetition, common words, word+number patterns and personal-info overlap.
- Demonstrate privacy-by-design: no password storage, logging or transmission.
- Teach password hygiene, hashing concepts and the limits of entropy estimates.

## Cybersecurity Relevance
Applies to authentication systems, registration forms, IAM, banking and e-commerce portals, password managers and employee security-awareness. Skills shown: secure coding, privacy engineering, pattern detection, authentication security and security testing.

## Features
Real-time meter, show/hide password, 15 analysis outputs (length, diversity, common, repetition, sequences, keyboard walks, dictionary words, personal info, entropy, suggestions...), passphrase and hygiene education, secure generator (`secrets`), configurable policy checker, metadata-only analytics dashboard (5 charts), 65 automated tests.

## Architecture
```
User -> Web UI (type=password) -> POST /api/analyze (JSON body, HTTPS in production)
     -> In-memory analysis: Length | Characters | Common | Sequence | Keyboard | Repetition | Structure | Context | Entropy
     -> Scoring engine -> Classification -> Suggestion engine -> Response
Optional (explicit "Add to dashboard" click): score, class, length, finding types -> SQLite -> Dashboard
(The password itself never reaches storage.)
```
See `docs/02_ARCHITECTURE_AND_DESIGN.md`.

## Technology Stack
HTML/CSS/vanilla JS, Python 3.10+ / Flask, SQLite, Chart.js (vendored locally, no CDN), pytest. Chosen for beginner-friendliness and zero external services.

## Password Analysis
`analyze_password(password, context=None)` returns `score`, `classification`, `findings`, `suggestions`, `strengths`, `metrics`.

## Length Analysis
Bands: <8 very short, 8-11 short, 12-15 better, 16+ strong contribution. Length alone is never enough: `aaaaaaaaaaaaaaaa` is long but predictable.

## Pattern Detection
Ascending/descending sequences (1234, dcba), keyboard walks (qwerty, asdf, zxcv), repeated characters and blocks (aaaa, abcabcabc), year patterns, word + number structures (welcome123, Rahul@123), dictionary words, optional personal-context overlap.

## Common Password Detection
Local educational list `data/common_passwords.txt` (about 110 public, non-personal entries), case-insensitive, with simple leetspeak variants (`p@ssw0rd`).

## Entropy Estimation
`H = L x log2(N)` is shown as an *optimistic theoretical* figure (it assumes random characters) next to a *pattern-adjusted* estimate. `Password123!` shows about 79 theoretical bits but about 18 adjusted bits. Labelled "Educational estimate only." No "time to crack" claims.

## Strength Scoring
Length (35) + diversity (15) + unique ratio (10) + pattern resistance (20) + not common (10) + unpredictability (10), minus penalties, with caps for tiny search spaces. Bands 0-20, 21-40, 41-60, 61-80, 81-100 are **project-defined teaching bands, not a universal standard**.

## Security Suggestions
Specific advice per finding (e.g. "Your password contains a predictable numeric or alphabetic sequence"), plus unique passwords, a password manager and MFA. Suggestions never repeat the password.

## Password Generator
`secrets` (OS cryptographic randomness), lengths 16/20/24, selectable character types, at least one of each selected type, unbiased shuffle. Never stored.

## Password Policy Checker
Configurable `minimum_length`, `common_password_check`, `personal_info_check`, `allow_spaces`. Shown as POLICY PASS/FAIL **separately** from the score.

## Privacy Design
Password in JSON body only (never URL); never logged (log filter + generic errors + `debug=False`); never stored (no password or hash column); not returned in responses; no localStorage/sessionStorage/cookies; `Cache-Control: no-store`, strict CSP, `Referrer-Policy: no-referrer`; analytics only on explicit click.

## Installation
```bash
git clone <repository-url> && cd Password-Strength-Analyzer-Security-Tool
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env             # optional (Windows: copy .env.example .env)
```

## Usage
```bash
python -m backend.utils.seed_demo   # optional: load synthetic demo data
python -m backend.app               # then open http://127.0.0.1:5000
python scripts/demo_cases.py        # the 5 safe demonstration cases
python demos/hashing_demo.py        # separate password-hashing demo
```
The Flask server also serves the frontend, so there is only one process to start.

## API Documentation
| Method & path | Purpose |
|---|---|
| `POST /api/analyze` | Body `{"password": "...", "context": {"first_name","birth_year","organization"}, "record": false}` returns score, classification, findings, suggestions, strengths, metrics, policy |
| `GET /api/dashboard/stats` | Aggregate counts, averages, score and length distributions |
| `GET /api/analytics/weaknesses` | Weakness/pattern frequencies |
| `POST /api/generate-password` | `{"length":20,"upper":true,"lower":true,"digits":true,"symbols":true}` |
| `GET /api/policy`, `GET /api/health` | Active policy; health check |

Status codes: 200 OK, 400 invalid input (generic message, never echoes input), 404/405, 413 body over 16 KB, 429 rate limited. Use HTTPS in production.

## Testing
```bash
python -m pytest -q                      # 65 tests
python scripts/run_test_matrix.py        # regenerates reports/test_matrix.md (T01-T30 with actual results)
```

## Security Testing
Automated checks that the password is not in the DB file, API response, logs/stdout/stderr (including error paths), URL or browser storage, that the input is a password field, and that analytics hold only metadata. Details in `docs/03_TESTING_AND_SECURITY.md`.

## Results
30/30 scenario tests pass (`reports/test_matrix.md`). Demo results: `123456` 0 (VERY WEAK), `Password123!` 28 (WEAK), `aaaaaaaaaaaaaaaa` 34 (WEAK), `qwerty2026!` 21 (WEAK), random 20-char about 100 (VERY STRONG).

## Limitations
No single formula measures strength. The word lists are small, so uncommon-but-guessable passwords can score well. Entropy is an estimate. The tool does not check real breach corpora (see future work). A strong password does not stop phishing or reuse.

## Future Improvements
zxcvbn-style estimation, privacy-preserving breach checks (k-anonymity), enterprise policies and IAM integration, passkey/WebAuthn education, localisation, accessibility audit, organisation-level aggregate reporting without collecting passwords.

## Screenshots
Add files to `screenshots/` using the names in `docs/04_GITHUB_AND_SCREENSHOTS.md`.

## Learning Outcomes
Password security concepts, entropy and its limits, pattern detection, secure randomness, privacy by design, REST API design, automated security testing, GitHub documentation.

## Security Disclaimer
Educational project. Do not type real passwords into any tool you did not audit. Scores are estimates, not guarantees.

## Author
Your Name - Cybersecurity student. LinkedIn: <link>
