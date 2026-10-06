# 2. Architecture and Design

## Architecture
```
User -> Secure web interface (password field) -> POST /api/analyze
      -> In-memory analysis
         Length Analyzer | Character Analyzer | Common Password Checker | Sequence Detector
         Keyboard Pattern Detector | Repetition Detector | Context Checker | Entropy Estimator
      -> Strength Scoring Engine -> Classification -> Suggestion Engine -> User
Optional: safe aggregate metrics -> SQLite analytics -> Dashboard
```
The password never travels into analytics storage: `database.save_analysis` receives only the result (score, class, length, ratio, finding types), not the password.

## Technology choice
| | Option A (used) | Option B |
|---|---|---|
| Frontend | HTML/CSS/JS | React |
| Backend | Flask | FastAPI |
| Pros | Few moving parts, one command to run, easy to explain in a viva | Typed models, auto API docs, modern job-market stack |
| Cons | Manual DOM updates | Node toolchain, more setup for a beginner |

**Recommendation:** Option A for a first security project; focus effort on the security logic and tests. Move to Option B later as an upgrade story.

## Folder guide
| Path | Purpose |
|---|---|
| `backend/app.py` | App factory, security headers, generic error handlers |
| `backend/config.py` | Bands, policy defaults, environment settings |
| `backend/routes/api.py` | REST endpoints, validation, rate limiting |
| `backend/services/` | `password_analyzer`, `pattern_detector`, `entropy_estimator`, `scoring_engine`, `suggestion_engine`, `password_generator`, `policy_checker` |
| `backend/models/database.py` | SQLite schema and metadata-only queries |
| `backend/utils/` | Word-list loader, rate limiter, logging filter, demo seeding |
| `frontend/` | `index.html`, `css/style.css`, `js/app.js`, vendored Chart.js |
| `data/` | Educational word lists (`common_passwords.txt`, `common_words.txt`) |
| `demos/` | Separate password-hashing demonstration |
| `scripts/` | Test-matrix generator, demo cases |
| `tests/` | Automated unit, API and privacy tests |
| `docs/`, `reports/`, `screenshots/` | Documentation, generated test report, proof images |

## Scoring model (0-100)
| Component | Max |
|---|---|
| Length (<8: 1.5/char, 8-11: 12-21, 12-15: 24-31.5, 16+: 35) | 35 |
| Character diversity (3.75 per type present) | 15 |
| Unique-character ratio | 10 |
| Pattern resistance (1 - share of characters covered by patterns) | 20 |
| Not a common password | 10 |
| Extra unpredictability (adjusted entropy / 80 bits) | 10 |

Penalties: exact common password 50, common variant 35, common word + number 15, other word+number 10, dictionary words 8, keyboard 10, sequence 8, repetition 8, year 8, personal info 15 (group caps; findings inside a larger structure are not double-charged), plus 8 if patterns cover 80%+ of the password. Caps: adjusted entropy under 30 bits -> max 40; under 45 bits -> max 60; length under 8 -> max 20; exact common -> max 15.
Bands: 0-20 VERY WEAK, 21-40 WEAK, 41-60 MODERATE, 61-80 STRONG, 81-100 VERY STRONG. These are **project-defined teaching bands**, not a universal standard, and the weights are judgment calls you can tune in `scoring_engine.py`.

## Database design
`analyses(analysis_id, score, classification, password_length, unique_character_ratio, weakness_count, created_at)`
`findings(finding_id, analysis_id, finding_type, severity, description)`
There is **no password column and no hash column**. Even a hash of an arbitrary user-typed password is unnecessary risk: people paste real passwords into strength meters, and short or predictable passwords can be recovered from unsalted hashes. Aggregates are all the dashboard needs.

## API design notes
- **Validation:** JSON object required; `password` must be a string up to 128 chars; context fields capped at 64 chars; body capped at 16 KB.
- **Privacy:** body-only transport, no logging, generic errors, no echo, `Cache-Control: no-store`.
- **Status codes:** 200, 400, 404/405, 413, 429 (with `Retry-After`).
- **Rate limiting:** in-memory sliding window per client IP (600/min default; use a shared store or gateway in production).
- **HTTPS:** required in production so the body is encrypted in transit; the local demo binds to 127.0.0.1.
