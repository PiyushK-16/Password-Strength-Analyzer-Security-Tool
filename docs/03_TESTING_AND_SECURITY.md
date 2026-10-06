# 3. Testing Strategy and Security Testing

## Run
```bash
python -m pytest -q                  # 65 tests
python scripts/run_test_matrix.py    # writes reports/test_matrix.md (Test ID, scenario, input, expected, ACTUAL, pass/fail)
```
`tests/scenarios.py` defines T01-T30 once; pytest and the report script both run it, so the table in `reports/test_matrix.md` always reflects real results. `tests/test_extra.py` adds detector, generator, policy, hashing, API and frontend checks.

## The 30 scenarios
T01 empty - T02 one character - T03 short numeric - T04 common - T05 long repeated - T06 lowercase only - T07 uppercase only - T08 numbers only - T09 symbols only - T10 mixed - T11 sequential numbers - T12 reverse numeric - T13 sequential letters - T14 keyboard - T15 repeated characters - T16 repeated substring - T17 common word + number - T18 word + year - T19 name overlap - T20 birth-year overlap - T21 passphrase - T22 Unicode - T23 spaces - T24 maximum length - T25 score boundaries - T26 suggestions - T27 secure generation - T28 not stored - T29 not logged - T30 analytics storage.

## Security tests and why each matters
| Check | How it is verified | Why it matters |
|---|---|---|
| Password not stored | T28 searches the raw SQLite file bytes and schema | A DB leak must not expose what users typed |
| Not in logs | T29 captures root logs, stdout, stderr, including error paths | Logs are widely readable and long-lived |
| Not in database | T28/T30 column check: no password/hash column | Even hashes of arbitrary input are risky |
| Not returned by API | `test_api_never_returns_password_or_internal_spans`, T24 (error body) | Responses can be cached, proxied or logged |
| Not in URL | Static test: no `?password`/`password=` in JS; API is POST body only | URLs end up in history, proxies and referrers |
| Password field used | `test_frontend_uses_password_field_and_hides_by_default` | Masks input, helps managers and browsers treat it as a secret |
| No unnecessary persistence | Static test forbids `localStorage`, `sessionStorage`, cookies, IndexedDB, `console.log`, `innerHTML` | Browser storage is readable by scripts and other users of the machine |
| Analytics metadata only | T30 compares the exact column set | Dashboard stats should be useless to an attacker |
| Headers and caching | `test_security_headers_and_no_store` | CSP limits script injection; no-store limits caching |
| Rate limiting | `test_rate_limiting` | Limits abuse of a CPU-bound endpoint |

## Manual checks (take screenshots)
1. Open browser DevTools -> Application -> Local/Session Storage: empty after typing.
2. Network tab: `POST /api/analyze`, no password in the URL, response has no password.
3. Terminal running the server: only lines like `POST /api/analyze ... 200`.
4. `sqlite3 data/analytics.db ".schema"`: no password column.
