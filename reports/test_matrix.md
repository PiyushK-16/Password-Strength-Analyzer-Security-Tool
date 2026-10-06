# Test matrix (generated)

All inputs are synthetic demo values. Regenerate with `python scripts/run_test_matrix.py`.

| Test ID | Scenario | Input | Expected result | Actual result | Pass/Fail |
|---|---|---|---|---|---|
| T01 | Empty password | `""` | Score 0, VERY WEAK | 0/VERY WEAK | PASS |
| T02 | One-character password | `a` | VERY WEAK | 20/VERY WEAK; findings=['low_variety', 'short_length'] | PASS |
| T03 | Short numeric password | `12345` | VERY WEAK, short | 0/VERY WEAK; findings=['common_password', 'low_variety', 'sequence', 'short_length'] | PASS |
| T04 | Common password | `password` | VERY WEAK, common_password | 0/VERY WEAK; findings=['common_password', 'dictionary_word', 'low_variety', 'short_length'] | PASS |
| T05 | Long repeated password | `a x 20` | WEAK or lower, repeated_character | 34/WEAK; findings=['repeated_character'] | PASS |
| T06 | Lowercase only | `kqzvmxwpltrb` | low_variety flagged | 75/STRONG; findings=['low_variety'] | PASS |
| T07 | Uppercase only | `KQZVMXWPLTRB` | low_variety flagged | 75/STRONG; findings=['low_variety'] | PASS |
| T08 | Numbers only | `739402581637` | low_variety, not above MODERATE | 60/MODERATE; findings=['low_variety'] | PASS |
| T09 | Symbols only | `!@#$%^&*()` | keyboard_pattern, WEAK or lower | 24/WEAK; findings=['keyboard_pattern', 'low_variety', 'short_length'] | PASS |
| T10 | Mixed random characters | `k7#Qm2!vXr9$` | STRONG or better, no findings | 89/VERY STRONG; findings=[] | PASS |
| T11 | Sequential numbers | `Ab1234Cd` | sequence detected | 40/WEAK; findings=['sequence', 'short_length'] | PASS |
| T12 | Reverse numeric sequence | `mq9876tw` | descending sequence detected | 40/WEAK; findings=['sequence', 'short_length'] | PASS |
| T13 | Sequential letters | `mkabcdq` | sequence detected | 20/VERY WEAK; findings=['low_variety', 'sequence', 'short_length'] | PASS |
| T14 | Keyboard sequence | `qwertyuiop` | keyboard_pattern detected | 0/VERY WEAK; findings=['common_password', 'dictionary_word', 'keyboard_pattern', 'low_variety', 'short_length'] | PASS |
| T15 | Repeated characters | `Tx1aaaaZ9` | repeated_character detected | 52/MODERATE; findings=['repeated_character', 'short_length'] | PASS |
| T16 | Repeated substring | `abcabcabc` | repeated_substring detected | 18/VERY WEAK; findings=['low_variety', 'repeated_substring', 'short_length'] | PASS |
| T17 | Common word + number | `welcome123` | common-word pattern, WEAK or lower | 15/VERY WEAK; findings=['common_word_pattern', 'short_length'] | PASS |
| T18 | Word + year | `summer2026` | word+year detected, WEAK or lower | 15/VERY WEAK; findings=['common_word_pattern', 'short_length', 'year_pattern'] | PASS |
| T19 | Personal name overlap | `Rahul@123 (name=Rahul)` | personal_info detected | 19/VERY WEAK; findings=['personal_info', 'predictable_structure', 'short_length'] | PASS |
| T20 | Birth year overlap | `mq2004zkv! (year=2004)` | personal_info detected | 44/MODERATE; findings=['personal_info', 'short_length', 'year_pattern'] | PASS |
| T21 | Long passphrase-like input | `violet-anchor-pepper-glacier-moss` | VERY STRONG-ish, no dictionary penalty | 89/VERY STRONG; findings=[] | PASS |
| T22 | Unicode handling | `Zürich-Ωmega-猫7!qx` | No crash, valid result | 100/VERY STRONG; findings=[] | PASS |
| T23 | Space handling | `tiny orbit lantern 4 meadow` | has_space true, STRONG or better | 93/VERY STRONG; has_space=True | PASS |
| T24 | Maximum accepted length | `128 chars / 132 chars` | 128 accepted, 132 rejected without echo | 128 chars -> 200; 132 chars -> 400; echoed=False | PASS |
| T25 | Strength-score boundaries | `scores 0,20,21,40,41,60,61,80,81,100` | Correct class for each | all 10 boundary scores map correctly | PASS |
| T26 | Suggestion generation | `123456` | Specific suggestions + manager + MFA | 8 suggestions incl. sequence, manager, MFA | PASS |
| T27 | Secure password generation | `length 20` | Secure, random, all classes | 20 chars, all classes, differs per call, uses secrets; analyzer score 100 | PASS |
| T28 | Password not stored | `synthetic secret via API` | Not in DB file, not in response | secret absent from DB file and API response; no password column | PASS |
| T29 | Password not logged | `synthetic secret via API` | Not in logs/stdout/stderr | secret absent from logs, stdout and stderr (incl. error paths) | PASS |
| T30 | Analytics storage | `3 recorded analyses` | Metadata-only rows, no password | 3 rows stored; columns=['analysis_id', 'score', 'classification', 'password_length', 'unique_character_ratio', 'weakness_count', 'created_at'] | PASS |

**30/30 passed.**
