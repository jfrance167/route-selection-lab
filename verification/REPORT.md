# Local verification — October 5, 2026

Approved stages 2–4 complete locally on Windows CPython 3.13.7. Original offline API/CLI, strict parser/canonical paths/groups, lookup, four fictional examples, tests and portfolio records. SCHEMA.md frozen before code after coordinator 01:41 addendum.

| Check | Actual result |
|---|---|
| `python -m unittest discover -s tests -v` | 21 passed; normal.log |
| `python -O -m unittest discover -s tests -v` | 21 passed, optimized CLI children; optimized.log |
| `python -m compileall -q route_lab.py tests` | exit 0 |
| Bandit 1.9.4 application/tests | exit 0, zero findings/errors; bandit.json |
| Independent bit-mask expectations | 32 bounded IPv4/IPv6 destination comparisons passed |
| Input-order permutation | same ambiguous report under route reversal |
| Forbidden capabilities | analysis passed while socket/DNS/subprocess/address iteration patched to fail |
| Actual receiving pipe closed | process exit 2, no ignored-flush traceback, normal and optimized |
| Deliberate shortest-prefix mutation | detected: 5 test failures |
| Deliberate first-tie mutation | detected: 3 test failures |
| Restore mutations and final suite | exact original source bytes restored; normal/-O final suites passed |
| Four demo CLI fixtures | lookup/ambiguous/ecmp exit 0; unsupported exit 3; saved demo JSON |

Receipt hashes application, tests and all four source fixtures. Source SHA-256 `df2a30b691a8dd172b42be4bddc598d767eb184d8ae0872ccbf3827cd91e9c07`. Logs and receipt.json preserve exact final checks. Expected results are fixed independently in tests/schema; the bit-mask oracle uses literal bases/shift masks, not ipaddress membership. No complete upstream/standards-conformance oracle claim.

## ECC self-review and repairs

Used ecc-code-review pinned checklist and ecc-verification-loop on actual application, parser/API/CLI callers, tests, examples and docs after restoration. Reviewed strict types, normalization, canonical duplicate identity, group scope/completeness, longest/tie/discard behavior, error delivery, resource bounds and absent network/system capabilities. Implementing-agent self-review, not independent audit.

Confirmed defect: route_lab.py main output-exception/shutdown path. Closing the receiving pipe reproduced process exit 120 and an ignored stdout-flush error, despite main returning 2. Fixed by disabling additional stdout shutdown flushing after delivery failure; exact guard now at source lines 267–270. Added process-level regression and reran normal/-O checks. No unresolved confirmed application defect from this review.

Initial Bandit B311 flagged deterministic seeded test sampling; replaced sampling with a fixed boundary list, improving expected-case clarity. Three narrow remaining test-only suppressions: subprocess import B404 and fixed local CLI `run`/`Popen` calls B603, each explained in source. Application has zero suppressions. There is no shell/third-party execution or security randomness.

Limits: Windows 3.13.7 only; Linux/Python 3.11/3.12 and hosted CI/CodeQL NOT RUN. No standalone Git repository/history, dedicated secret-scanner result, live router comparison or packet/flow simulation. Authored files were reviewed for private material/credentials; not a secret-scanner guarantee. No publication/merge/system changes. Original scanner Linux live SYN verification remains pending; DNS/scanner source/evidence untouched.
