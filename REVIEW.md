# Review record

Two self-review passes, as required by the project standards. An independent review by the coordinator follows.

## Pass 1: correctness, law, API, tests (8 Nov 2026)

### What was checked

- **Law against code**, line by line: Article 23(1)-(4) and Article 6 NIS2; Articles 1, 3, 4 and 5-14 and recitals 30-40 of Implementing Regulation (EU) 2024/2690, re-read on EUR-Lex. Every threshold compared with the official wording ("more than", "exceeds", "whichever is smaller/lower", durations, user shares, the DNS misconfiguration exception, the trust-service calendar-week rule). Corrigenda and amendment status checked on EUR-Lex (none affecting the English text of the provisions used; two NIS2 amendment proposals pending).
- **Deadlines**: 24/72 h as elapsed time, trust-service 24 h notification, final report counted from the *submission* of the notification, progress-report rule, calendar months with month-end clamping, DST gaps and overlaps, local date vs UTC date.
- **Report content**: each stage carries exactly the Article 23(4) elements; optional fields separated and labelled.
- **API design**: pure functions for rules; store, clock and network only at the edges; public exports and TSDoc; README examples executed by a doctest.
- **Tests**: boundary values on both sides of every threshold and deadline; coverage.
- **Security checklist** from GOAL.md, item by item.
- **UI** rendered and screenshotted at 1280 px and 390 px (no horizontal page overflow, no console errors).

### Found and fixed

| # | Finding | Fix |
|---|---|---|
| 1 | Before the final-report deadline the tool showed a progress report and an undated final report for every incident whose handling had not concluded yet. Misleading: nobody knows yet whether it will still be ongoing then. | Until that deadline passes, one "final report" deadline is shown, with the progress-report rule in its basis (`finalAndProgress`). |
| 2 | A progress report that was never sent stayed "overdue" forever after handling concluded, although it can no longer be submitted. | New state `missed`; excluded from pending lists and reminders. |
| 3 | The recurring-incident check (IR Art 4) also grouped incidents of entities outside IR 2024/2690. | Only incidents with at least one relevant-entity service type count. |
| 4 | Point (f) of IR Art 3(1) could never be "met" for a real incident: there was no way to record a collective incident. | `create --link`, `linkedIncidentIds`, and `assessIncident()` runs the recurring check for the linked group. |
| 5 | The web form only showed open questions, so an answered question could not be corrected. | All questions for the service types are shown with their current values; open ones are marked (`questionsFor`). CLI: `questions --all`. |
| 6 | The optional "deadline" field of an intermediate report used the first request's deadline, not the one being answered. | Matched by request id. |
| 7 | Viewing a report in the UI wrote an audit entry (a GET with a side effect; could also fail on a locked store after the response was sent). | Removed; only files written by `report --out` and exports are audited. |
| 8 | Raw Unicode bidirectional-control characters had ended up in four source files inside regular expressions (Trojan Source risk; one broke a parser). | Replaced with `\u` escapes; a test now fails on any raw bidi or invisible character in sources, tests and README. |
| 9 | Display text for the 5 % turnover limit was clumsy ("rounded down for display"). | Reworded. |
| 10 | Incident ids wrapped across three lines in tables; the Lock button sat inside the navigation. | `nowrap` on id cells; Lock aligned right. |
| 11 | Coverage threshold applied to CLI/UI glue and failed at 89.9 % overall. | Threshold scoped to core modules (≥ 90 % lines); flow tests added for the remaining CLI commands (overall now 94.6 % lines). |
| 12 | Unused helper `any()` in thresholds; a shadowed variable in deadlines. | Removed / renamed. |
| 13 | LEGAL.md listed the eIDAS breach regime as a parallel regime; NIS2 Art 42 replaced that part of eIDAS. | Corrected the list (GDPR, DORA via Art 4 NIS2, CER, sector rules). |

## Pass 2: security, with an attacker's eyes (8 Nov 2026)

### What was checked

Assumed attackers: a thief with the disk but not the key; a web page open in the operator's browser; a network or DNS attacker on webhook traffic; a crafted import, store, export or config file; a hostile contributor. For each: what they could read, change, forge, or make Tocsin do.

- Store and export format: tampering, swapping, deleting, adding and replaying records; header and KDF manipulation; oversized KDF cost; malformed JSON; prototype keys; rollback.
- Key handling: flags vs environment vs prompt, key-file permissions, error oracles, weak-parameter hooks.
- UI: login token, session cookie, CSRF, Origin and Fetch-Metadata checks, DNS rebinding, clickjacking, content types, body and field limits, timeouts, error output, escaping of every value, redirects, headers on every response, binding.
- Webhooks: SSRF (private, loopback, link-local, metadata, CGNAT, ULA, mapped and translated IPv6 forms, decimal/hex IPv4 literals, mixed DNS answers, rebinding), redirects, timeouts, response size, signatures, secrets in config or logs, chat markup injection.
- Imports and terminal output: control characters, ANSI escapes, bidi overrides, size and count limits.
- Supply chain: dependencies, lockfile, install scripts, CI permissions and action pinning, Docker base image and user.

### Found and fixed

| # | Finding | Fix |
|---|---|---|
| 1 | A hostile or careless config could point a webhook's `urlEnv` or `secretEnv` at `TOCSIN_KEY` / `TOCSIN_PASSPHRASE` (key material used as a URL or HMAC secret). | Those names are refused by config validation (test added). |
| 2 | `TOCSIN_TEST_SCRYPT_N` let anyone create stores and exports with a 8× cheaper KDF. | Hook removed; CLI always uses N = 2^17. Tests use raw keys or the real cost. |
| 3 | A store copied with loose permissions would be opened silently. | The CLI warns when the store file is readable by group or others (test added). |
| 4 | The key-file permission check had no test. | Test added (0644 refused, 0600 accepted). |
| 5 | `servername` (SNI) was set even for IP-literal webhook URLs, which RFC 6066 forbids and Node warns about. | SNI only for host names. |
| 6 | Token comparison used HKDF as a hash; correct but unusual. | Plain SHA-256 of both sides, then `timingSafeEqual`. |
| 7 | Residual risks were not all documented: self-declared actor names, the one-time login link in logs (e.g. `docker logs`), `TOCSIN_DEBUG` stack traces, metadata visible in the store file. | Added to SECURITY.md. |
| 8 | Docker: a host port different from the container port would fail the Host check without explanation. | README shows `--allowed-host` for that case. |

Checked and found sound (tests exist and fail if the control is removed): per-record AES-256-GCM with bound ids, sealed index with record hashes, KDF bounds before work, 0600 + O_EXCL temp files + fsync + rename, symlink refusal, lock, rollback detection in an open session; one-time login token, HttpOnly/SameSite=Strict cookie, idle expiry, CSRF token, Origin and `Sec-Fetch-Site` checks, Host allow-list, form content type only, 64 KiB body, rate limit, security headers on every response, no stack traces, loopback default; SSRF address policy and DNS pinning, no redirects, timeout, HMAC signature with replay window; HTML and Markdown escaping, report CSP hash; control-character stripping for terminal output and imports.

### Not fixed (accepted, documented in SECURITY.md)

- Whole-file rollback by someone with disk write access cannot be detected on a fresh start (no external state). Mitigation: note the audit head hash.
- The UI uses plain HTTP on loopback; exposure beyond the machine needs a TLS proxy.
- Record ids, counts and sizes are visible in the store file.
- The response-size cap of the webhook transport is exercised (large body, no hang) but its effect is not directly observable in a test.

## Results after both passes

- `npm run check`: typecheck, lint, build and tests pass.
- Tests: 267 in 10 files. Coverage: 94.6 % lines overall; core modules 96-100 % lines.
- `npm audit --omit=dev`: 0 vulnerabilities (no runtime dependencies). Full `npm audit`: 0 after the minimatch override.
- Docker image built, run read-only as `node` with `init` and `ui`; login checked over the published loopback port; image and volume removed afterwards.

## Independent review (8 Nov 2026)

A separate review that did not rely on the two passes above. The official texts were downloaded from EUR-Lex again and compared word by word with the code, LEGAL.md and README; security controls were attacked directly; each claimed security control was removed temporarily to see whether a test fails (mutation check, about 65 mutations); the README quick start was run from a packed and installed package in an empty directory.

### What was checked

- **Law.** NIS2 Article 23(1)-(4) and the trust-service subparagraph, Article 5 (minimum harmonisation), Article 6 definitions and their numbers; IR 2024/2690 Articles 1, 3, 4 and 5-14 and recitals 30-40; Regulation 1182/71 Articles 1 and 3; corrigenda lists of both acts (the English NIS2 corrigendum of 22.12.2023 changes only Article 19(1); the IR corrigenda cover PL, SV and NL only). Every threshold: strict "more than" / "exceeds", "whichever number is smaller / lower", units (seconds, milliseconds, cents, user counts), the DNS misconfiguration exception (fewer than 1 000 and no more than 1 %), the trust-service calendar week, which entity types each article covers, which articles Article 3(3) user counting applies to (7 and 9-14, not 8). Deadlines: 24 h / 72 h as elapsed time across DST; the 24 h trust-service notification; final report from the notification *submission*; progress report and final report under point (e); month-end clamping; DST gap and overlap at the end of a month; the "earlier deadline" policy.
- **Security.** Web UI: login token, session cookie, CSRF token, Origin, `Sec-Fetch-Site`, Host allow-list and DNS rebinding, any-address binds, CSP and headers, body and field limits, method and content-type checks, error output. Store: AES-GCM construction, nonce handling, associated data, sealed index, rollback, permissions, atomic writes, lock recovery under concurrency, export/import. Webhooks: IPv4/IPv6 special ranges including mapped, compatible, translated, NAT64, 6to4 and Teredo forms, mixed DNS answers, address pinning, SNI, redirects, header and message injection, secrets in errors. Importers: size cap, deep nesting (V8's parser handles 5 million levels without a stack overflow), prototype keys, control characters. CLI: terminal escapes and carriage returns, output files (O_EXCL, symlinks), key files. Docker image (non-root, read-only, no package manager, pinned base).
- **Publish gate.** `git log --all`: only antonmacius-droid as author and committer, no co-author or tool-attribution lines. Tree: no agent files.

### Found and fixed

| # | Severity | Finding | Fix |
|---|---|---|---|
| 1 | High (docs) | The README quick start failed at its last step: `submit` refused the early warning because its two prescribed elements were empty. | Two `tocsin set` lines added. A new test runs every `tocsin` line of the README quick start, so the README cannot drift again. Verified with the packed package. |
| 2 | Medium (legal) | LEGAL.md said national law "may allow a later time; it cannot require an earlier one than the Directive's outer limits", and README said "National law may allow more time". Both are wrong: transposition cannot give more time than Article 23(4), and Article 5 NIS2 (minimum harmonisation) allows stricter rules. | Both corrected and referenced to Article 5. |
| 3 | Medium | Stale-lock recovery was racy: two writers that found the same stale lock both removed it and both entered the critical section (reproduced in a test: lost updates). A writer also deleted the lock file in `finally` even if it was no longer its own. | Stale lock is moved aside with an atomic rename and its inode checked; a writer removes the lock only if it is still the file it created. Tests: concurrent recovery, live-process old lock, taken-over lock. |
| 4 | Medium (tests) | Several controls listed above as "tests fail if the control is removed" were not covered: per-record associated data (the index hash masked it), the audit-chain check on open, the live-process check for old locks, `nosniff` and `frame-ancestors` (the test compared headers with the same constant), the 10 MiB import cap, IPv4-compatible IPv6. | New tests that re-seal the index with the real key to isolate the associated-data and audit checks (plus a check that the re-sealing helper itself is correct), literal header values, import cap and address-form cases. All these mutations now fail the suite. |
| 5 | Low (legal) | The DNS and TLD data-compromise questions said "data related to the provision of the service". IR Art 5(c) covers only the *authoritative* resolution service, Art 6(c) data related to the *technical operation of the TLD*. A recursive-only compromise could be answered "yes" and over-reported. | Service-specific wording; test added. |
| 6 | Low (legal) | LEGAL.md said a skipped (DST-gap) wall-clock time uses "the earliest matching instant"; no instant matches. | Wording states what the code does: read with the offset after the change, the earlier instant (02:30 becomes 01:30 local). Code comments aligned. |
| 7 | Low | The SSRF guard allowed IPv6 addresses outside global unicast (e.g. `4000::1`). | Only 2000::/3 is allowed; SECURITY.md updated. |
| 8 | Low | With `--host 0.0.0.0`, `0.0.0.0:<port>` was an accepted Host header (browsers reach 0.0.0.0 as the local machine). `--allowed-host` values were not validated. | Any-address binds are never a valid Host and require at least one `--allowed-host`; values must be `host[:port]`. Tests added. |
| 9 | Low | `tocsin report` without `--out` printed stored text unfiltered; a carriage return in a description could overwrite earlier terminal output. | Filtered through the terminal sanitiser when stdout is a terminal; pipes keep exact content. Test added. |
| 10 | Low (gate) | `.gitignore` did not exclude the local tool-state directory that the publish gate lists. | Added to `.gitignore` and `.dockerignore`. |
| 11 | Low (docs) | README "Why" omitted TLD name registries and managed security service providers; `audit verify` instead of `audit --verify` in a comment; the "(estimate)" deadline column overflowed. | Corrected. |

### Checked and found correct

Every threshold in `thresholds.ts` and `assess.ts` against Articles 3-14 (strictness, "whichever is smaller/lower" via `x > a ∨ x > b`, exact integers); Article 3(2) handling; Article 4 window and loss aggregation; Article 23(4) elements per stage; the 24 h trust-service rule with unknown impact counted as yes; final report counted from the notification submission; progress/final under point (e); a final report cannot be recorded before handling concluded; the 1182/71 comparison (Tocsin is never later); AES-256-GCM with random 96-bit nonces, HKDF per file salt, KDF bound into the index; Slack/Teams/generic payloads; HMAC signing and replay window; no secret or URL in error messages; Docker user and file system.

### Open decisions for the owner

1. **Recurring incidents (IR Art 4).** Only incidents *assessed as not significant* are grouped. Incidents that are undetermined or not yet assessed are left out. Including them would follow the "report more" policy but could suggest collective reports for incidents nobody has assessed. Keep as is, or include them with a warning?
2. **Article 23(4)(b) "where applicable".** The initial assessment (severity, impact) is treated as *required* in the incident notification. The text can be read as making it "where applicable" too. The stricter reading is kept; confirm.
3. **Docker base image.** The pinned digest was not re-verified in this review (no registry access); verify before the first published image.

### Results

- `npm run check`: typecheck, lint, build and tests pass. 281 tests in 10 files (was 267). Coverage 94.7 % lines overall; core threshold met.
- `npm audit --omit=dev`: 0 vulnerabilities.
- Mutation check: every security and legal control in the list above now fails at least one test when removed. Remaining survivors are equivalent or redundant mutations (the KDF binding in the index associated data, because any KDF change already changes the key; the DNS "fewer than 1 000" boundary, decided earlier by the "outside the exception" branch; the temporary-file mode, which is reset by `chmod` before rename; the webhook response cap, documented above).

## Store recovery: rekey, restore and migrations (issue #8)

### What was checked

- Every file-system step of `rekey`, `import --replace` and `migrate`, by crashing the operation there (the call fails and every later call fails too, as for a dead process: no cleanup, lock left behind), plus a half-written variant of every write. 4 rekey directions, restore and migrate; about 30 crash points each.
- After each crash: for rekey, exactly one of the two secrets opens the store, the store verifies (records, index, audit chain), and the rotation completes when run again; for restore and migrate, the store is the original file byte for byte, or the new store with a complete `.bak` of the original.
- Durability order: temp file fsynced before the rename, directory fsynced after it; `.bak` copies fsynced and their directory entry made durable before the store is replaced.
- Mutation check: each new control removed in turn (26 mutations), plus an in-place (non-atomic) write.

### Found and fixed during the work

| # | Finding | Fix |
|---|---|---|
| 1 | The version check ran after the strict key check, so a newer store with a new field was reported as "invalid structure". | The version is read first; a newer version is refused by name and never rewritten. |
| 2 | A truncated store gave "The file is not valid JSON." with no next step. | The message says it may be truncated or damaged and points to restoring a backup. |
| 3 | The no-key message suggested `--key-file` for the export and new-key prompts too. | Each prompt names its own flag. |

### Results

- All 26 mutations of new controls fail at least one test except one equivalent mutation: `import` passing `replace: true` to `restoreStore` is masked by the CLI's own check before any secret is read (the library check is killed separately).
- An in-place write instead of temp file and rename fails the crash matrix on the invariant itself (neither key opens after a half write).
