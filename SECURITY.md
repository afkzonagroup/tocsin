# Security

## Reporting a vulnerability

Please report vulnerabilities privately through **GitHub Security Advisories** ("Report a vulnerability" on the repository's Security tab). Do not open a public issue. If that is not possible, write to info@afkzonagroup.lt with "SECURITY" in the subject.

We confirm receipt within 3 working days and aim to fix confirmed issues within 30 days. We credit reporters who want to be credited.

Supported versions: the latest minor release.

## Threat model

### Assets

1. **Incident records**: descriptions, impact, indicators of compromise, timelines, answers about losses and affected persons. Confidential; may include personal data and information an attacker could use.
2. **Integrity of the record**: what was reported, when, and why (submission snapshots, the audit log). Needed as evidence towards the authority.
3. **Keys**: the store key or passphrase, export passphrases, webhook URLs and HMAC secrets.
4. **Deadlines**: correct computation; a wrong date can cause a missed legal deadline.

### Actors

- The **operator** (legitimate user) on their own machine or server.
- A **local attacker** with read access to the disk or backups but not the key (stolen laptop, backup leak, other user on a shared host).
- A **web attacker**: a page the operator visits while the UI runs (CSRF, DNS rebinding, clickjacking).
- A **network attacker** on the path of outgoing webhooks, or controlling DNS for a webhook host.
- A **hostile input source**: imported incident-tool exports, edited configuration, crafted store or export files.
- A **hostile contributor** submitting code.

### Trust boundaries

| Boundary | Crossing | Mitigations |
|---|---|---|
| Disk | Store and export files | AES-256-GCM per record with a fresh 96-bit random nonce, record id bound as associated data; sealed index with SHA-256 of every record box (detects removal, addition, swap, replay of an old record); KDF header bound into the index; files written with mode 0600 through temp file + fsync + rename + directory fsync; exclusive lock for every write; size caps on read; symlinks refused on read; new report files created with O_EXCL (never overwrite, never follow a planted link). |
| Key input | Environment, key file, terminal | Secrets only from `TOCSIN_KEY` / `TOCSIN_PASSPHRASE` / a 0600 key file / a no-echo prompt, never from command-line flags (visible in `ps`). scrypt N=2^17, r=8, p=1 for passphrases (minimum 12 characters); KDF parameters read from a file are bounded (2^14 to 2^20) before any work. Derived keys are zeroed on close. Wrong key and tampering give the same message (no oracle). |
| Browser to UI | HTTP on 127.0.0.1 | Loopback bind by default; non-loopback needs an explicit flag. One-time 256-bit login token; session cookie HttpOnly + SameSite=Strict; 8 h idle expiry. Every POST needs: form content type, Origin equal to the allowed Host, no cross-site `Sec-Fetch-Site`, and a per-session CSRF token compared in constant time. Host header allow-list (DNS rebinding); an any-address bind (0.0.0.0, ::) is never accepted as a Host and requires explicit `--allowed-host` values. CSP `default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'` and no JavaScript at all. nosniff, DENY framing, no-referrer, COOP/CORP, `Cache-Control: no-store`. 64 KiB body limit, 300 form fields, header/request timeouts, rate-limit hook (default 300 requests/min per client). Errors never contain stack traces. All output escaped through one HTML template function. |
| Tocsin to webhook | Outbound HTTPS | Only when configured and `tocsin notify` runs. URL and secret from environment variables, never in the config file or logs. https only, default port, no credentials in the URL. Every DNS answer must be a public unicast address (blocks loopback, RFC 1918, CGNAT, link-local incl. 169.254.169.254, IPv6 ULA incl. fd00:ec2::254, multicast, documentation, 6to4/NAT64/Teredo, IPv4-mapped, IPv4-compatible and IPv4-translated, and any IPv6 address outside global unicast 2000::/3). The connection is pinned to the checked address (DNS rebinding). Redirects are not followed. 10 s timeout, 64 KiB response cap. No cookies. Generic webhooks are HMAC-SHA256 signed over timestamp and body. Messages carry deadline metadata only; titles only if enabled, and then stripped of chat markup. |
| Imports | Third-party JSON | 10 MiB cap, 1000 incidents, only documented fields read, control and bidi characters removed, lengths capped, drafts only (never awareness, significance or submissions). |
| Reports | Files you send | Markdown escapes HTML and Markdown syntax; HTML escapes every value and embeds a CSP that allows only its own hashed stylesheet. Reports are plaintext by design: store them as carefully as the incident itself. |
| Terminal | CLI output | Control characters (including ESC) are stripped from user data before printing. |
| Supply chain | Dependencies, CI | Zero runtime dependencies. Dev dependencies pinned; lockfile committed; `npm audit --omit=dev` clean; no install scripts; CI actions pinned by commit SHA with `contents: read`; CodeQL. |

### Residual risks and limits

- **Whole-file rollback**: someone with write access to the disk can replace the store with an older complete copy. An open UI or CLI session notices a revision going backwards; a fresh start cannot. Write down the audit head hash (`tocsin audit --verify`) after important steps if you need proof against this.
- **Metadata**: the store reveals record ids (incident numbers and years), the number of audit entries and record sizes, but no contents.
- **Key holder**: anyone with the key can read and rewrite everything, including the audit chain.
- **Memory**: data is decrypted in process memory while Tocsin runs. JavaScript strings cannot be wiped.
- **Actor names** in the audit log come from `TOCSIN_ACTOR` or the operating-system user. They are self-declared, not authenticated.
- **Login link**: `tocsin ui` prints a one-time login link on standard error. Anyone who reads it before you use it (for example in `docker logs`) can log in once. Use it promptly; restart the UI to get a new one.
- **Debug output**: `TOCSIN_DEBUG=1` prints stack traces of unexpected errors to the local terminal. The web UI never shows them.
- **Plain HTTP UI**: the UI uses plain HTTP on loopback. If you expose it beyond the machine (for example in a container), put it behind TLS and an authenticating proxy, and pass the proxy host with `--allowed-host`.
- **Lock files**: a crashed process can leave `<store>.lock`. Tocsin removes it after two minutes when the recorded process no longer exists; otherwise delete it by hand.
- **Time**: deadlines depend on a correct system clock and on the IANA time-zone data in your Node.js runtime.

## Data flows

Nothing leaves the machine unless you configure webhooks and run `tocsin notify`. There is no telemetry, no update check, no remote font or script. The UI loads only its own stylesheet.

| Data | Where it goes |
|---|---|
| Incident records, answers, audit log | Encrypted store file only |
| Exports | Encrypted bundle file you choose |
| Reports | Your terminal or a file you choose (plaintext) |
| Webhook messages | The URLs you configure: incident id, stage, due time, state; title only if enabled |
