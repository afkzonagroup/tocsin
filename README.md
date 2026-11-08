# Tocsin

Tocsin is a self-hosted, offline incident register for NIS2 significant-incident reporting: deadlines, significance criteria, report content and an encrypted audit trail.

## Why

The NIS2 Directive, [Directive (EU) 2022/2555](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022L2555), applies through national law from 18 October 2024. Under Article 23, essential and important entities must report significant incidents to their CSIRT or competent authority in stages: an early warning within 24 hours of becoming aware, an incident notification within 72 hours, and a final report one month after the notification. For DNS service providers, TLD name registries, cloud, data centre, CDN, managed service and managed security service providers, online marketplaces, search engines, social networks and trust service providers, [Implementing Regulation (EU) 2024/2690](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R2690) sets the thresholds for "significant".

Most teams track this in Word and Excel templates. Tocsin keeps the register, computes the deadlines, checks the thresholds, and builds each report with the elements the Directive names. Everything stays on your machine.

## What it does

- Keeps an incident register in an encrypted local file.
- Computes the Article 23(4) deadlines from the moment you record awareness, in UTC, shown in your time zone, safe across daylight-saving changes.
- Assesses significance against Articles 3 to 14 of Implementing Regulation (EU) 2024/2690 and shows the article behind every result. Questions that need judgement are asked, not answered.
- Builds the early warning, incident notification, intermediate, progress and final report with exactly the elements Article 23(4) lists, and keeps optional fields apart.
- Writes reports as Markdown, JSON or self-contained HTML.
- Keeps a hash-chained audit log of every change and a snapshot of each submitted report.
- Sends deadline reminders to Slack, Microsoft Teams or any HTTPS endpoint, if you configure it.

It does **not** submit anything to authorities, does not know national portals or forms, and does not decide whether you are in scope of NIS2.

## Quick start

Requires Node.js 22 or later.

```sh
npm install -g @afkzona/tocsin
mkdir tocsin && cd tocsin
tocsin init --timezone Europe/Brussels        # asks for a passphrase; writes tocsin.config.json
# edit tocsin.config.json: your entity and your CSIRT or competent authority
tocsin create --title "Storage cluster outage" --service cloud --detected now
tocsin assess INC-2026-0001 --answer services.cloud.completeUnavailabilitySeconds=45m --answer scheduledMaintenanceOnly=no
tocsin aware INC-2026-0001 --at now           # starts the 24 h / 72 h clocks
tocsin deadlines
tocsin set INC-2026-0001 suspectedUnlawfulOrMalicious unknown   # the early-warning elements
tocsin set INC-2026-0001 crossBorderImpact no
tocsin report INC-2026-0001 early-warning --format html --out early-warning.html
tocsin submit INC-2026-0001 early-warning --at now --ref "CSIRT ticket 123"
```

Instead of the prompt you can set `TOCSIN_PASSPHRASE`, or `TOCSIN_KEY` with a random 32-byte key (`openssl rand -hex 32`).

## How it maps to the law

| Requirement | Provision | In Tocsin |
|---|---|---|
| Notify significant incidents to the CSIRT or competent authority | [NIS2 Art 23(1)](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022L2555) | `authority` in the config; no national contacts built in |
| What is significant (general test) | NIS2 Art 23(3) | Two questions for entities outside IR 2024/2690 |
| What is significant (relevant entities) | [IR 2024/2690 Art 3, 5-14](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R2690) | `tocsin assess`, thresholds exact |
| Recurring incidents | IR 2024/2690 Art 4 | `tocsin recurring` |
| Early warning within 24 h | NIS2 Art 23(4)(a) | Deadline + report |
| Incident notification within 72 h (24 h for trust services) | NIS2 Art 23(4)(b) and last subparagraph | Deadline + report |
| Intermediate report on request | NIS2 Art 23(4)(c) | `tocsin request`, `status-update` |
| Final report one month after the notification | NIS2 Art 23(4)(d) | Deadline + report (i)-(iv) |
| Progress report if still ongoing | NIS2 Art 23(4)(e) | Deadline + report |
| Notify recipients of services; communicate measures for significant cyber threats | NIS2 Art 23(1), 23(2) | `tocsin recipients`, reminder |

[LEGAL.md](LEGAL.md) quotes the provisions, lists every threshold and explains the interpretation choices. The key ones:

- **Hours are real elapsed time.** 24 hours across a daylight-saving change ends one wall-clock hour later or earlier.
- **"One month" is a calendar month in your time zone**: same day and time next month; 31 January → 28 (or 29) February; 31 March → 30 April.
- Where the text allows two readings, Tocsin uses the one with the earlier deadline. National transposition law decides how periods are counted and may set stricter rules (NIS2 Art 5 allows a higher level of cybersecurity); check it.

## Command line

| Command | What it does |
|---|---|
| `init [--timezone Z]` | Create the encrypted store and a config template |
| `config check` | Validate the configuration |
| `create --title T --service S[,S] [--occurred T] [--detected T]` | New incident |
| `list`, `show <id>` | Register and one incident (`--json` for scripts) |
| `set <id> <field> <value or ->` | Change a field; `-` reads standard input; `--clear` removes |
| `aware <id> --at T [--reason R]` | Became aware of the significant incident; starts the clocks |
| `conclude <id> --at T` / `--reopen` | Handling concluded / incident ongoing again |
| `questions <id>`, `assess <id> --answer id=value` | Significance questions and answers |
| `recurring` | Recurring-incident check |
| `deadlines [--all] [--fail-on-overdue]` | Deadlines; overdue in red; exit code 3 when overdue |
| `request <id> --at T [--by X] [--due T]` | The authority asked for an intermediate report |
| `status-update <id> <request> <text>` | Content of that report |
| `report <id> <stage> [--format md\|json\|html] [--out F]` | Build a report (submitted stages show what was sent) |
| `submit <id> <stage> --at T [--ref X]` | Record a submission |
| `recipients <id> --kind incident\|threat --at T --audience A --summary S` | Record a communication to recipients |
| `audit [--verify]` | Audit log and chain check |
| `export --out F` | Encrypted export, also the backup format |
| `import --in F [--replace]` | Restore an export; `--replace` replaces an existing store and keeps it as a `.bak` |
| `rekey [--new-key-file F]` | Re-encrypt the store under a new key or passphrase |
| `migrate` | Upgrade the store file to the current format version |
| `import-incidents --format F --in F --service S` | Draft incidents from another tool |
| `notify [--dry-run]` | Send due and overdue reminders |
| `ui` | Local web interface |

Times: `now`, `2026-03-29T14:05` (your configured zone) or `2026-03-29T14:05+02:00`. Times that do not exist or happen twice because of a clock change are refused unless you give the offset. Colours follow [NO_COLOR](https://no-color.org) and `--no-color`.

Stages: `early-warning`, `incident-notification`, `intermediate-report`, `progress-report`, `final-report`.

Service types: `dns`, `tld-registry`, `cloud`, `data-centre`, `cdn`, `managed-service`, `managed-security-service`, `online-marketplace`, `online-search-engine`, `social-network`, `trust-service`, `other`.

## Backup and restore

A backup is an encrypted export. It is sealed under its own key, so you can keep the backup key apart from the store key.

```sh
export TOCSIN_EXPORT_KEY="$(cat /secure/backup.key)"     # or TOCSIN_EXPORT_PASSPHRASE, or the prompt
tocsin export --out "backup-$(date -u +%Y%m%dT%H%M%SZ).tocsin-export"
```

Each export adds an `export.created` entry to the audit log, so the log shows when backups were taken. Copy the file off the machine.

To restore into a new store, give a new `--store` path. To replace a store that is damaged or lost its key, add `--replace`:

```sh
tocsin import --in backup-20260110T080000Z.tocsin-export --replace
```

Before anything is replaced, Tocsin decrypts every record of the backup and checks its index and its audit chain. A backup that does not verify changes nothing. Without `--replace`, an existing store is never overwritten. With it, the current store file is kept byte for byte as `<store>.<UTC time>.bak` (mode 0600), even when it is damaged. The restored store gets a `store.restored` audit entry. It is encrypted under the store key you give (`TOCSIN_KEY`, `TOCSIN_PASSPHRASE`, `--key-file` or the prompt).

Practise a restore now and then: restore the latest backup into a scratch path and run `tocsin audit --verify --store <scratch>` on it.

If the store file is cut short (a full disk, a copy that stopped), Tocsin refuses to open it and says it may be truncated. Its own writes cannot cause this: every write goes to a temporary file, which is fsynced and then renamed over the store. A crash can leave a `.<store>.<random>.tmp` file next to the store. Tocsin never reads it; delete it.

## Key rotation

```sh
TOCSIN_KEY=<current key> TOCSIN_NEW_KEY="$(openssl rand -hex 32)" tocsin rekey
```

The new secret comes from `--new-key-file` (a 0600 file), `TOCSIN_NEW_KEY`, `TOCSIN_NEW_PASSPHRASE`, or a prompt that asks twice. It is never taken from the command line and never printed. Any direction works: passphrase to passphrase, raw key to raw key, or between the two. A new passphrase needs at least 12 characters, and the same secret again is refused.

`rekey` takes the store lock, verifies the whole store and its audit chain with the current secret, seals every record again under a new salt, verifies the result in memory, replaces the file atomically, and reads it back to verify it once more. The audit log keeps every entry and gains a `store.rekeyed` entry that names only the kind of secret. If the process stops at any point, the store opens with the old secret or with the new one, never neither: try both.

Stop `tocsin ui` before rotating: a running interface holds the old key and refuses to write afterwards. Backups and exports made before the rotation still open with the keys they were made with; make a new backup and destroy old ones if the old key leaked.

## Format upgrades

Every store file records its format version. A Tocsin release that changes the format can still read the old one: run `tocsin migrate`. It takes the lock, verifies the store, converts it step by step, verifies the result completely, keeps the original as `<store>.v<old version>-<UTC time>.bak` and adds a `store.migrated` audit entry. On a current store it only verifies and changes nothing. Other commands refuse an old store and point to `tocsin migrate`. A store written by a newer Tocsin is refused, never rewritten; upgrade Tocsin instead.

## Web interface

```sh
tocsin ui            # http://127.0.0.1:8080, prints a one-time login link
```

The interface listens on 127.0.0.1 only. Open the printed link once; it sets a session cookie. There is no JavaScript. Every form is protected against cross-site requests, and the page works with a strict Content-Security-Policy. To bind elsewhere you must pass `--allow-non-loopback` and the host names users will type with `--allowed-host`; then put it behind TLS and authentication.

## Docker

```sh
docker build -t tocsin .
docker volume create tocsin-data
printf 'TOCSIN_KEY=%s\n' "$(openssl rand -hex 32)" > tocsin.env && chmod 600 tocsin.env   # keep this file safe
docker run --rm -it --env-file tocsin.env -v tocsin-data:/data tocsin init --timezone Europe/Brussels
docker run --rm -it --env-file tocsin.env -v tocsin-data:/data --read-only -p 127.0.0.1:8080:8080 tocsin
```

The image runs as a non-root user, has no npm or other package manager, and keeps all data in `/data`. Edit `/data/tocsin.config.json` through the volume. Publish the port on `127.0.0.1` only. If you publish it on another host port, add that host and port to the command, for example `ui --host 0.0.0.0 --port 8080 --allow-non-loopback --allowed-host 127.0.0.1:9000`.

## Webhooks

Reminders for due and overdue deadlines, and notices of recorded submissions. Configure in `tocsin.config.json`; run `tocsin notify` from cron or a systemd timer:

```json
"webhooks": [
  { "id": "security-chat", "kind": "slack", "urlEnv": "TOCSIN_SLACK_WEBHOOK_URL", "events": ["deadline-due-soon", "deadline-overdue"] },
  { "id": "teams", "kind": "teams", "urlEnv": "TOCSIN_TEAMS_WEBHOOK_URL", "events": ["deadline-overdue"] },
  { "id": "soc", "kind": "generic", "urlEnv": "TOCSIN_SOC_URL", "secretEnv": "TOCSIN_SOC_SECRET", "events": ["deadline-overdue", "stage-submitted"] }
]
```

```sh
*/15 * * * * cd /srv/tocsin && TOCSIN_KEY=... TOCSIN_SLACK_WEBHOOK_URL=... tocsin notify
```

- **Slack**: an [incoming webhook](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/) URL. Body `{"text": …}`.
- **Microsoft Teams**: a Workflows webhook ("When a Teams webhook request is received"); Office 365 connectors were retired. Body: one Adaptive Card ([Microsoft docs](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook)).
- **Generic**: JSON body with headers `x-tocsin-timestamp` and `x-tocsin-signature: sha256=<HMAC-SHA256(secret, timestamp + "." + body)>`. Verify with `verifySignature()` from the package; reject timestamps older than five minutes.

URLs and secrets are read from the environment variables you name, never from the file. Only HTTPS to public addresses is allowed; redirects are not followed. Messages contain the incident id, stage, due time and state. Titles are left out unless you set `"includeTitle": true`.

## Importing from other tools

Creates **draft** incidents (title, detection time, a summary line, a reference, and for MISP the indicators of compromise). It never records awareness, significance or submissions; those are your decisions.

| `--format` | Input | Documentation |
|---|---|---|
| `pagerduty` | Response of the PagerDuty REST API v2 "Get an incident" (`{"incident":…}`) or "List incidents" (`{"incidents":[…]}`) | [Get an incident](https://docs.pagerduty.com/developer/api/reference/rest/incidents/get-incident), [List incidents](https://docs.pagerduty.com/developer/api/reference/rest/incidents/list-incidents) |
| `incident-io` | Response of incident.io API v2 "Show incident" or "List incidents" (schema `IncidentV2`) | [incident.io API reference](https://docs.incident.io/api-reference), [OpenAPI](https://api.incident.io/v1/openapiV3.json) |
| `misp` | A MISP event (`{"Event":…}`) in the MISP core format; attributes with `to_ids: true` become IoCs | [MISP core format (Internet-Draft)](https://github.com/MISP/misp-rfc) |

```sh
curl -s -H "Authorization: Token token=$PD_TOKEN" -H "Accept: application/vnd.pagerduty+json;version=2" \
  https://api.pagerduty.com/incidents/Q1ABC > pd.json
tocsin import-incidents --format pagerduty --in pd.json --service cloud
```

## Library

```ts
import { addCalendarMonths, assessSignificance, computeDeadlines, parseInstant } from '@afkzona/tocsin';

const awareAt = parseInstant('2027-01-31T09:30', 'Europe/Brussels');
console.log(addCalendarMonths(awareAt, 1, 'Europe/Brussels')); // '2027-02-28T08:30:00.000Z'

const result = assessSignificance({
  serviceTypes: ['cloud'],
  answers: { services: { cloud: { completeUnavailabilitySeconds: 31 * 60 } } },
});
console.log(result.outcome); // 'significant'
console.log(result.reasons[0]?.ref.provision); // 'Article 7, point (a)'
```

```ts
import { buildReport, computeDeadlines, renderReport, type Incident, type TocsinConfig } from '@afkzona/tocsin';

const config: TocsinConfig = {
  version: 1,
  timeZone: 'Europe/Brussels',
  entity: { name: 'Example UAB' },
  authority: { role: 'csirt', name: 'National CSIRT' },
};
const incident: Incident = {
  id: 'INC-2026-0001',
  title: 'Storage cluster outage',
  createdAt: '2026-03-28T09:00:00.000Z',
  updatedAt: '2026-03-28T09:00:00.000Z',
  serviceTypes: ['cloud'],
  awareAt: '2026-03-28T10:00:00.000Z',
  details: { suspectedUnlawfulOrMalicious: 'no', crossBorderImpact: 'unknown' },
  submissions: [],
  intermediateRequests: [],
  recipientCommunications: [],
  linkedIncidentIds: [],
};
const due = computeDeadlines(incident, config.timeZone, Date.parse('2026-03-28T10:00:00.000Z'));
console.log(due.map((d) => [d.kind, d.dueAt])[0]); // ['early-warning', '2026-03-29T10:00:00.000Z']
const markdown = renderReport(buildReport(incident, 'early-warning', config, Date.now()), 'md');
console.log(markdown.startsWith('# Early warning: Storage cluster outage')); // true
```

The package also exports the encrypted store (`EncryptedStore`), store maintenance (`rekeyStore`, `restoreStore`, `migrateStore`), the register operations (`ops`), the audit chain, the web UI (`startUi`), the webhook sender and the importers. All public functions have TSDoc comments.

## Configuration

`tocsin.config.json` (path: `--config` or `TOCSIN_CONFIG`). See [tocsin.config.example.json](tocsin.config.example.json).

| Field | Required | Meaning |
|---|---|---|
| `version` | yes | `1` |
| `timeZone` | yes | IANA zone for display and "one month" (e.g. `Europe/Brussels`) |
| `entity.name` | yes | Your organisation |
| `entity.category`, `memberState`, `contactName`, `contactEmail`, `contactPhone` | no | Shown as optional report fields |
| `authority.role` | yes | `csirt` or `competent-authority` |
| `authority.name` | yes | Who receives your reports under your national law |
| `authority.channel`, `url` (https), `email`, `phone`, `notes` | no | How you submit |
| `turnover.financialYear`, `turnover.amountCents` | no | Preceding year's total annual turnover, for the 5 % test of IR Art 3(1)(a) |
| `webhooks[]` | no | See "Webhooks" |

Environment: `TOCSIN_STORE`, `TOCSIN_CONFIG`, `TOCSIN_KEY` or `TOCSIN_PASSPHRASE`, `TOCSIN_EXPORT_KEY` or `TOCSIN_EXPORT_PASSPHRASE`, `TOCSIN_NEW_KEY` or `TOCSIN_NEW_PASSPHRASE` (for `rekey`), `TOCSIN_ACTOR` (name in the audit log; default: OS user), `NO_COLOR`.

## Limitations

- Not legal advice, and using it does not make anyone compliant. You decide what is significant and what you report.
- National rules are not encoded: portals, forms, languages, extra fields, and thresholds for entities outside IR 2024/2690.
- Other regimes (GDPR breach notification, DORA, CER, sector rules) are not covered.
- English only. Labels are not official translations of the Directive.
- The legal texts were checked on 8 November 2026. Amendment proposals COM(2025) 837 and COM(2026) 13 were pending and are not implemented.

## Security

Details and the threat model: [SECURITY.md](SECURITY.md). In short: AES-256-GCM per record with a sealed index, scrypt for passphrases, atomic 0600 writes, crash-safe key rotation and verified restores, hash-chained audit log, loopback-only UI with one-time token, CSRF tokens and a strict CSP, SSRF-guarded webhooks, no telemetry. Report vulnerabilities through GitHub Security Advisories.

## Dependencies

Runtime: **none**. Tocsin uses only Node.js built-ins (`node:crypto`, `node:fs`, `node:http`, `node:https`, `node:dns`, `node:net`, `node:util`, `Intl`).

Development only (pinned in `package-lock.json`): TypeScript (compiler), Vitest and @vitest/coverage-v8 (tests, coverage), ESLint, @eslint/js and typescript-eslint (lint), @types/node (types). An npm `overrides` entry pins minimatch 11.0.5 in the dev tree to clear a moderate advisory in ESLint's dependency.

Node.js 22 or later: Node.js 20 reached end of life on 30 April 2026, and the test tooling requires 22.12.

## Licence and Enterprise

Copyright 2026 MB AFKzona Group.

Tocsin is licensed under the [GNU AGPL v3 only](LICENSE) with one additional term under section 7(b) ([LICENSE-ADDITIONAL-TERMS.md](LICENSE-ADDITIONAL-TERMS.md)): the attribution "Tocsin by AFKzona Group" stays in the web interface and in the report templates. "Tocsin" is a trademark; forks must use another name ([TRADEMARKS.md](TRADEMARKS.md)).

**Enterprise.** MB AFKzona Group offers a commercial licence for organisations that cannot use the AGPL-3.0 terms (including white-label use without the attribution notice, and warranty and indemnity options), integration into your systems, custom connectors and features, and support agreements. See [COMMERCIAL.md](COMMERCIAL.md) or contact info@afkzonagroup.lt.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Pull requests need the [CLA](CLA.md). Please follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Disclaimer

Tocsin is provided "as is", without warranty, as set out in the licence. It is not legal advice. Check your national law and your authority's guidance, and have your reporting process reviewed by a qualified person.

Maintained by AFKzona Group.
