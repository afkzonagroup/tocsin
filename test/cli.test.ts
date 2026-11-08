// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { run } from '../src/cli/main.js';
import { colourEnabled, paint, term, type CliIo } from '../src/cli/io.js';
import { tempDir } from './helpers.js';

const KEY = 'ab'.repeat(32);
let dir: string;
let cleanup: () => Promise<void>;
let now = Date.UTC(2026, 0, 10, 8);

interface Captured {
  code: number;
  out: string;
  err: string;
}

async function cli(args: string[], env: Record<string, string> = {}, extra: Partial<CliIo> = {}): Promise<Captured> {
  let out = '';
  let err = '';
  const io: CliIo = {
    stdout: (s) => (out += s),
    stderr: (s) => (err += s),
    env: { TOCSIN_STORE: join(dir, 's.tocsin'), TOCSIN_CONFIG: join(dir, 'c.json'), TOCSIN_KEY: KEY, TOCSIN_ACTOR: 'tester', ...env },
    now: () => now,
    isTty: false,
    ...extra,
  };
  const code = await run(args, io);
  return { code, out, err };
}

beforeEach(async () => {
  ({ dir, cleanup } = await tempDir());
  now = Date.UTC(2026, 0, 10, 8);
  expect((await cli(['init', '--timezone', 'Europe/Vilnius'])).code).toBe(0);
});
afterEach(async () => {
  await cleanup();
});

describe('argument validation', () => {
  it('usage and unknown commands exit 2', async () => {
    expect((await cli([])).code).toBe(2);
    expect((await cli(['frobnicate'])).code).toBe(2);
    expect((await cli(['help'])).code).toBe(0);
    expect((await cli(['--version'])).out).toBe('0.1.1\n');
  });

  it('unknown options and extra positionals are rejected', async () => {
    const r = await cli(['list', '--bogus']);
    expect(r.code).toBe(2);
    expect(r.err).toMatch(/Unknown option/u);
    expect((await cli(['list', 'extra'])).code).toBe(2);
    expect((await cli(['create', '--title', 'x', '--service', 'cloud', 'extra'])).code).toBe(2);
  });

  it('required options, enums and times are validated', async () => {
    expect((await cli(['create', '--service', 'cloud'])).err).toMatch(/--title is required/u);
    expect((await cli(['create', '--title', 'x', '--service', 'toaster'])).err).toMatch(/service type must be one of/u);
    expect((await cli(['create', '--title', 'x', '--service', 'cloud', '--detected', '2026-02-30T10:00'])).code).toBe(2);
    expect((await cli(['create', '--title', 'x', '--service', 'cloud', '--detected', '2026-03-29T03:30'])).err).toMatch(/does not exist/u);
    expect((await cli(['create', '--title', 'x\u001b[31m', '--service', 'cloud'])).err).toMatch(/control/u);
    expect((await cli(['report', 'INC-2026-0001', 'bogus-stage'])).code).toBe(2);
    expect((await cli(['set', 'INC-2026-0001', 'notAField', 'x'])).code).not.toBe(0);
    expect((await cli(['assess', 'INC-2026-0001', '--answer', 'novalue'])).code).toBe(2);
  });

  it('secrets are never taken from flags', async () => {
    expect((await cli(['list', '--passphrase', 'x'])).code).toBe(2);
    expect((await cli(['list', '--key', KEY])).code).toBe(2);
  });

  it('a missing key without a terminal is an error, a wrong key is refused', async () => {
    expect((await cli(['list'], { TOCSIN_KEY: '' })).err).toMatch(/No key/u);
    const r = await cli(['list'], { TOCSIN_KEY: 'cd'.repeat(32) });
    expect(r.code).toBe(1);
    expect(r.err).toMatch(/Wrong key/u);
  });

  it('accepts a key file only when other users cannot read it', async () => {
    if (process.platform === 'win32') return;
    const { chmod } = await import('node:fs/promises');
    const kf = join(dir, 'key');
    await writeFile(kf, `${KEY}\n`, { mode: 0o644 });
    await chmod(kf, 0o644);
    expect((await cli(['list', '--key-file', kf], { TOCSIN_KEY: '' })).err).toMatch(/readable by other users/u);
    await chmod(kf, 0o600);
    expect((await cli(['list', '--key-file', kf], { TOCSIN_KEY: '' })).code).toBe(0);
  });

  it('warns when the store file is readable by other users', async () => {
    if (process.platform === 'win32') return;
    const { chmod } = await import('node:fs/promises');
    await chmod(join(dir, 's.tocsin'), 0o644);
    expect((await cli(['list'])).err).toMatch(/readable by other users/u);
  });

  it('init refuses to overwrite an existing store', async () => {
    expect((await cli(['init'])).err).toMatch(/already exists/u);
  });
});

describe('full flow', () => {
  it('create, assess, aware, deadlines, report, submit, audit, export and import', async () => {
    expect((await cli(['create', '--title', 'Cloud outage', '--service', 'cloud', '--detected', '2026-01-10T09:00'])).out).toMatch(/Created INC-2026-0001/u);
    const a = await cli(['assess', 'INC-2026-0001', '--answer', 'services.cloud.completeUnavailabilitySeconds=31m', '--answer', 'scheduledMaintenanceOnly=no']);
    expect(a.out).toMatch(/SIGNIFICANT/u);
    expect(a.out).toMatch(/IR 2024\/2690 Article 7, point \(a\)/u);
    expect((await cli(['questions', 'INC-2026-0001'])).out).toMatch(/directFinancialLossCents/u);

    await cli(['aware', 'INC-2026-0001', '--at', '2026-01-10T10:00']);
    let d = await cli(['deadlines']);
    expect(d.out).toMatch(/Early warning +2026-01-11 10:00 \(UTC\+02:00\)/u);
    expect(d.out).toMatch(/Incident notification +2026-01-13 10:00/u);

    now = Date.UTC(2026, 0, 11, 9); // early warning overdue
    d = await cli(['deadlines', '--fail-on-overdue']);
    expect(d.code).toBe(3);
    expect(d.out).toMatch(/OVERDUE/u);
    expect(d.out).not.toContain('\u001b['); // not a terminal: no colour

    await cli(['set', 'INC-2026-0001', 'suspectedUnlawfulOrMalicious', 'no']);
    await cli(['set', 'INC-2026-0001', 'crossBorderImpact', 'unknown']);
    const draft = await cli(['report', 'INC-2026-0001', 'incident-notification']);
    expect(draft.err).toMatch(/still empty: severity, impact/u);
    expect((await cli(['submit', 'INC-2026-0001', 'early-warning', '--at', 'now', '--ref', 'CSIRT-42'])).out).toMatch(/after the deadline/u);
    expect((await cli(['submit', 'INC-2026-0001', 'incident-notification', '--at', 'now'])).err).toMatch(/Prescribed elements are empty/u);
    await cli(['set', 'INC-2026-0001', 'severity', 'High']);
    await cli(['set', 'INC-2026-0001', 'impact', 'All EU customers']);
    expect((await cli(['submit', 'INC-2026-0001', 'incident-notification', '--at', 'now'])).code).toBe(0);

    const out = join(dir, 'ew.html');
    expect((await cli(['report', 'INC-2026-0001', 'early-warning', '--format', 'html', '--out', out])).out).toMatch(/as submitted/u);
    expect(await readFile(out, 'utf8')).toMatch(/Content-Security-Policy/u);
    expect((await cli(['report', 'INC-2026-0001', 'early-warning', '--format', 'html', '--out', out])).err).toMatch(/already exists/u);

    const audit = await cli(['audit', '--verify']);
    expect(audit.code).toBe(0);
    expect(audit.out).toMatch(/Audit chain intact/u);

    const bundle = join(dir, 'b.tocsin-export');
    const exportEnv = { TOCSIN_EXPORT_PASSPHRASE: 'export passphrase long' }; // real scrypt cost (2^17)
    expect((await cli(['export', '--out', bundle], exportEnv)).code).toBe(0);
    const restored = join(dir, 'restored.tocsin');
    const imp = await cli(['import', '--in', bundle, '--store', restored], { ...exportEnv, TOCSIN_KEY: 'ef'.repeat(32) });
    expect(imp.out).toMatch(/Restored 1 incident/u);
    const show = await cli(['show', 'INC-2026-0001', '--store', restored], { TOCSIN_KEY: 'ef'.repeat(32) });
    expect(show.out).toMatch(/Cloud outage/u);
    expect((await cli(['import', '--in', bundle, '--store', restored], { ...exportEnv, TOCSIN_KEY: 'ef'.repeat(32) })).err).toMatch(/already exists/u);
  });

  it('set reads "-" from standard input and --clear removes a value', async () => {
    await cli(['create', '--title', 'X', '--service', 'other']);
    await cli(['set', 'INC-2026-0001', 'indicatorsOfCompromise', '-'], {}, { readStdin: () => Promise.resolve('ip: 203.0.113.1\n\nsha256: abc\n') });
    let show = await cli(['show', 'INC-2026-0001', '--json']);
    expect((JSON.parse(show.out) as { details: { indicatorsOfCompromise: string[] } }).details.indicatorsOfCompromise).toEqual(['ip: 203.0.113.1', 'sha256: abc']);
    await cli(['set', 'INC-2026-0001', 'indicatorsOfCompromise', '--clear']);
    show = await cli(['show', 'INC-2026-0001', '--json']);
    expect((JSON.parse(show.out) as { details: Record<string, unknown> }).details['indicatorsOfCompromise']).toBeUndefined();
  });

  it('changing the awareness time after a submission needs a reason', async () => {
    await cli(['create', '--title', 'X', '--service', 'other']);
    await cli(['aware', 'INC-2026-0001', '--at', '2026-01-10T09:00']);
    await cli(['set', 'INC-2026-0001', 'suspectedUnlawfulOrMalicious', 'no']);
    await cli(['set', 'INC-2026-0001', 'crossBorderImpact', 'no']);
    await cli(['submit', 'INC-2026-0001', 'early-warning', '--at', 'now']);
    expect((await cli(['aware', 'INC-2026-0001', '--at', '2026-01-10T08:00'])).err).toMatch(/Give a reason/u);
    expect((await cli(['aware', 'INC-2026-0001', '--at', '2026-01-10T08:00', '--reason', 'log review'])).code).toBe(0);
  });

  it('imports drafts from a documented export format', async () => {
    const f = join(dir, 'pd.json');
    await writeFile(f, JSON.stringify({ incidents: [{ id: 'PX1', incident_number: 7, title: 'DB down', created_at: '2026-01-09T10:00:00Z', status: 'resolved' }] }));
    const r = await cli(['import-incidents', '--format', 'pagerduty', '--in', f, '--service', 'cloud']);
    expect(r.out).toMatch(/Imported 1 draft/u);
    const show = JSON.parse((await cli(['show', 'INC-2026-0001', '--json'])).out) as { title: string; awareAt?: string; detectedAt: string };
    expect(show.title).toBe('DB down');
    expect(show.awareAt).toBeUndefined();
    expect(show.detectedAt).toBe('2026-01-09T10:00:00.000Z');
  });

  it('covers the remaining commands', async () => {
    await writeFile(join(dir, 'c.json'), JSON.stringify({ version: 1, timeZone: 'Europe/Vilnius', entity: { name: 'E' }, authority: { role: 'csirt', name: 'C' }, turnover: { financialYear: '2025', amountCents: 100_000_000_000 } }));
    await cli(['create', '--title', 'Phish A', '--service', 'cloud', '--occurred', '2026-01-02T10:00', '--detected', '2026-01-02T11:00']);
    await cli(['create', '--title', 'Phish B', '--service', 'cloud', '--occurred', '2026-01-05T10:00']);
    for (const id of ['INC-2026-0001', 'INC-2026-0002']) {
      await cli(['set', id, 'rootCauseKey', 'phishing']);
      const answers = ['directFinancialLossCents=300000', 'scheduledMaintenanceOnly=no', 'tradeSecretExfiltration=no', 'deathOfNaturalPerson=no', 'considerableHealthDamage=no', 'maliciousUnauthorisedAccess=no'];
      const metrics = ['completeUnavailabilitySeconds=0s', 'limitedAvailabilitySeconds=0s', 'usersLimitedAvailability=0', 'totalUsersInUnion=10', 'dataCompromised=no', 'dataCompromisedMalicious=no', 'usersDataCompromise=0'].map((m) => `services.cloud.${m}`);
      const r = await cli(['assess', id, ...[...answers, ...metrics].flatMap((a) => ['--answer', a])]);
      expect(r.out, r.err).toMatch(/NOT-SIGNIFICANT/u);
    }
    expect((await cli(['recurring'])).out).toMatch(/SIGNIFICANT \(collectively\)/u);
    expect((await cli(['recurring', '--json'])).out).toMatch(/"status": "met"/u);
    const created = await cli(['create', '--title', 'Recurring phishing', '--service', 'cloud', '--link', 'INC-2026-0001', '--link', 'INC-2026-0002']);
    expect(created.out).toMatch(/INC-2026-0003/u);
    expect((await cli(['assess', 'INC-2026-0003'])).out).toMatch(/IR-3-1-f/u);
    expect((await cli(['questions', 'INC-2026-0001', '--all'])).out).toMatch(/answered: 300000.00/u);
    expect((await cli(['questions', 'INC-2026-0003', '--json'])).code).toBe(0);
    expect((await cli(['list'])).out).toMatch(/Recurring phishing/u);
    expect((await cli(['list', '--json'])).code).toBe(0);
    await cli(['aware', 'INC-2026-0003', '--at', '2026-01-10T09:00']);
    expect((await cli(['request', 'INC-2026-0003', '--at', 'now', '--by', 'CSIRT', '--due', '2026-01-12T10:00'])).out).toMatch(/R-1/u);
    expect((await cli(['status-update', 'INC-2026-0003', 'R-1', 'All contained'])).code).toBe(0);
    expect((await cli(['recipients', 'INC-2026-0003', '--kind', 'incident', '--at', 'now', '--audience', 'Customers', '--summary', 'Notice', '--measures', 'Reset passwords'])).out).toMatch(/C-1/u);
    expect((await cli(['conclude', 'INC-2026-0003', '--at', 'now'])).out).toMatch(/concluded/u);
    expect((await cli(['conclude', 'INC-2026-0003', '--reopen'])).out).toMatch(/ongoing again/u);
    expect((await cli(['conclude', 'INC-2026-0003', '--reopen', '--at', 'now'])).code).toBe(2);
    const show = await cli(['show', 'INC-2026-0003']);
    expect(show.out).toMatch(/Request R-1/u);
    expect(show.out).toMatch(/Recipients C-1/u);
    expect((await cli(['deadlines', '--all', '--json'])).code).toBe(0);
    expect((await cli(['audit'])).out).toMatch(/incident\.created/u);
    expect((await cli(['audit', '--verify', '--json'])).out).toMatch(/"ok": true/u);
    expect((await cli(['report', 'INC-2026-0003', 'intermediate-report', '--request', 'R-1', '--format', 'json'])).out).toMatch(/All contained/u);
  });

  it('notify plans and sends nothing in a dry run', async () => {
    await writeFile(
      join(dir, 'c.json'),
      JSON.stringify({ version: 1, timeZone: 'Europe/Vilnius', entity: { name: 'E' }, authority: { role: 'csirt', name: 'C' }, webhooks: [{ id: 'chat', kind: 'slack', urlEnv: 'HOOK', events: ['deadline-overdue'] }] }),
    );
    await cli(['create', '--title', 'X', '--service', 'other']);
    await cli(['aware', 'INC-2026-0001', '--at', '2026-01-08T09:00']);
    const r = await cli(['notify', '--dry-run']);
    expect(r.out).toMatch(/\[dry-run\] chat: \[Tocsin\] INC-2026-0001: Early warning is OVERDUE/u);
    const send = await cli(['notify']);
    expect(send.code).toBe(1);
    expect(send.err).toMatch(/HOOK/u);
  });

  it('notify does nothing without configured webhooks', async () => {
    expect((await cli(['notify'])).out).toMatch(/No webhooks configured/u);
  });

  it('config check reports problems', async () => {
    expect((await cli(['config', 'check'])).out).toMatch(/Configuration OK/u);
    await writeFile(join(dir, 'c.json'), JSON.stringify({ version: 1, timeZone: 'Mars/Base', entity: { name: 'x' }, authority: { role: 'csirt', name: 'y' } }));
    expect((await cli(['config', 'check'])).err).toMatch(/Unknown IANA time zone/u);
  });
});

describe('terminal output', () => {
  it('colour only on a terminal and never with NO_COLOR', () => {
    expect(colourEnabled({ env: {}, isTty: true })).toBe(true);
    expect(colourEnabled({ env: {}, isTty: false })).toBe(false);
    expect(colourEnabled({ env: { NO_COLOR: '1' }, isTty: true })).toBe(false);
    expect(colourEnabled({ env: { NO_COLOR: '' }, isTty: true })).toBe(true);
    expect(colourEnabled({ env: { TERM: 'dumb' }, isTty: true })).toBe(false);
    expect(colourEnabled({ env: {}, isTty: true }, true)).toBe(false);
    expect(paint(true, 'red', 'x')).toBe('\u001b[31mx\u001b[0m');
    expect(paint(false, 'red', 'x')).toBe('x');
  });

  it('overdue deadlines are red on a terminal, plain with NO_COLOR', async () => {
    await cli(['create', '--title', 'X', '--service', 'other']);
    await cli(['aware', 'INC-2026-0001', '--at', '2026-01-08T09:00']);
    const red = await cli(['deadlines'], {}, { isTty: true });
    expect(red.out).toContain('\u001b[31m');
    const plain = await cli(['deadlines'], { NO_COLOR: '1' }, { isTty: true });
    expect(plain.out).not.toContain('\u001b[');
    expect(plain.out).toContain('OVERDUE');
  });

  it('a report printed to a terminal cannot carry carriage returns from stored text', async () => {
    await cli(['create', '--title', 'X', '--service', 'other']);
    expect((await cli(['set', 'INC-2026-0001', 'description', 'Real text\rFAKE'])).code).toBe(0);
    const tty = await cli(['report', 'INC-2026-0001', 'final-report'], {}, { isTty: true });
    expect(tty.out).not.toContain('\r');
    expect(tty.out).toContain('Real textFAKE');
    const piped = await cli(['report', 'INC-2026-0001', 'final-report', '--format', 'json']);
    expect(piped.out).toContain('Real text\\rFAKE'); // exact content when not on a terminal (JSON-escaped)
  });

  it('strips control characters from text bound for the terminal', () => {
    expect(term('a\u001b[2Jb\u0007c\u202Ed\ne')).toBe('a[2Jbcd\ne'); // ESC removed, so the rest is inert text
  });
});

describe('README quick start', () => {
  /** The `tocsin …` lines of the README's first sh block, split like a shell would (double quotes only). */
  async function quickStart(): Promise<string[][]> {
    const readme = await readFile(new URL('../README.md', import.meta.url), 'utf8');
    const block = /## Quick start[\s\S]*?```sh\n([\s\S]*?)```/u.exec(readme)?.[1] ?? '';
    return block
      .split('\n')
      .map((l) => l.replace(/\s+#.*$/u, '').trim())
      .filter((l) => l.startsWith('tocsin '))
      .map((l) => [...l.matchAll(/"([^"]*)"|(\S+)/gu)].map((m) => m[1] ?? m[2] ?? '').slice(1));
  }

  it('every command of the quick start succeeds as written', async () => {
    const commands = await quickStart();
    expect(commands.map((c) => c[0])).toEqual(['init', 'create', 'assess', 'aware', 'deadlines', 'set', 'set', 'report', 'submit']);
    const env = { TOCSIN_STORE: join(dir, 'qs.tocsin'), TOCSIN_CONFIG: join(dir, 'qs.json') };
    for (const args of commands) {
      // Keep written files inside the temporary directory.
      const fixed = args.map((a, i) => (args[i - 1] === '--out' ? join(dir, a) : a));
      const r = await cli(fixed, env);
      expect(r.code, `tocsin ${args.join(' ')}: ${r.err}`).toBe(0);
    }
    expect(await readFile(join(dir, 'early-warning.html'), 'utf8')).toContain('<h1>Early warning: Storage cluster outage</h1>');
  });
});
