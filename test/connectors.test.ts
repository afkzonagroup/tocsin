// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { importTimestamp, MAX_IMPORT_BYTES, parseImport } from '../src/connectors/importers.js';
import { planNotifications, plainForChat } from '../src/connectors/notify.js';
import { isBlockedAddress, resolveSafeTarget } from '../src/connectors/ssrf.js';
import { deliverWebhook, escapeSlack, nodeTransport, sendWebhook, signBody, slackBody, teamsBody, verifySignature, type TransportRequest, type WebhookMessage } from '../src/connectors/webhook.js';
import type { TocsinConfig, WebhookConfig } from '../src/model/config.js';
import { validateConfig } from '../src/model/config.js';
import { emptyData } from '../src/store/store.js';
import { TocsinError } from '../src/util/errors.js';
import { CFG, incident, sub } from './helpers.js';

const publicResolver = (addr: string) => (): Promise<{ address: string; family: number }[]> => Promise.resolve([{ address: addr, family: addr.includes(':') ? 6 : 4 }]);

describe('SSRF address policy', () => {
  it.each([
    '127.0.0.1',
    '127.255.255.254',
    '10.1.2.3',
    '172.16.0.1',
    '172.31.255.255',
    '192.168.1.1',
    '169.254.169.254', // cloud metadata
    '100.64.0.1', // CGNAT
    '0.0.0.0',
    '224.0.0.1',
    '255.255.255.255',
    '198.18.0.1',
    '::1',
    '::',
    'fe80::1',
    'fc00::1',
    'fd00:ec2::254', // AWS metadata over IPv6
    'ff02::1',
    '::ffff:127.0.0.1',
    '::ffff:7f00:1',
    '::ffff:169.254.169.254',
    '64:ff9b::a9fe:a9fe',
    '2002:7f00:1::1',
    '2001:db8::1',
    '::7f00:1', // IPv4-compatible 127.0.0.1
    '::a9fe:a9fe', // IPv4-compatible 169.254.169.254
    '::ffff:0:7f00:1', // IPv4-translated (SIIT)
    '4000::1', // outside global unicast 2000::/3
    'not-an-ip',
  ])('blocks %s', (ip) => {
    expect(isBlockedAddress(ip)).toBe(true);
  });

  it.each(['93.184.216.34', '1.1.1.1', '172.32.0.1', '100.128.0.1', '2606:4700:4700::1111', '::ffff:93.184.216.34'])('allows public %s', (ip) => {
    expect(isBlockedAddress(ip)).toBe(false);
  });
});

describe('resolveSafeTarget', () => {
  const code = async (p: Promise<unknown>): Promise<string> => {
    try {
      await p;
      return 'ok';
    } catch (e) {
      return e instanceof TocsinError ? e.code : 'other';
    }
  };

  it('only https, no credentials, default port, public names', async () => {
    expect(await code(resolveSafeTarget('http://hooks.example.com/x', { resolver: publicResolver('93.184.216.34') }))).toBe('SSRF_BLOCKED');
    expect(await code(resolveSafeTarget('https://u:p@hooks.example.com/x', { resolver: publicResolver('93.184.216.34') }))).toBe('SSRF_BLOCKED');
    expect(await code(resolveSafeTarget('https://hooks.example.com:8443/x', { resolver: publicResolver('93.184.216.34') }))).toBe('SSRF_BLOCKED');
    expect(await code(resolveSafeTarget('https://localhost/x'))).toBe('SSRF_BLOCKED');
    expect(await code(resolveSafeTarget('https://intranet/x'))).toBe('SSRF_BLOCKED');
    expect(await code(resolveSafeTarget('file:///etc/passwd'))).toBe('SSRF_BLOCKED');
    expect(await code(resolveSafeTarget('https://[::1]/x'))).toBe('SSRF_BLOCKED');
    expect(await code(resolveSafeTarget('https://169.254.169.254/latest/meta-data'))).toBe('SSRF_BLOCKED');
    expect(await code(resolveSafeTarget('https://2130706433/x'))).toBe('SSRF_BLOCKED'); // decimal 127.0.0.1, normalised by URL
  });

  it('blocks names resolving to private addresses, also when mixed with public ones', async () => {
    expect(await code(resolveSafeTarget('https://rebind.example.com/', { resolver: publicResolver('10.0.0.5') }))).toBe('SSRF_BLOCKED');
    const mixed = (): Promise<{ address: string; family: number }[]> =>
      Promise.resolve([
        { address: '93.184.216.34', family: 4 },
        { address: '127.0.0.1', family: 4 },
      ]);
    expect(await code(resolveSafeTarget('https://mixed.example.com/', { resolver: mixed }))).toBe('SSRF_BLOCKED');
  });

  it('pins the checked address and honours the host allow-list', async () => {
    const t = await resolveSafeTarget('https://hooks.slack.com/services/x', { resolver: publicResolver('93.184.216.34'), allowedHosts: ['hooks.slack.com'] });
    expect(t.address).toBe('93.184.216.34');
    expect(await code(resolveSafeTarget('https://evil.example.com/', { resolver: publicResolver('93.184.216.34'), allowedHosts: ['hooks.slack.com'] }))).toBe('SSRF_BLOCKED');
  });
});

describe('webhook payloads and signing', () => {
  const msg: WebhookMessage = { event: 'deadline-overdue', incidentId: 'INC-2026-0001', stage: 'early-warning', stageLabel: 'Early warning', state: 'overdue', text: 'a <b> & c' };

  it('Slack text is escaped; Teams uses an Adaptive Card message', () => {
    expect(escapeSlack('<!channel> & <x>')).toBe('&lt;!channel&gt; &amp; &lt;x&gt;');
    expect(JSON.parse(slackBody(msg))).toEqual({ text: 'a &lt;b&gt; &amp; c' });
    const teams = JSON.parse(teamsBody(msg)) as { type: string; attachments: { contentType: string; content: { type: string } }[] };
    expect(teams.type).toBe('message');
    expect(teams.attachments[0]?.contentType).toBe('application/vnd.microsoft.card.adaptive');
    expect(teams.attachments[0]?.content.type).toBe('AdaptiveCard');
  });

  it('signatures verify, and fail for a changed body, a wrong secret or an old timestamp', () => {
    const secret = 's'.repeat(40);
    const sig = signBody(secret, 1_000_000, '{"a":1}');
    expect(verifySignature(secret, '1000000', '{"a":1}', sig, 1_000_100)).toBe(true);
    expect(verifySignature(secret, '1000000', '{"a":2}', sig, 1_000_100)).toBe(false);
    expect(verifySignature('t'.repeat(40), '1000000', '{"a":1}', sig, 1_000_100)).toBe(false);
    expect(verifySignature(secret, '1000000', '{"a":1}', sig, 1_000_301)).toBe(false);
    expect(verifySignature(secret, undefined, '{"a":1}', sig)).toBe(false);
    expect(verifySignature(secret, '1e6', '{"a":1}', sig)).toBe(false);
  });

  const generic: WebhookConfig = { id: 'ops', kind: 'generic', urlEnv: 'HOOK_URL', secretEnv: 'HOOK_SECRET', events: ['deadline-overdue'] };

  it('sends a signed generic request through the transport; secrets come from the environment', async () => {
    let seen: TransportRequest | undefined;
    await sendWebhook(generic, msg, { HOOK_URL: 'https://hooks.example.com/in', HOOK_SECRET: 'k'.repeat(32) }, {
      resolver: publicResolver('93.184.216.34'),
      now: () => 1_000_000_000,
      transport: (r) => {
        seen = r;
        return Promise.resolve({ status: 204 });
      },
    });
    expect(seen?.target.address).toBe('93.184.216.34');
    expect(seen?.headers['x-tocsin-signature']).toBe(signBody('k'.repeat(32), 1_000_000, seen?.body ?? ''));
    expect(seen?.headers['cookie']).toBeUndefined();
    expect(seen?.headers['authorization']).toBeUndefined();
  });

  it('refuses missing URL or weak secret, redirects and errors', async () => {
    const env = { HOOK_URL: 'https://hooks.example.com/in', HOOK_SECRET: 'k'.repeat(32) };
    const opts = (status: number) => ({ resolver: publicResolver('93.184.216.34'), transport: () => Promise.resolve({ status }) });
    await expect(sendWebhook(generic, msg, {}, opts(200))).rejects.toThrow(/HOOK_URL/u);
    await expect(sendWebhook(generic, msg, { ...env, HOOK_SECRET: 'short' }, opts(200))).rejects.toThrow(/at least 32/u);
    await expect(sendWebhook(generic, msg, env, opts(302))).rejects.toThrow(/redirect/u);
    await expect(sendWebhook(generic, msg, env, opts(500))).rejects.toThrow(/HTTP 500/u);
    await expect(sendWebhook(generic, msg, { ...env, HOOK_URL: 'https://10.0.0.1/x' }, opts(200))).rejects.toThrow(/private/u);
  });

  describe('delivery with retries', () => {
    const env = { HOOK_URL: 'https://hooks.example.com/in', HOOK_SECRET: 'k'.repeat(32) };
    const run = (statuses: (number | 'timeout')[], attempts?: number) => {
      const seen: TransportRequest[] = [];
      const delays: number[] = [];
      const queue = [...statuses];
      const p = deliverWebhook(generic, msg, env, {
        resolver: publicResolver('93.184.216.34'),
        ...(attempts === undefined ? {} : { attempts }),
        sleep: (ms) => {
          delays.push(ms);
          return Promise.resolve();
        },
        random: () => 0.5,
        transport: (r) => {
          seen.push(r);
          const next = queue.shift() ?? 200;
          if (next === 'timeout') return Promise.reject(new TocsinError('NETWORK', 'Webhook request failed (timeout).', { retryable: true }));
          return Promise.resolve({ status: next });
        },
      });
      return { p, seen, delays };
    };

    it('retries 5xx, 429 and timeouts with growing delays and one delivery id', async () => {
      const r = run([503, 'timeout', 204]);
      await expect(r.p).resolves.toEqual({ attempts: 3 });
      expect(r.delays).toEqual([750, 1500]);
      const ids = new Set(r.seen.map((x) => x.headers['x-tocsin-delivery']));
      expect(ids.size).toBe(1);
    });

    it('does not retry other client errors, redirects or blocked destinations', async () => {
      const r400 = run([400]);
      await expect(r400.p).rejects.toThrow(/HTTP 400/u);
      expect(r400.seen).toHaveLength(1);
      const r302 = run([302]);
      await expect(r302.p).rejects.toThrow(/redirect/u);
      expect(r302.seen).toHaveLength(1);
      await expect(deliverWebhook(generic, msg, { ...env, HOOK_URL: 'https://10.0.0.1/x' }, { sleep: () => Promise.resolve() })).rejects.toThrow(/private/u);
    });

    it('gives up after the configured number of attempts', async () => {
      const r = run([500, 500, 500, 500], 2);
      await expect(r.p).rejects.toThrow(/HTTP 500/u);
      expect(r.seen).toHaveLength(2);
      await expect(deliverWebhook(generic, msg, env, { attempts: 9 })).rejects.toThrow(/between 1 and 5/u);
    });
  });

  describe('node transport against a local server', () => {
    let server: Server | undefined;
    afterEach(async () => {
      await new Promise<void>((r) => (server === undefined ? r() : server.close(() => r())));
    });

    it('connects to the pinned address, posts the body and does not follow redirects', async () => {
      const hits: { host: string | undefined; body: string; url: string | undefined }[] = [];
      server = createServer((req, res) => {
        let body = '';
        req.on('data', (c: Buffer) => (body += c.toString()));
        req.on('end', () => {
          hits.push({ host: req.headers.host, body, url: req.url });
          if (req.url === '/redirect') {
            res.writeHead(302, { location: 'http://169.254.169.254/' });
            res.end();
          } else {
            res.writeHead(200);
            res.end('x'.repeat(100_000)); // larger than the response cap; must not hang
          }
        });
      });
      await new Promise<void>((r) => server?.listen(0, '127.0.0.1', () => r()));
      const port = (server.address() as AddressInfo).port;
      const resolver = publicResolver('127.0.0.1');
      const opts = { resolver, allowHttp: true, isBlocked: () => false, transport: nodeTransport };
      const slack: WebhookConfig = { id: 's', kind: 'slack', urlEnv: 'U', events: ['deadline-overdue'] };
      // The name does not resolve in DNS; only the pinned address makes this work.
      await sendWebhook(slack, msg, { U: `http://hooks.invalid-test.example:${port}/ok` }, opts);
      expect(hits[0]?.host).toBe(`hooks.invalid-test.example:${port}`);
      expect(JSON.parse(hits[0]?.body ?? '{}')).toEqual({ text: 'a &lt;b&gt; &amp; c' });
      await expect(sendWebhook(slack, msg, { U: `http://hooks.invalid-test.example:${port}/redirect` }, opts)).rejects.toThrow(/redirect/u);
      expect(hits.map((h) => h.url)).toEqual(['/ok', '/redirect']);
    });

    it('times out', async () => {
      server = createServer(() => undefined); // never answers
      await new Promise<void>((r) => server?.listen(0, '127.0.0.1', () => r()));
      const port = (server.address() as AddressInfo).port;
      const slack: WebhookConfig = { id: 's', kind: 'slack', urlEnv: 'U', events: ['deadline-overdue'] };
      await expect(
        sendWebhook(slack, msg, { U: `http://hooks.example.com:${port}/` }, { resolver: publicResolver('127.0.0.1'), allowHttp: true, isBlocked: () => false, timeoutMs: 200 }),
      ).rejects.toThrow(/timeout/u);
      server.closeAllConnections();
    });
  });
});

describe('notification planning', () => {
  const cfg: TocsinConfig = { ...CFG, webhooks: [{ id: 'chat', kind: 'slack', urlEnv: 'U', events: ['deadline-due-soon', 'deadline-overdue', 'stage-submitted'] }] };
  const aware = '2026-01-10T08:00:00.000Z';

  it('plans due-soon and overdue messages without titles by default, deduplicated', () => {
    const data = { ...emptyData(aware), incidents: [incident({ awareAt: aware, title: 'Secret project <x>' })] };
    const soon = planNotifications(data, cfg, Date.parse('2026-01-11T03:00:00.000Z')); // early warning in 5 h
    expect(soon.map((n) => [n.message.event, n.message.stage])).toEqual([['deadline-due-soon', 'early-warning']]);
    expect(soon[0]?.message.text).not.toContain('Secret');
    const later = planNotifications(data, cfg, Date.parse('2026-01-11T09:00:00.000Z'));
    expect(later.map((n) => n.message.event)).toEqual(['deadline-overdue']);
    const dedup = planNotifications({ ...data, meta: { ...data.meta, notified: later.map((n) => n.key) } }, cfg, Date.parse('2026-01-11T10:00:00.000Z'));
    expect(dedup).toEqual([]);
  });

  it('includes a sanitised title only when configured; announces recent submissions', () => {
    const withTitle: TocsinConfig = { ...cfg, webhooks: [{ id: 'chat', kind: 'slack', urlEnv: 'U', events: ['stage-submitted'], includeTitle: true }] };
    const data = { ...emptyData(aware), incidents: [incident({ awareAt: aware, title: 'DB [click](http://x) @here', submissions: [sub('early-warning', '2026-01-10T09:00:00.000Z')] })] };
    const plan = planNotifications(data, withTitle, Date.parse('2026-01-10T10:00:00.000Z'));
    expect(plan).toHaveLength(1);
    expect(plan[0]?.message.title).toBe('DB click http://x here');
    expect(plainForChat('<!channel> *x*')).toBe('channel x');
  });
});

describe('importers (documented formats only)', () => {
  it('PagerDuty single and list responses', () => {
    const one = parseImport('pagerduty', JSON.stringify({ incident: { id: 'Q1', incident_number: 12, title: 'API errors', created_at: '2026-01-02T03:04:05Z', status: 'triggered', urgency: 'high', service: { summary: 'API' } } }), ['cloud']);
    expect(one).toEqual([
      { title: 'API errors', serviceTypes: ['cloud'], detectedAt: '2026-01-02T03:04:05.000Z', details: { summary: 'Imported from PagerDuty (status triggered, urgency high, service API). Created there 2026-01-02T03:04:05Z.', internalReference: 'PagerDuty #12' } },
    ]);
    const many = parseImport('pagerduty', JSON.stringify({ incidents: [{ title: 'a' }, { summary: 'b' }], limit: 25, more: false }), ['cdn']);
    expect(many.map((x) => x.title)).toEqual(['a', 'b']);
  });

  it('incident.io v2 incidents with microsecond timestamps', () => {
    const r = parseImport('incident-io', JSON.stringify({ incidents: [{ id: '01F', name: 'Our database is sad', reference: 'INC-123', summary: 'Sad.', created_at: '2021-08-17T13:28:57.801578Z', severity: { name: 'Minor' }, incident_status: { name: 'Closed' } }] }), ['other']);
    expect(r[0]?.detectedAt).toBe('2021-08-17T13:28:57.801Z');
    expect(r[0]?.details?.internalReference).toBe('incident.io INC-123');
    expect(r[0]?.details?.summary).toBe('Imported from incident.io (severity Minor, status Closed). Sad.');
  });

  it('MISP events: only actionable (to_ids), non-deleted attributes become IoCs', () => {
    const ev = {
      Event: {
        uuid: '57f4f6d9-cd20-458b-84fd-109ec0a83869',
        info: 'Phishing wave',
        date: '2026-01-05',
        Attribute: [
          { type: 'ip-dst', value: '203.0.113.7', to_ids: true, deleted: false },
          { type: 'comment', value: 'context', to_ids: false, deleted: false },
          { type: 'domain', value: 'old.example', to_ids: true, deleted: true },
        ],
      },
    };
    const r = parseImport('misp', JSON.stringify(ev), ['other']);
    expect(r[0]?.title).toBe('Phishing wave');
    expect(r[0]?.details?.indicatorsOfCompromise).toEqual(['ip-dst: 203.0.113.7']);
    expect(r[0]?.detectedAt).toBeUndefined();
  });

  it('strips control and bidi characters and caps lengths', () => {
    const r = parseImport('pagerduty', JSON.stringify({ incident: { title: `A\u001b[31mB\u202Ec${'x'.repeat(500)}` } }), ['cloud']);
    expect(r[0]?.title.startsWith('A [31mB c')).toBe(true);
    expect(Array.from(r[0]?.title ?? '').length).toBe(200);
  });

  it('rejects malformed input', () => {
    expect(() => parseImport('pagerduty', 'nope', ['cloud'])).toThrow(/not valid JSON/u);
    expect(() => parseImport('pagerduty', JSON.stringify({ x: 1 }), ['cloud'])).toThrow(/Expected/u);
    expect(() => parseImport('misp', JSON.stringify({ x: 1 }), ['cloud'])).toThrow(/Event/u);
    expect(() => parseImport('incident-io', JSON.stringify({ incidents: [] }), ['cloud'])).toThrow(/No incidents/u);
    expect(() => parseImport('incident-io', JSON.stringify({ incidents: Array(1001).fill({ name: 'x' }) }), ['cloud'])).toThrow(/Too many/u);
    // Over 10 MiB is refused before parsing, even when it is valid JSON.
    const big = JSON.stringify({ incident: { title: 'x', summary: 'y'.repeat(MAX_IMPORT_BYTES) } });
    expect(() => parseImport('pagerduty', big, ['cloud'])).toThrow(/too large/u);
    expect(importTimestamp('2026-01-01')).toBeUndefined();
    expect(importTimestamp('2026-13-01T00:00:00Z')).toBeUndefined();
  });
});

describe('configuration', () => {
  it('validates webhooks: URLs only via environment variable names, generic needs a secret', () => {
    const base = { version: 1, timeZone: 'UTC', entity: { name: 'E' }, authority: { role: 'csirt', name: 'C' } };
    expect(() => validateConfig({ ...base, webhooks: [{ id: 'a', kind: 'generic', urlEnv: 'U', events: ['deadline-overdue'] }] })).toThrow(/secretEnv/u);
    expect(() => validateConfig({ ...base, webhooks: [{ id: 'a', kind: 'slack', url: 'https://x', urlEnv: 'U', events: ['deadline-overdue'] }] })).toThrow(/unknown field/u);
    expect(() => validateConfig({ ...base, webhooks: [{ id: 'a', kind: 'slack', urlEnv: 'lower', events: ['deadline-overdue'] }] })).toThrow();
    expect(() => validateConfig({ ...base, authority: { role: 'csirt', name: 'C', url: 'http://insecure.example' } })).toThrow(/https/u);
    expect(() => validateConfig({ ...base, __proto__: { polluted: true } })).toThrow(/must be an object/u); // non-plain prototype
    expect(() => validateConfig(JSON.parse(`{"version":1,"timeZone":"UTC","entity":{"name":"E"},"authority":{"role":"csirt","name":"C"},"__proto__":{"x":1}}`))).toThrow(/unknown field/u);
    expect(({} as Record<string, unknown>)['x']).toBeUndefined();
    expect(() => validateConfig({ ...base, extra: 1 })).toThrow(/unknown field/u);
    expect(() => validateConfig({ ...base, webhooks: [{ id: 'a', kind: 'slack', urlEnv: 'TOCSIN_KEY', events: ['deadline-overdue'] }] })).toThrow(/holds a Tocsin key/u);
    expect(() => validateConfig({ ...base, webhooks: [{ id: 'a', kind: 'generic', urlEnv: 'U', secretEnv: 'TOCSIN_PASSPHRASE', events: ['deadline-overdue'] }] })).toThrow(/holds a Tocsin key/u);
    expect(validateConfig({ ...base, turnover: { financialYear: '2025', amountCents: 123 } }).turnover?.amountCents).toBe(123);
  });
});
