// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { request } from 'node:http';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createIncident, initStore } from '../src/registry/ops.js';
import { EncryptedStore, emptyData } from '../src/store/store.js';
import { fixedWindowLimiter, SECURITY_HEADERS, startUi, type UiHandle } from '../src/ui/server.js';
import { CFG, RAW_KEY, tempDir } from './helpers.js';

interface Res {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

let ui: UiHandle;
let store: EncryptedStore;
let cleanup: () => Promise<void>;
let port: number;
let clock = Date.UTC(2026, 0, 10, 8);
const TOKEN = 'T'.repeat(43);

function http(method: string, path: string, opts: { headers?: Record<string, string>; body?: string } = {}): Promise<Res> {
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, method, path, headers: { host: `127.0.0.1:${port}`, ...opts.headers } }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (c: string) => (body += c));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body }));
    });
    req.on('error', reject);
    if (opts.body !== undefined) req.write(opts.body);
    req.end();
  });
}

async function login(): Promise<{ cookie: string; csrf: string }> {
  const r = await http('GET', `/login?token=${TOKEN}`);
  expect(r.status).toBe(303);
  const set = String(r.headers['set-cookie']);
  const cookie = /tocsin_session=([^;]+)/u.exec(set)?.[1] ?? '';
  const home = await http('GET', '/', { headers: { cookie: `tocsin_session=${cookie}` } });
  const csrf = /name="_csrf" value="([^"]+)"/u.exec(home.body)?.[1] ?? '';
  return { cookie: `tocsin_session=${cookie}`, csrf };
}

function form(fields: Record<string, string | string[]>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(fields)) for (const x of Array.isArray(v) ? v : [v]) p.append(k, x);
  return p.toString();
}

function post(path: string, cookie: string, body: string, headers: Record<string, string> = {}): Promise<Res> {
  return http('POST', path, {
    headers: { cookie, origin: `http://127.0.0.1:${port}`, 'content-type': 'application/x-www-form-urlencoded', ...headers },
    body,
  });
}

beforeEach(async () => {
  const t = await tempDir();
  cleanup = t.cleanup;
  clock = Date.UTC(2026, 0, 10, 8);
  const ctx = { now: clock, actor: 't' };
  const data = createIncident(initStore(emptyData('2026-01-10T08:00:00.000Z'), ctx), { title: '<script>alert(1)</script>', serviceTypes: ['cloud'] }, ctx).data;
  store = await EncryptedStore.create(join(t.dir, 's.tocsin'), RAW_KEY, data);
  ui = await startUi({ store, config: CFG, host: '127.0.0.1', port: 0, actor: 'ui-test', loginToken: TOKEN, now: () => clock, rateLimiter: fixedWindowLimiter(1000) });
  port = Number(new URL(ui.origin).port);
});

afterEach(async () => {
  await ui.close();
  store.close();
  await cleanup();
});

describe('session token', () => {
  it('everything except the stylesheet needs a session', async () => {
    expect((await http('GET', '/')).status).toBe(401);
    expect((await http('GET', '/incidents/INC-2026-0001')).status).toBe(401);
    expect((await http('GET', '/static/app.css')).status).toBe(200);
  });

  it('the login token is checked and works once', async () => {
    expect((await http('GET', '/login?token=wrong')).status).toBe(403);
    expect((await http('GET', '/login')).status).toBe(403);
    await login();
    expect((await http('GET', `/login?token=${TOKEN}`)).status).toBe(403);
  });

  it('the session cookie is HttpOnly and SameSite=Strict', async () => {
    const r = await http('GET', `/login?token=${TOKEN}`);
    expect(String(r.headers['set-cookie'])).toMatch(/HttpOnly; SameSite=Strict; Path=\//u);
  });

  it('forged or expired session cookies are refused', async () => {
    const { cookie } = await login();
    expect((await http('GET', '/', { headers: { cookie: `tocsin_session=${'A'.repeat(43)}` } })).status).toBe(401);
    clock += 8 * 3_600_000 + 1;
    expect((await http('GET', '/', { headers: { cookie } })).status).toBe(401);
  });

  it('logout ends the session', async () => {
    const { cookie, csrf } = await login();
    expect((await post('/logout', cookie, form({ _csrf: csrf }))).status).toBe(303);
    expect((await http('GET', '/', { headers: { cookie } })).status).toBe(401);
  });
});

describe('CSRF and request checks', () => {
  it('accepts a correct same-origin form post', async () => {
    const { cookie, csrf } = await login();
    const r = await post('/incidents', cookie, form({ _csrf: csrf, title: 'From UI', serviceTypes: ['dns', 'cdn'] }));
    expect(r.status).toBe(303);
    expect(r.headers['location']).toBe('/incidents/INC-2026-0002');
    expect((await store.refresh()).incidents[1]?.serviceTypes).toEqual(['dns', 'cdn']);
  });

  it('rejects a missing or wrong CSRF token', async () => {
    const { cookie } = await login();
    expect((await post('/incidents', cookie, form({ title: 'x', serviceTypes: 'dns' }))).status).toBe(403);
    expect((await post('/incidents', cookie, form({ _csrf: 'nope', title: 'x', serviceTypes: 'dns' }))).status).toBe(403);
    expect((await store.refresh()).incidents).toHaveLength(1);
  });

  it('rejects a missing or foreign Origin and cross-site fetch metadata', async () => {
    const { cookie, csrf } = await login();
    const body = form({ _csrf: csrf, title: 'x', serviceTypes: 'dns' });
    expect((await post('/incidents', cookie, body, { origin: 'http://evil.example' })).status).toBe(403);
    expect((await post('/incidents', cookie, body, { origin: 'null' })).status).toBe(403);
    expect((await post('/incidents', cookie, body, { 'sec-fetch-site': 'cross-site' })).status).toBe(403);
    const noOrigin = await http('POST', '/incidents', { headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' }, body });
    expect(noOrigin.status).toBe(403);
  });

  it('rejects other content types, oversize bodies and unknown methods', async () => {
    const { cookie, csrf } = await login();
    expect((await post('/incidents', cookie, JSON.stringify({ _csrf: csrf }), { 'content-type': 'application/json' })).status).toBe(415);
    expect((await post('/incidents', cookie, `_csrf=${csrf}&title=${'x'.repeat(70_000)}`)).status).toBe(413);
    expect((await http('PUT', '/', { headers: { cookie } })).status).toBe(405);
    expect((await http('DELETE', '/', { headers: { cookie } })).status).toBe(405);
  });

  it('rejects unknown Host headers (DNS rebinding)', async () => {
    const { cookie } = await login();
    expect((await http('GET', '/', { headers: { cookie, host: 'attacker.example' } })).status).toBe(421);
    expect((await http('GET', '/', { headers: { cookie, host: `localhost:${port}` } })).status).toBe(200);
  });

  it('rate-limits', async () => {
    await ui.close();
    ui = await startUi({ store, config: CFG, host: '127.0.0.1', port: 0, actor: 'x', loginToken: TOKEN, now: () => clock, rateLimiter: fixedWindowLimiter(3) });
    port = Number(new URL(ui.origin).port);
    const codes: number[] = [];
    for (let i = 0; i < 5; i++) codes.push((await http('GET', '/static/app.css')).status);
    expect(codes).toEqual([200, 200, 200, 429, 429]);
  });
});

describe('responses', () => {
  it('every response carries the security headers and a script-free CSP', async () => {
    for (const path of ['/', '/static/app.css', '/nope']) {
      const r = await http('GET', path);
      for (const [k, v] of Object.entries(SECURITY_HEADERS)) expect(r.headers[k], `${path} ${k}`).toBe(v);
      // Literal values, so removing a header or directive from SECURITY_HEADERS fails here too.
      expect(r.headers['x-content-type-options']).toBe('nosniff');
      expect(r.headers['x-frame-options']).toBe('DENY');
      expect(r.headers['referrer-policy']).toBe('no-referrer');
      expect(r.headers['cache-control']).toBe('no-store');
      expect(r.headers['cross-origin-opener-policy']).toBe('same-origin');
      expect(r.headers['content-security-policy']).toBe("default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    }
    expect(SECURITY_HEADERS['content-security-policy']).not.toMatch(/script-src|unsafe/u);
  });

  it('escapes user data in pages', async () => {
    const { cookie } = await login();
    const home = await http('GET', '/', { headers: { cookie } });
    expect(home.body).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(home.body).not.toContain('<script>');
    const page = await http('GET', '/incidents/INC-2026-0001', { headers: { cookie } });
    expect(page.status).toBe(200);
    expect(page.body).not.toContain('<script>');
  });

  it('shows validation errors without stack traces', async () => {
    const { cookie, csrf } = await login();
    const r = await post('/incidents/INC-2026-0001/aware', cookie, form({ _csrf: csrf, at: '2026-02-30T10:00' }));
    expect(r.status).toBe(422);
    expect(r.body).toMatch(/not a valid calendar date/u);
    expect(r.body).not.toMatch(/at .*\.ts:\d+/u);
  });

  it('records awareness, answers and a submission through forms', async () => {
    const { cookie, csrf } = await login();
    expect((await post('/incidents/INC-2026-0001/aware', cookie, form({ _csrf: csrf, at: '2026-01-10T09:00' }))).status).toBe(303);
    expect((await post('/incidents/INC-2026-0001/assess', cookie, form({ _csrf: csrf, 'a:services.cloud.completeUnavailabilitySeconds': '2h' }))).status).toBe(303);
    expect((await post('/incidents/INC-2026-0001/details', cookie, form({ _csrf: csrf, suspectedUnlawfulOrMalicious: 'no', crossBorderImpact: 'unknown', severity: '' }))).status).toBe(303);
    expect((await post('/incidents/INC-2026-0001/submit', cookie, form({ _csrf: csrf, stage: 'early-warning', at: 'now' }))).status).toBe(303);
    const inc = (await store.refresh()).incidents[0];
    expect(inc?.assessment?.outcome).toBe('significant');
    expect(inc?.submissions.map((s) => s.stage)).toEqual(['early-warning']);
    const html = await http('GET', '/incidents/INC-2026-0001/report/early-warning?format=html', { headers: { cookie } });
    expect(html.headers['content-security-policy']).toMatch(/default-src 'none'; style-src 'sha256-/u);
    const md = await http('GET', '/incidents/INC-2026-0001/report/early-warning?format=md', { headers: { cookie } });
    expect(md.headers['content-disposition']).toBe('attachment; filename="INC-2026-0001-early-warning.md"');
  });

  it('unknown ids and paths are 404', async () => {
    const { cookie } = await login();
    expect((await http('GET', '/incidents/INC-2026-9999', { headers: { cookie } })).status).toBe(404);
    expect((await http('GET', '/incidents/..%2f..%2fetc', { headers: { cookie } })).status).toBe(404);
    expect((await http('GET', '/incidents/INC-2026-0001/report/early-warning?format=exe', { headers: { cookie } })).status).toBe(422);
  });

  it('about page and footer carry the attribution and source link', async () => {
    const { cookie } = await login();
    const r = await http('GET', '/about', { headers: { cookie } });
    expect(r.body).toContain('Tocsin by AFKzona Group');
    expect(r.body).toContain('Source code');
  });
});

describe('pages', () => {
  it('renders every page through a full lifecycle', async () => {
    const { cookie, csrf } = await login();
    const ok = async (path: string, fields: Record<string, string | string[]>): Promise<void> => {
      const r = await post(path, cookie, form({ _csrf: csrf, ...fields }));
      expect(r.status, `${path}: ${r.body.slice(0, 300)}`).toBe(303);
    };
    const I = '/incidents/INC-2026-0001';
    await ok(`${I}/aware`, { at: '2026-01-10T09:00' });
    await ok(`${I}/details`, {
      suspectedUnlawfulOrMalicious: 'yes',
      crossBorderImpact: 'yes',
      affectedMemberStates: 'lv, ee',
      indicatorsOfCompromise: 'ip: 203.0.113.1\r\nhash: abc',
      severity: 'High',
      impact: 'All',
      rootCauseKey: 'phishing',
      recipientsLikelyAffected: 'yes',
    });
    await ok(`${I}/submit`, { stage: 'early-warning', at: 'now' });
    await ok(`${I}/submit`, { stage: 'incident-notification', at: 'now' });
    await ok(`${I}/request`, { at: 'now', requestedBy: 'CSIRT', dueAt: '2026-01-12T10:00' });
    await ok(`${I}/status-update`, { requestId: 'R-1', statusUpdate: 'Contained' });
    await ok(`${I}/submit`, { stage: 'intermediate-report', requestId: 'R-1', at: 'now' });
    await ok(`${I}/recipients`, { kind: 'incident-23-1', at: 'now', audience: 'Customers', summary: 'Notice', measuresOrRemedies: 'Rotate keys' });
    await ok(`${I}/conclude`, { at: 'now' });
    await ok(`${I}/conclude`, { at: '' });
    await ok(`${I}/conclude`, { at: 'now' });
    await ok(`${I}/details`, { description: 'D', threatTypeOrRootCause: 'R', mitigationApplied: 'M', mitigationOngoing: 'None' });
    const page = await http('GET', I, { headers: { cookie } });
    expect(page.body).toContain('Intermediate report R-1');
    expect(page.body).toContain('Customers');
    await ok(`${I}/submit`, { stage: 'final-report', at: 'now' });
    const closed = await http('GET', I, { headers: { cookie } });
    expect(closed.body).toContain('The record is closed');
    const inc = (await store.refresh()).incidents[0];
    expect(inc?.details.affectedMemberStates).toEqual(['LV', 'EE']);
    expect(inc?.details.indicatorsOfCompromise).toEqual(['ip: 203.0.113.1', 'hash: abc']);
    for (const path of ['/', '/new', '/recurring', '/audit', '/about', `${I}/report/intermediate-report?format=md&request=R-1`, `${I}/report/final-report?format=json`]) {
      expect((await http('GET', path, { headers: { cookie } })).status, path).toBe(200);
    }
    const audit = await http('GET', '/audit', { headers: { cookie } });
    expect(audit.body).toContain('Chain intact');
    const bad = await post(`${I}/details`, cookie, form({ _csrf: csrf, severity: 'x' }));
    expect(bad.status).toBe(422);
    expect(bad.body).toMatch(/closed/u);
  });

  it('shows form errors on the page they came from', async () => {
    const { cookie, csrf } = await login();
    const r = await post('/incidents', cookie, form({ _csrf: csrf, title: 'No services' }));
    expect(r.status).toBe(422);
    expect(r.body).toMatch(/Choose at least one service type/u);
    expect((await post('/incidents/INC-2026-0001/unknown', cookie, form({ _csrf: csrf }))).status).toBe(404);
    expect((await post('/nowhere', cookie, form({ _csrf: csrf }))).status).toBe(404);
  });
});

describe('binding', () => {
  it('refuses non-loopback addresses unless explicitly allowed', async () => {
    await expect(startUi({ store, config: CFG, host: '0.0.0.0', port: 0, actor: 'x' })).rejects.toThrow(/loopback/u);
  });

  it('an any-address bind needs explicit allowed hosts, validated, and never accepts 0.0.0.0 as Host', async () => {
    await expect(startUi({ store, config: CFG, host: '0.0.0.0', port: 0, actor: 'x', allowNonLoopback: true })).rejects.toThrow(/allowed-host/u);
    await expect(startUi({ store, config: CFG, host: '127.0.0.1', port: 0, actor: 'x', allowedHosts: ['evil.example/x'] })).rejects.toThrow(/Invalid allowed host/u);
    await expect(startUi({ store, config: CFG, host: '127.0.0.1', port: 0, actor: 'x', allowedHosts: ['0.0.0.0:8080'] })).rejects.toThrow(/Invalid allowed host/u);
    const any = await startUi({ store, config: CFG, host: '0.0.0.0', port: 0, actor: 'x', allowNonLoopback: true, allowedHosts: ['Tocsin.Internal:9000'], loginToken: TOKEN });
    try {
      const p = Number(new URL(any.origin).port);
      expect(any.loginUrl).toBe(`http://tocsin.internal:9000/login?token=${TOKEN}`);
      const get = (host: string): Promise<number> =>
        new Promise((resolve, reject) => {
          const r = request({ host: '127.0.0.1', port: p, path: '/', headers: { host } }, (res) => {
            res.resume();
            resolve(res.statusCode ?? 0);
          });
          r.on('error', reject);
          r.end();
        });
      expect(await get(`0.0.0.0:${p}`)).toBe(421);
      expect(await get('tocsin.internal:9000')).toBe(401);
    } finally {
      await any.close();
    }
  });
});
