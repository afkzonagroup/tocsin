// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { randomBytes } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { applyAnswerText } from '../assess/answers.js';
import { findRecurringIncidents } from '../assess/recurring.js';
import { verifyAudit } from '../audit/chain.js';
import type { TocsinConfig } from '../model/config.js';
import { SERVICE_TYPES, STAGES, type Stage } from '../model/types.js';
import { DETAIL_FIELDS, INCIDENT_ID_RE } from '../model/validate.js';
import {
  addIntermediateRequest,
  addRecipientCommunication,
  assessIncident,
  createIncident,
  findIncident,
  recordAwareness,
  recordHandlingConcluded,
  recordSubmission,
  saveAssessment,
  setStatusUpdate,
  updateDetails,
  type OpContext,
} from '../registry/ops.js';
import { buildReport, type ReportContent } from '../reports/content.js';
import { REPORT_CSP, REPORT_FORMATS, renderReport, validateReportContent, type ReportFormat } from '../reports/render.js';
import { computeDeadlines, pendingDeadlines, submissionOf, type Deadline } from '../stages/deadlines.js';
import { constantTimeEqual } from '../store/crypto.js';
import type { EncryptedStore, StoreData } from '../store/store.js';
import { parseInstant, toIso } from '../time/zone.js';
import { TocsinError, invalid, publicMessage } from '../util/errors.js';
import { oneOf, TRI_VALUES } from '../util/validate.js';
import { aboutPage, auditPage, errorPage, homePage, incidentPage, layout, loginPage, newIncidentPage, recurringPage, type PageCtx } from './pages.js';
import { APP_CSS } from './style.js';

/**
 * Local web UI. Defaults: bound to 127.0.0.1, one-time login token printed on the terminal, session
 * cookie (HttpOnly, SameSite=Strict), per-session CSRF token on every form, Origin and Host checks,
 * strict CSP without any script, body size limit, form content type only, rate limiting.
 */

export const MAX_BODY_BYTES = 64 * 1024;
export const SESSION_IDLE_MS = 8 * 3_600_000;
export const COOKIE = 'tocsin_session';

export const UI_CSP = "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

export const SECURITY_HEADERS: Readonly<Record<string, string>> = {
  'content-security-policy': UI_CSP,
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  // same-origin, not no-referrer: under no-referrer browsers send "Origin: null" on form posts, which the
  // Origin check must refuse. Same-origin still sends no referrer to any other site.
  'referrer-policy': 'same-origin',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
  'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  'cache-control': 'no-store',
};

/** Rate limiter hook: return false to reject the request with 429. */
export type RateLimiter = (clientKey: string, now: number) => boolean;

/** Default: fixed window, 300 requests per minute per client address. */
export function fixedWindowLimiter(limit = 300, windowMs = 60_000): RateLimiter {
  const hits = new Map<string, { start: number; count: number }>();
  return (key, now) => {
    const h = hits.get(key);
    if (h === undefined || now - h.start >= windowMs) {
      if (hits.size > 10_000) hits.clear();
      hits.set(key, { start: now, count: 1 });
      return true;
    }
    h.count++;
    return h.count <= limit;
  };
}

export interface UiOptions {
  readonly store: EncryptedStore;
  readonly config: TocsinConfig;
  readonly configPath?: string;
  readonly host: string;
  readonly port: number;
  /** Required to bind anything other than a loopback address (e.g. inside a container). */
  readonly allowNonLoopback?: boolean;
  /** Extra Host header values accepted (e.g. "tocsin.internal:8080"). */
  readonly allowedHosts?: readonly string[];
  readonly actor: string;
  readonly now?: () => number;
  readonly rateLimiter?: RateLimiter;
  /** Fixed login token (tests only). */
  readonly loginToken?: string;
}

export interface UiHandle {
  readonly server: Server;
  readonly origin: string;
  readonly loginUrl: string;
  readonly closed: Promise<void>;
  close(): Promise<void>;
}

interface Session {
  readonly csrf: string;
  lastSeen: number;
}

const LOOPBACK = new Set(['127.0.0.1', '::1', 'localhost']);
/** "Any address" binds. Never a valid Host header: browsers can reach them as 0.0.0.0, so they are not allowed as one. */
const UNSPECIFIED = new Set(['0.0.0.0', '::', '[::]']);
/** host[:port] as a browser sends it in the Host header: a DNS name or IPv4 address, or a bracketed IPv6 address. */
const HOST_HEADER_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)*|\[[0-9a-f:.]{2,45}\])(?::\d{1,5})?$/u;

function token(): string {
  return randomBytes(32).toString('base64url');
}

class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

function send(res: ServerResponse, status: number, body: string, type = 'text/html; charset=utf-8', extra: Record<string, string> = {}): void {
  res.writeHead(status, { ...SECURITY_HEADERS, 'content-type': type, 'content-length': String(Buffer.byteLength(body)), ...extra });
  res.end(body);
}

function redirect(res: ServerResponse, location: string, extra: Record<string, string> = {}): void {
  res.writeHead(303, { ...SECURITY_HEADERS, location, 'content-length': '0', ...extra });
  res.end();
}

function parseCookies(header: string | undefined): Map<string, string> {
  const m = new Map<string, string>();
  if (header === undefined) return m;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) m.set(part.slice(0, i).trim(), part.slice(i + 1).trim());
  }
  return m;
}

async function readBody(req: IncomingMessage): Promise<string> {
  const len = req.headers['content-length'];
  if (len !== undefined && (!/^\d{1,9}$/u.test(len) || Number(len) > MAX_BODY_BYTES)) throw new HttpError(413, 'Request body too large.');
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const b = chunk as Buffer;
    size += b.length;
    if (size > MAX_BODY_BYTES) throw new HttpError(413, 'Request body too large.');
    chunks.push(b);
  }
  return Buffer.concat(chunks).toString('utf8');
}

/** Form fields; repeated keys collected. At most 300 fields. */
function parseForm(body: string): Map<string, string[]> {
  const params = new URLSearchParams(body);
  const m = new Map<string, string[]>();
  let n = 0;
  for (const [k, v] of params) {
    if (++n > 300) throw new HttpError(413, 'Too many form fields.');
    const list = m.get(k) ?? [];
    list.push(v);
    m.set(k, list);
  }
  return m;
}

function one(form: Map<string, string[]>, key: string): string | undefined {
  return form.get(key)?.[0];
}

function nonEmpty(form: Map<string, string[]>, key: string): string | undefined {
  const v = one(form, key)?.trim();
  return v === undefined || v === '' ? undefined : v;
}

/** Starts the UI server. Resolves once listening. */
export async function startUi(opts: UiOptions): Promise<UiHandle> {
  const host = opts.host;
  if (!LOOPBACK.has(host) && opts.allowNonLoopback !== true) {
    throw new TocsinError('CONFIG', `Refusing to listen on ${host}: only loopback addresses unless --allow-non-loopback is given.`);
  }
  const extraHosts = (opts.allowedHosts ?? []).map((h) => h.toLowerCase());
  for (const h of extraHosts) {
    if (h.length > 260 || !HOST_HEADER_RE.test(h) || UNSPECIFIED.has(h.replace(/:\d+$/u, ''))) throw new TocsinError('CONFIG', `Invalid allowed host "${h.slice(0, 60)}": use host or host:port.`);
  }
  if (UNSPECIFIED.has(host) && extraHosts.length === 0) {
    throw new TocsinError('CONFIG', `Listening on ${host} needs at least one --allowed-host: the host and port users type in the browser.`);
  }
  const now = opts.now ?? Date.now;
  const limiter = opts.rateLimiter ?? fixedWindowLimiter();
  let loginToken: string | undefined = opts.loginToken ?? token();
  const sessions = new Map<string, Session>();
  const cfg = opts.config;
  const store = opts.store;
  let origin = '';
  let allowedHostHeaders = new Set<string>();

  const ctxFor = (s: Session): PageCtx => ({ csrf: s.csrf, cfg, now: now() });
  const op = (): OpContext => ({ now: now(), actor: opts.actor });
  const at = (v: string): string => (v.trim() === 'now' ? toIso(now()) : parseInstant(v, cfg.timeZone));

  const sessionOf = (req: IncomingMessage): { id: string; s: Session } | undefined => {
    const id = parseCookies(req.headers.cookie).get(COOKIE);
    if (id === undefined || !/^[A-Za-z0-9_-]{43}$/u.test(id)) return undefined;
    const s = sessions.get(id);
    if (s === undefined) return undefined;
    if (now() - s.lastSeen > SESSION_IDLE_MS) {
      sessions.delete(id);
      return undefined;
    }
    s.lastSeen = now();
    return { id, s };
  };

  const checkPost = (req: IncomingMessage, form: Map<string, string[]>, s: Session): void => {
    const type = (req.headers['content-type'] ?? '').split(';')[0]?.trim().toLowerCase();
    if (type !== 'application/x-www-form-urlencoded') throw new HttpError(415, 'Unsupported content type.');
    // The Host header was already checked against the allow-list; the Origin must name that same host.
    const hostHeader = (req.headers.host ?? '').toLowerCase();
    const reqOrigin = req.headers.origin;
    const sameOrigin = reqOrigin === `http://${hostHeader}` || (reqOrigin === `https://${hostHeader}` && extraHosts.includes(hostHeader));
    if (reqOrigin === undefined || !sameOrigin) throw new HttpError(403, 'Cross-origin request refused.');
    const site = req.headers['sec-fetch-site'];
    if (site !== undefined && site !== 'same-origin') throw new HttpError(403, 'Cross-site request refused.');
    const sent = one(form, '_csrf') ?? '';
    if (!constantTimeEqual(sent, s.csrf)) throw new HttpError(403, 'The form expired. Reload the page and try again.');
  };

  const pendingRows = (data: StoreData): { inc: StoreData['incidents'][number]; d: Deadline }[] => {
    const rows: { inc: StoreData['incidents'][number]; d: Deadline }[] = [];
    for (const inc of data.incidents) for (const d of pendingDeadlines(computeDeadlines(inc, cfg.timeZone, now()))) rows.push({ inc, d });
    return rows.sort((a, b) => (a.d.dueAt ?? '9999').localeCompare(b.d.dueAt ?? '9999'));
  };

  const incidentView = (data: StoreData, id: string, s: Session, flash?: { kind: 'ok' | 'bad'; text: string }): string => {
    const inc = findIncident(data, id);
    const assessment = assessIncident(data.incidents, inc, cfg);
    return layout(inc.id, incidentPage(ctxFor(s), inc, computeDeadlines(inc, cfg.timeZone, now()), assessment), ctxFor(s), flash);
  };

  const handlePost = async (path: string, form: Map<string, string[]>): Promise<string> => {
    if (path === '/incidents') {
      const services = (form.get('serviceTypes') ?? []).map((t) => oneOf(t, SERVICE_TYPES, 'service type'));
      if (services.length === 0) invalid('Choose at least one service type.');
      const occurred = nonEmpty(form, 'occurredAt');
      const detected = nonEmpty(form, 'detectedAt');
      const inc = await store.transact((d) =>
        createIncident(
          d,
          {
            title: one(form, 'title') ?? '',
            serviceTypes: services,
            ...(occurred === undefined ? {} : { occurredAt: at(occurred) }),
            ...(detected === undefined ? {} : { detectedAt: at(detected) }),
          },
          op(),
        ),
      );
      return `/incidents/${inc.id}`;
    }
    const m = /^\/incidents\/(INC-\d{4}-\d{4,6})\/([a-z-]+)$/u.exec(path);
    if (m === null) throw new HttpError(404, 'Not found.');
    const id = m[1] as string;
    const action = m[2] as string;
    const back = `/incidents/${id}`;
    switch (action) {
      case 'aware': {
        const v = nonEmpty(form, 'at');
        if (v === undefined) invalid('Enter the time.');
        const reason = nonEmpty(form, 'reason');
        await store.transact((d) => recordAwareness(d, id, at(v), op(), reason));
        return back;
      }
      case 'conclude': {
        const v = nonEmpty(form, 'at');
        await store.transact((d) => recordHandlingConcluded(d, id, v === undefined ? null : at(v), op()));
        return back;
      }
      case 'assess': {
        const assignments: [string, string][] = [];
        for (const [k, vals] of form) if (k.startsWith('a:')) assignments.push([k.slice(2), vals[0] ?? '']);
        await store.transact((d) => {
          const inc = findIncident(d, id);
          return saveAssessment(d, id, applyAnswerText(inc.assessment?.answers ?? {}, assignments), cfg, op());
        });
        return back;
      }
      case 'details': {
        const patch: Record<string, unknown> = {};
        for (const key of DETAIL_FIELDS) {
          if (!form.has(key)) continue;
          const raw = (one(form, key) ?? '').replace(/\r\n/gu, '\n');
          const v = raw.trim();
          if (key === 'suspectedUnlawfulOrMalicious' || key === 'crossBorderImpact' || key === 'recipientsLikelyAffected' || key === 'trustServicesImpacted') {
            if (v === '') patch[key] = null;
            else if ((TRI_VALUES as readonly string[]).includes(v)) patch[key] = v;
            else invalid(`${key}: invalid choice.`);
          } else if (key === 'indicatorsOfCompromise') {
            const list = v.split('\n').map((x) => x.trim()).filter((x) => x !== '');
            patch[key] = list.length === 0 ? null : list;
          } else if (key === 'affectedMemberStates') {
            const list = v.split(/[,\s]+/u).map((x) => x.trim().toUpperCase()).filter((x) => x !== '');
            patch[key] = list.length === 0 ? null : list;
          } else patch[key] = v === '' ? null : raw.trim();
        }
        await store.transact((d) => {
          const inc = findIncident(d, id);
          // Only send fields that changed, so the audit log lists real changes.
          const changed: Record<string, unknown> = {};
          for (const [k, v] of Object.entries(patch)) {
            const cur = (inc.details as Record<string, unknown>)[k];
            if (JSON.stringify(cur ?? null) !== JSON.stringify(v)) changed[k] = v;
          }
          if (Object.keys(changed).length === 0) return { data: d, result: inc };
          return updateDetails(d, id, changed, op());
        });
        return back;
      }
      case 'submit': {
        const stage: Stage = oneOf(one(form, 'stage'), STAGES, 'stage');
        const v = nonEmpty(form, 'at');
        if (v === undefined) invalid('Enter the submission time.');
        const requestId = nonEmpty(form, 'requestId');
        const ref = nonEmpty(form, 'authorityReference');
        await store.transact((d) =>
          recordSubmission(
            d,
            id,
            {
              stage,
              submittedAt: at(v),
              ...(stage === 'intermediate-report' && requestId !== undefined ? { requestId } : {}),
              ...(ref === undefined ? {} : { authorityReference: ref }),
              allowIncomplete: one(form, 'allowIncomplete') === '1',
            },
            cfg,
            op(),
          ),
        );
        return back;
      }
      case 'request': {
        const v = nonEmpty(form, 'at');
        if (v === undefined) invalid('Enter when the request was received.');
        const by = nonEmpty(form, 'requestedBy');
        const due = nonEmpty(form, 'dueAt');
        await store.transact((d) => addIntermediateRequest(d, id, { requestedAt: at(v), ...(by === undefined ? {} : { requestedBy: by }), ...(due === undefined ? {} : { dueAt: at(due) }) }, op()));
        return back;
      }
      case 'status-update': {
        const rid = one(form, 'requestId') ?? '';
        await store.transact((d) => setStatusUpdate(d, id, rid, (one(form, 'statusUpdate') ?? '').replace(/\r\n/gu, '\n').trim(), op()));
        return back;
      }
      case 'recipients': {
        const v = nonEmpty(form, 'at');
        if (v === undefined) invalid('Enter when the communication was made.');
        const kind = oneOf(one(form, 'kind'), ['incident-23-1', 'cyber-threat-23-2'] as const, 'kind');
        const measures = nonEmpty(form, 'measuresOrRemedies');
        await store.transact((d) =>
          addRecipientCommunication(
            d,
            id,
            {
              kind,
              communicatedAt: at(v),
              audience: nonEmpty(form, 'audience') ?? '',
              summary: (one(form, 'summary') ?? '').replace(/\r\n/gu, '\n').trim(),
              ...(measures === undefined ? {} : { measuresOrRemedies: measures.replace(/\r\n/gu, '\n') }),
            },
            op(),
          ),
        );
        return back;
      }
      default:
        throw new HttpError(404, 'Not found.');
    }
  };

  const reportResponse = (res: ServerResponse, data: StoreData, id: string, stageText: string, query: URLSearchParams): void => {
    const stage: Stage = oneOf(stageText, STAGES, 'stage');
    const format: ReportFormat = oneOf(query.get('format') ?? 'html', REPORT_FORMATS, 'format');
    const requestId = query.get('request') ?? undefined;
    if (requestId !== undefined && !/^R-\d{1,4}$/u.test(requestId)) invalid('Invalid request id.');
    const inc = findIncident(data, id);
    const submitted = stage === 'intermediate-report' ? inc.intermediateRequests.find((r) => r.id === requestId)?.submission : submissionOf(inc, stage);
    const content: ReportContent = submitted !== undefined ? validateReportContent(submitted.snapshot) : buildReport(inc, stage, cfg, now(), requestId);
    const body = renderReport(content, format);
    const name = `${inc.id}-${stage}${requestId === undefined ? '' : `-${requestId}`}.${format}`;
    if (format === 'html') {
      send(res, 200, body, 'text/html; charset=utf-8', { 'content-security-policy': `${REPORT_CSP}; frame-ancestors 'none'` });
    } else {
      send(res, 200, body, format === 'json' ? 'application/json; charset=utf-8' : 'text/markdown; charset=utf-8', { 'content-disposition': `attachment; filename="${name}"` });
    }
  };

  const handle = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const hostHeader = (req.headers.host ?? '').toLowerCase();
    if (!allowedHostHeaders.has(hostHeader)) throw new HttpError(421, 'Unknown host.');
    if (!limiter(req.socket.remoteAddress ?? 'unknown', now())) throw new HttpError(429, 'Too many requests.');
    const method = req.method ?? 'GET';
    if (method !== 'GET' && method !== 'HEAD' && method !== 'POST') throw new HttpError(405, 'Method not allowed.');
    const url = new URL(req.url ?? '/', origin);
    const path = url.pathname;

    if (path === '/static/app.css' && method !== 'POST') {
      send(res, 200, APP_CSS, 'text/css; charset=utf-8');
      return;
    }
    if (path === '/login' && method === 'GET') {
      const t = url.searchParams.get('token') ?? '';
      if (loginToken === undefined || !constantTimeEqual(t, loginToken)) {
        send(res, 403, layout('Locked', loginPage(), undefined));
        return;
      }
      loginToken = undefined; // one-time
      const id = token();
      sessions.set(id, { csrf: token(), lastSeen: now() });
      redirect(res, '/', { 'set-cookie': `${COOKIE}=${id}; HttpOnly; SameSite=Strict; Path=/` });
      return;
    }
    const sess = sessionOf(req);
    if (sess === undefined) {
      send(res, 401, layout('Locked', loginPage(), undefined));
      return;
    }
    const s = sess.s;

    if (method === 'POST') {
      const form = parseForm(await readBody(req));
      checkPost(req, form, s);
      if (path === '/logout') {
        sessions.delete(sess.id);
        redirect(res, '/login', { 'set-cookie': `${COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0` });
        return;
      }
      try {
        redirect(res, await handlePost(path, form));
      } catch (err) {
        if (err instanceof HttpError) throw err;
        const text = publicMessage(err);
        const m = /^\/incidents\/(INC-\d{4}-\d{4,6})\//u.exec(path);
        const data = await store.refresh();
        if (m !== null && data.incidents.some((i) => i.id === m[1])) send(res, 422, incidentView(data, m[1] as string, s, { kind: 'bad', text }));
        else if (path === '/incidents') send(res, 422, layout('New incident', newIncidentPage(ctxFor(s)), ctxFor(s), { kind: 'bad', text }));
        else send(res, 422, layout('Error', errorPage(text), ctxFor(s)));
      }
      return;
    }

    const data = await store.refresh();
    if (path === '/') {
      send(res, 200, layout('Incidents', homePage(ctxFor(s), data.incidents, pendingRows(data)), ctxFor(s)));
      return;
    }
    if (path === '/new') {
      send(res, 200, layout('New incident', newIncidentPage(ctxFor(s)), ctxFor(s)));
      return;
    }
    if (path === '/recurring') {
      send(res, 200, layout('Recurring incidents', recurringPage(findRecurringIncidents(data.incidents, cfg.turnover?.amountCents, cfg.timeZone)), ctxFor(s)));
      return;
    }
    if (path === '/audit') {
      send(res, 200, layout('Audit log', auditPage(data.audit, verifyAudit(data.audit)), ctxFor(s)));
      return;
    }
    if (path === '/about') {
      send(res, 200, layout('About', aboutPage(ctxFor(s)), ctxFor(s)));
      return;
    }
    const inc = /^\/incidents\/([^/]{1,20})$/u.exec(path);
    if (inc !== null) {
      const id = inc[1] as string;
      if (!INCIDENT_ID_RE.test(id)) throw new HttpError(404, 'Not found.');
      send(res, 200, incidentView(data, id, s));
      return;
    }
    const rep = /^\/incidents\/(INC-\d{4}-\d{4,6})\/report\/([a-z-]{1,30})$/u.exec(path);
    if (rep !== null) {
      reportResponse(res, data, rep[1] as string, rep[2] as string, url.searchParams);
      return;
    }
    throw new HttpError(404, 'Not found.');
  };

  const server = createServer({ requestTimeout: 30_000, headersTimeout: 10_000, maxHeaderSize: 16 * 1024 }, (req, res) => {
    handle(req, res).catch((err: unknown) => {
      if (res.headersSent) {
        res.destroy();
        return;
      }
      if (err instanceof HttpError) send(res, err.status, layout('Error', errorPage(err.message), undefined));
      else if (err instanceof TocsinError) send(res, err.code === 'NOT_FOUND' ? 404 : 422, layout('Error', errorPage(publicMessage(err)), undefined));
      else send(res, 500, layout('Error', errorPage('Unexpected internal error.'), undefined));
    });
  });
  server.keepAliveTimeout = 5_000;

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(opts.port, host, () => {
      server.off('error', reject);
      resolve();
    });
  });
  const addr = server.address() as AddressInfo;
  const hostPart = addr.family === 'IPv6' ? `[${addr.address}]` : addr.address;
  origin = `http://${hostPart}:${addr.port}`;
  allowedHostHeaders = new Set([
    ...(UNSPECIFIED.has(host) ? [] : [`${hostPart}:${addr.port}`]),
    ...(LOOPBACK.has(host) ? [`localhost:${addr.port}`, `127.0.0.1:${addr.port}`, `[::1]:${addr.port}`] : []),
    ...extraHosts,
  ]);
  const closed = new Promise<void>((resolve) => server.once('close', () => { resolve(); }));
  const initialToken = loginToken;
  return {
    server,
    origin,
    // Behind a published container port the bind address (0.0.0.0) is not reachable by name: use the first allowed host.
    loginUrl: `${!LOOPBACK.has(host) && extraHosts.length > 0 ? `http://${extraHosts[0] ?? ''}` : origin}/login?token=${initialToken}`,
    closed,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => { resolve(); });
        server.closeAllConnections();
      }),
  };
}
