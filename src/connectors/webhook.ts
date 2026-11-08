// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { createHmac, randomUUID } from 'node:crypto';
import { request as httpRequest, type IncomingMessage, type RequestOptions } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { isIP, type LookupFunction } from 'node:net';
import type { WebhookConfig, WebhookEvent, WebhookKind } from '../model/config.js';
import { constantTimeEqual } from '../store/crypto.js';
import { TocsinError } from '../util/errors.js';
import { resolveSafeTarget, type GuardOptions, type ResolvedTarget } from './ssrf.js';

/**
 * Outbound webhooks (Slack incoming webhooks, Microsoft Teams workflow webhooks, generic JSON).
 * Only deadline metadata is sent: incident id, stage, due time and state. Titles are left out unless
 * `includeTitle` is set. Nothing is sent unless a webhook is configured and `tocsin notify` runs.
 */

export interface WebhookMessage {
  readonly event: WebhookEvent;
  readonly incidentId: string;
  readonly stage: string;
  readonly stageLabel: string;
  readonly dueAt?: string;
  readonly dueLocal?: string;
  readonly state: string;
  readonly title?: string;
  readonly text: string;
}

/** Slack mrkdwn escaping: &, < and > are control characters (Slack "Formatting text" docs). */
export function escapeSlack(text: string): string {
  return text.replace(/&/gu, '&amp;').replace(/</gu, '&lt;').replace(/>/gu, '&gt;');
}

/** Body for a Slack incoming webhook: `{ "text": … }`. */
export function slackBody(m: WebhookMessage): string {
  return JSON.stringify({ text: escapeSlack(m.text) });
}

/**
 * Body for a Microsoft Teams "workflow" webhook (Power Automate "When a Teams webhook request is
 * received"): a message with one Adaptive Card attachment.
 */
export function teamsBody(m: WebhookMessage): string {
  return JSON.stringify({
    type: 'message',
    attachments: [
      {
        contentType: 'application/vnd.microsoft.card.adaptive',
        contentUrl: null,
        content: {
          $schema: 'http://adaptivecards.io/schemas/adaptive-card.json',
          type: 'AdaptiveCard',
          version: '1.4',
          body: [{ type: 'TextBlock', text: m.text, wrap: true }],
        },
      },
    ],
  });
}

/** Body for a generic receiver. */
export function genericBody(m: WebhookMessage, deliveryId: string): string {
  return JSON.stringify({ source: 'tocsin', version: 1, deliveryId, ...m });
}

export const SIGNATURE_HEADER = 'x-tocsin-signature';
export const TIMESTAMP_HEADER = 'x-tocsin-timestamp';

/** HMAC-SHA256 over `${timestamp}.${body}`, hex, prefixed "sha256=". */
export function signBody(secret: string, timestamp: number, body: string): string {
  return `sha256=${createHmac('sha256', secret).update(`${timestamp}.${body}`, 'utf8').digest('hex')}`;
}

/**
 * Verifies a generic-webhook signature on the receiving side (constant-time, with a replay window).
 * @example verifySignature(secret, req.headers['x-tocsin-timestamp'], rawBody, req.headers['x-tocsin-signature'])
 */
export function verifySignature(secret: string, timestampHeader: string | undefined, body: string, signatureHeader: string | undefined, nowSeconds = Math.floor(Date.now() / 1000), toleranceSeconds = 300): boolean {
  if (timestampHeader === undefined || signatureHeader === undefined || !/^\d{1,12}$/u.test(timestampHeader)) return false;
  const ts = Number(timestampHeader);
  if (Math.abs(nowSeconds - ts) > toleranceSeconds) return false;
  return constantTimeEqual(signBody(secret, ts, body), signatureHeader);
}

export interface TransportRequest {
  readonly target: ResolvedTarget;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
  readonly timeoutMs: number;
  readonly maxResponseBytes: number;
}

export type Transport = (req: TransportRequest) => Promise<{ status: number }>;

/**
 * Default transport: one POST over node:https (node:http only when the guard allowed it), connected to
 * the pre-checked address, no redirects followed, no cookies, response body capped and discarded.
 */
export const nodeTransport: Transport = (req) =>
  new Promise((resolve, reject) => {
    const { url, address, family } = req.target;
    const pinned: LookupFunction = (_host, options, cb) => {
      if (typeof options === 'object' && options.all === true) {
        (cb as unknown as (err: null, addrs: { address: string; family: number }[]) => void)(null, [{ address, family }]);
      } else {
        cb(null, address, family);
      }
    };
    const options: RequestOptions = {
      method: 'POST',
      host: url.hostname.replace(/^\[|\]$/gu, ''),
      port: url.port === '' ? undefined : Number(url.port),
      path: `${url.pathname}${url.search}`,
      headers: { ...req.headers, 'content-length': String(Buffer.byteLength(req.body)) },
      lookup: pinned,
      timeout: req.timeoutMs,
      agent: false,
    };
    const onResponse = (res: IncomingMessage): void => {
      let seen = 0;
      res.on('data', (chunk: Buffer) => {
        seen += chunk.length;
        if (seen > req.maxResponseBytes) res.destroy();
      });
      res.on('end', () => {
        resolve({ status: res.statusCode ?? 0 });
      });
      res.on('close', () => {
        resolve({ status: res.statusCode ?? 0 });
      });
      res.on('error', () => {
        resolve({ status: res.statusCode ?? 0 });
      });
    };
    // SNI must be a host name (RFC 6066); for an IP-literal URL the certificate is checked against the IP.
    const sni = isIP(options.host ?? '') === 0 ? { servername: url.hostname } : {};
    const r = url.protocol === 'https:' ? httpsRequest({ ...options, ...sni }, onResponse) : httpRequest(options, onResponse);
    const timer = setTimeout(() => r.destroy(new Error('timeout')), req.timeoutMs);
    r.on('timeout', () => r.destroy(new Error('timeout')));
    r.on('error', (e) => {
      clearTimeout(timer);
      reject(new TocsinError('NETWORK', `Webhook request failed (${e.message === 'timeout' ? 'timeout' : 'connection error'}).`));
    });
    r.on('close', () => { clearTimeout(timer); });
    r.end(req.body);
  });

export interface SendOptions extends GuardOptions {
  readonly transport?: Transport;
  readonly timeoutMs?: number;
  readonly now?: () => number;
}

function bodyFor(kind: WebhookKind, m: WebhookMessage, deliveryId: string): string {
  switch (kind) {
    case 'slack':
      return slackBody(m);
    case 'teams':
      return teamsBody(m);
    case 'generic':
      return genericBody(m, deliveryId);
  }
}

/**
 * Sends one message to one configured webhook. The URL and secret come from the environment variables
 * named in the configuration; neither is logged.
 */
export async function sendWebhook(cfg: WebhookConfig, m: WebhookMessage, env: Readonly<Record<string, string | undefined>>, opts: SendOptions = {}): Promise<void> {
  const url = env[cfg.urlEnv];
  if (url === undefined || url === '') throw new TocsinError('CONFIG', `Environment variable ${cfg.urlEnv} (webhook "${cfg.id}") is not set.`);
  const target = await resolveSafeTarget(url, { ...opts, ...(cfg.allowedHosts === undefined ? {} : { allowedHosts: cfg.allowedHosts }) });
  const deliveryId = randomUUID();
  const body = bodyFor(cfg.kind, m, deliveryId);
  const headers: Record<string, string> = { 'content-type': 'application/json', 'user-agent': 'tocsin-webhook/1' };
  if (cfg.kind === 'generic') {
    const secretName = cfg.secretEnv;
    const secret = secretName === undefined ? undefined : env[secretName];
    if (secret === undefined || secret.length < 32) throw new TocsinError('CONFIG', `Environment variable ${secretName ?? '(secretEnv)'} must hold an HMAC secret of at least 32 characters.`);
    const ts = Math.floor((opts.now ?? Date.now)() / 1000);
    headers[TIMESTAMP_HEADER] = String(ts);
    headers[SIGNATURE_HEADER] = signBody(secret, ts, body);
    headers['x-tocsin-delivery'] = deliveryId;
    headers['x-tocsin-event'] = m.event;
  }
  const res = await (opts.transport ?? nodeTransport)({ target, headers, body, timeoutMs: opts.timeoutMs ?? 10_000, maxResponseBytes: 64 * 1024 });
  if (res.status >= 300 && res.status < 400) throw new TocsinError('NETWORK', `Webhook "${cfg.id}" answered with a redirect (${res.status}); redirects are not followed.`);
  if (res.status < 200 || res.status >= 300) throw new TocsinError('NETWORK', `Webhook "${cfg.id}" answered with HTTP ${res.status}.`);
}
