// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { invalid } from '../util/errors.js';
import { arr, asRecord, bool, MAX_CENTS, nonNegInt, oneOf, onlyKeys, optStr, str } from '../util/validate.js';
import { assertTimeZone } from '../time/zone.js';

/**
 * User configuration. Member States designate their own CSIRTs, competent authorities and
 * reporting channels (Articles 8, 10 and 23 NIS2), so none are built in: describe yours here.
 *
 * @example
 * ```json
 * {
 *   "version": 1,
 *   "timeZone": "Europe/Brussels",
 *   "entity": { "name": "Example UAB", "category": "important", "memberState": "LT" },
 *   "authority": { "role": "csirt", "name": "National CSIRT", "channel": "Web portal", "url": "https://portal.example" }
 * }
 * ```
 */
export interface TocsinConfig {
  readonly version: 1;
  /** IANA zone for wall-clock display and for "one month" deadlines. */
  readonly timeZone: string;
  readonly entity: EntityConfig;
  readonly authority: AuthorityConfig;
  /** Total annual turnover in the preceding financial year, for IR 2024/2690 Art 3(1)(a). */
  readonly turnover?: TurnoverConfig;
  readonly webhooks?: readonly WebhookConfig[];
}

export interface EntityConfig {
  readonly name: string;
  readonly category?: 'essential' | 'important';
  /** Member State of establishment, two-letter EU code (EL for Greece). */
  readonly memberState?: string;
  readonly contactName?: string;
  readonly contactEmail?: string;
  readonly contactPhone?: string;
}

export interface AuthorityConfig {
  /** Who receives notifications under Art 23(1): the CSIRT or, where applicable, the competent authority. */
  readonly role: 'csirt' | 'competent-authority';
  readonly name: string;
  /** How reports are submitted (portal, e-mail, form). Free text. */
  readonly channel?: string;
  readonly url?: string;
  readonly email?: string;
  readonly phone?: string;
  readonly notes?: string;
}

export interface TurnoverConfig {
  readonly financialYear: string;
  readonly amountCents: number;
}

export const WEBHOOK_KINDS = ['slack', 'teams', 'generic'] as const;
export type WebhookKind = (typeof WEBHOOK_KINDS)[number];
export const WEBHOOK_EVENTS = ['deadline-due-soon', 'deadline-overdue', 'stage-submitted'] as const;
export type WebhookEvent = (typeof WEBHOOK_EVENTS)[number];

export interface WebhookConfig {
  readonly id: string;
  readonly kind: WebhookKind;
  /** Name of the environment variable holding the webhook URL. URLs are secrets and never live in this file. */
  readonly urlEnv: string;
  /** Name of the environment variable holding the HMAC secret (required for `generic`). */
  readonly secretEnv?: string;
  readonly events: readonly WebhookEvent[];
  /** Hours before a deadline that a "due soon" message is sent. Default 6. */
  readonly dueSoonHours?: number;
  /** Include the incident title in messages. Default false (data minimisation). */
  readonly includeTitle?: boolean;
  /** Extra allow-list: when set, the URL host must be one of these names. */
  readonly allowedHosts?: readonly string[];
}

const ENV_NAME = /^[A-Z][A-Z0-9_]{0,63}$/u;
/** Environment variables that hold Tocsin's own keys; a webhook must never be pointed at them. */
const RESERVED_ENV = new Set(['TOCSIN_KEY', 'TOCSIN_PASSPHRASE', 'TOCSIN_EXPORT_KEY', 'TOCSIN_EXPORT_PASSPHRASE']);

function envName(v: unknown, what: string): string {
  const name = str(v, what, { max: 64, pattern: ENV_NAME });
  if (RESERVED_ENV.has(name)) invalid(`${what} must not name ${name}, which holds a Tocsin key.`);
  return name;
}
const HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/u;
const EMAIL = /^[^\s@<>"']{1,64}@[^\s@<>"']{1,190}$/u;

function optHttpsUrl(v: unknown, what: string): string | undefined {
  const s = optStr(v, what, { max: 500 });
  if (s === undefined) return undefined;
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    invalid(`${what} is not a valid URL.`);
  }
  if (u.protocol !== 'https:') invalid(`${what} must be an https:// URL.`);
  if (u.username !== '' || u.password !== '') invalid(`${what} must not contain credentials.`);
  return u.toString();
}

function put<T extends object, K extends keyof T>(target: T, key: K, value: T[K] | undefined): void {
  if (value !== undefined) target[key] = value;
}

function validateWebhook(v: unknown, i: number): WebhookConfig {
  const what = `webhooks[${i}]`;
  const o = asRecord(v, what);
  onlyKeys(o, ['id', 'kind', 'urlEnv', 'secretEnv', 'events', 'dueSoonHours', 'includeTitle', 'allowedHosts'], what);
  const kind = oneOf(o['kind'], WEBHOOK_KINDS, `${what}.kind`);
  const events = arr(o['events'], `${what}.events`, WEBHOOK_EVENTS.length).map((e) => oneOf(e, WEBHOOK_EVENTS, `${what}.events`));
  if (events.length === 0) invalid(`${what}.events must list at least one event.`);
  const w: { -readonly [K in keyof WebhookConfig]: WebhookConfig[K] } = {
    id: str(o['id'], `${what}.id`, { max: 40, min: 1, pattern: /^[a-z0-9][a-z0-9-]*$/u }),
    kind,
    urlEnv: envName(o['urlEnv'], `${what}.urlEnv`),
    events: [...new Set(events)],
  };
  put(w, 'secretEnv', o['secretEnv'] === undefined ? undefined : envName(o['secretEnv'], `${what}.secretEnv`));
  if (kind === 'generic' && w.secretEnv === undefined) invalid(`${what}.secretEnv is required for generic webhooks (requests are HMAC-signed).`);
  if (o['dueSoonHours'] !== undefined) {
    const h = nonNegInt(o['dueSoonHours'], `${what}.dueSoonHours`, 72);
    if (h < 1) invalid(`${what}.dueSoonHours must be at least 1.`);
    w.dueSoonHours = h;
  }
  if (o['includeTitle'] !== undefined) w.includeTitle = bool(o['includeTitle'], `${what}.includeTitle`);
  if (o['allowedHosts'] !== undefined) {
    w.allowedHosts = arr(o['allowedHosts'], `${what}.allowedHosts`, 20).map((h, j) => str(h, `${what}.allowedHosts[${j}]`, { max: 253, pattern: HOSTNAME }));
  }
  return w;
}

/** Validates a parsed configuration object. Throws VALIDATION with the first problem found. */
export function validateConfig(v: unknown): TocsinConfig {
  const o = asRecord(v, 'config');
  onlyKeys(o, ['$schema', 'version', 'timeZone', 'entity', 'authority', 'turnover', 'webhooks'], 'config');
  if (o['version'] !== 1) invalid('config.version must be 1.');
  const timeZone = assertTimeZone(str(o['timeZone'], 'config.timeZone', { max: 64 }));

  const e = asRecord(o['entity'], 'config.entity');
  onlyKeys(e, ['name', 'category', 'memberState', 'contactName', 'contactEmail', 'contactPhone'], 'config.entity');
  const entity: { -readonly [K in keyof EntityConfig]: EntityConfig[K] } = { name: str(e['name'], 'entity.name', { max: 200, min: 1 }) };
  if (e['category'] !== undefined) entity.category = oneOf(e['category'], ['essential', 'important'] as const, 'entity.category');
  put(entity, 'memberState', optStr(e['memberState'], 'entity.memberState', { max: 2, min: 2, pattern: /^[A-Z]{2}$/u }));
  put(entity, 'contactName', optStr(e['contactName'], 'entity.contactName', { max: 200 }));
  put(entity, 'contactEmail', optStr(e['contactEmail'], 'entity.contactEmail', { max: 254, pattern: EMAIL }));
  put(entity, 'contactPhone', optStr(e['contactPhone'], 'entity.contactPhone', { max: 40, pattern: /^[0-9+()\- ]{3,40}$/u }));

  const a = asRecord(o['authority'], 'config.authority');
  onlyKeys(a, ['role', 'name', 'channel', 'url', 'email', 'phone', 'notes'], 'config.authority');
  const authority: { -readonly [K in keyof AuthorityConfig]: AuthorityConfig[K] } = {
    role: oneOf(a['role'], ['csirt', 'competent-authority'] as const, 'authority.role'),
    name: str(a['name'], 'authority.name', { max: 200, min: 1 }),
  };
  put(authority, 'channel', optStr(a['channel'], 'authority.channel', { max: 200 }));
  put(authority, 'url', optHttpsUrl(a['url'], 'authority.url'));
  put(authority, 'email', optStr(a['email'], 'authority.email', { max: 254, pattern: EMAIL }));
  put(authority, 'phone', optStr(a['phone'], 'authority.phone', { max: 40, pattern: /^[0-9+()\- ]{3,40}$/u }));
  put(authority, 'notes', optStr(a['notes'], 'authority.notes', { max: 2000, multiline: true }));

  const cfg: { -readonly [K in keyof TocsinConfig]: TocsinConfig[K] } = { version: 1, timeZone, entity, authority };
  if (o['turnover'] !== undefined) {
    const t = asRecord(o['turnover'], 'config.turnover');
    onlyKeys(t, ['financialYear', 'amountCents'], 'config.turnover');
    cfg.turnover = {
      financialYear: str(t['financialYear'], 'turnover.financialYear', { max: 20, min: 4 }),
      amountCents: nonNegInt(t['amountCents'], 'turnover.amountCents', MAX_CENTS),
    };
  }
  if (o['webhooks'] !== undefined) {
    const list = arr(o['webhooks'], 'config.webhooks', 10).map(validateWebhook);
    const ids = new Set(list.map((w) => w.id));
    if (ids.size !== list.length) invalid('webhook ids must be unique.');
    cfg.webhooks = list;
  }
  return cfg;
}
