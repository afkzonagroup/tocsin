// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { invalid } from './errors.js';

/** Hand-written boundary validators. Each one either returns a typed value or throws VALIDATION. */

export type Tri = 'yes' | 'no' | 'unknown';
export const TRI_VALUES: readonly Tri[] = ['yes', 'no', 'unknown'];

/** Plain object check (no arrays, no class instances, no null). */
export function isRecord(v: unknown): v is Record<string, unknown> {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return false;
  const proto: unknown = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

export function asRecord(v: unknown, what: string): Record<string, unknown> {
  if (!isRecord(v)) invalid(`${what} must be an object.`);
  return v;
}

/** Rejects keys not in the allow-list (and prototype-polluting keys). */
export function onlyKeys(obj: Record<string, unknown>, allowed: readonly string[], what: string): void {
  for (const k of Object.keys(obj)) {
    if (!allowed.includes(k)) invalid(`${what}: unknown field "${truncate(k, 40)}".`);
  }
}

// C0 controls except TAB, LF, CR; DEL; C1 controls; bidi overrides and isolates.
// eslint-disable-next-line no-control-regex -- the point of this pattern is to match control characters
const FORBIDDEN_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]/u;
// eslint-disable-next-line no-control-regex -- single-line fields forbid every control character incl. newlines
const FORBIDDEN_SINGLE_LINE = /[\u0000-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]/u;

export interface StringRule {
  readonly max: number;
  readonly min?: number;
  readonly multiline?: boolean;
  readonly pattern?: RegExp;
}

/** Validates a string: type, length (in code points), control characters, optional pattern. */
export function str(v: unknown, what: string, rule: StringRule): string {
  if (typeof v !== 'string') invalid(`${what} must be a string.`);
  const s = v.normalize('NFC');
  const len = codePointLength(s);
  if (len > rule.max) invalid(`${what} is too long (max ${rule.max} characters).`);
  if (len < (rule.min ?? 0)) invalid(`${what} is too short (min ${rule.min ?? 0} characters).`);
  const forbidden = rule.multiline === true ? FORBIDDEN_CHARS : FORBIDDEN_SINGLE_LINE;
  if (forbidden.test(s)) invalid(`${what} contains control or bidirectional-override characters.`);
  if (rule.pattern !== undefined && !rule.pattern.test(s)) invalid(`${what} has an invalid format.`);
  return s;
}

export function optStr(v: unknown, what: string, rule: StringRule): string | undefined {
  return v === undefined ? undefined : str(v, what, rule);
}

export function bool(v: unknown, what: string): boolean {
  if (typeof v !== 'boolean') invalid(`${what} must be true or false.`);
  return v;
}

export function tri(v: unknown, what: string): Tri {
  if (typeof v !== 'string' || !(TRI_VALUES as readonly string[]).includes(v)) invalid(`${what} must be one of: yes, no, unknown.`);
  return v as Tri;
}

export function oneOf<T extends string>(v: unknown, allowed: readonly T[], what: string): T {
  if (typeof v !== 'string' || !(allowed as readonly string[]).includes(v)) {
    invalid(`${what} must be one of: ${allowed.join(', ')}.`);
  }
  return v as T;
}

/** Non-negative safe integer within [0, max]. */
export function nonNegInt(v: unknown, what: string, max: number = Number.MAX_SAFE_INTEGER): number {
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 0) invalid(`${what} must be a non-negative whole number.`);
  if (v > max) invalid(`${what} is too large (max ${max}).`);
  return v;
}

export function optNonNegInt(v: unknown, what: string, max?: number): number | undefined {
  return v === undefined ? undefined : nonNegInt(v, what, max);
}

export function arr(v: unknown, what: string, maxItems: number): unknown[] {
  if (!Array.isArray(v)) invalid(`${what} must be a list.`);
  if (v.length > maxItems) invalid(`${what} has too many items (max ${maxItems}).`);
  return v as unknown[];
}

/** Parses a decimal integer from text (CLI / form input). */
export function parseIntText(v: string, what: string, max: number = Number.MAX_SAFE_INTEGER): number {
  if (!/^\d{1,16}$/u.test(v)) invalid(`${what} must be a non-negative whole number.`);
  return nonNegInt(Number(v), what, max);
}

/** Parses an amount in euro ("1234", "1234.5", "1234.56") into integer cents, exactly. */
export function parseEuroToCents(v: string, what: string): number {
  const m = /^(\d{1,13})(?:\.(\d{1,2}))?$/u.exec(v.trim());
  if (m === null) invalid(`${what} must be an amount in euro such as 1250000 or 1250000.50.`);
  const whole = Number(m[1]);
  const frac = Number((m[2] ?? '0').padEnd(2, '0'));
  return nonNegInt(whole * 100 + frac, what, MAX_CENTS);
}

/** 10^15 cents = 10 trillion euro. Keeps all arithmetic (x * 1000) inside the safe-integer range. */
export const MAX_CENTS = 1_000_000_000_000_000;
/** Upper bound for user counts (keeps x * 1000 inside safe integers). */
export const MAX_COUNT = 1_000_000_000_000;

/** Number of Unicode code points (what users perceive as characters for length limits). */
export function codePointLength(s: string): number {
  return Array.from(s).length;
}

/** First `n` code points of `s`. */
export function codePointSlice(s: string, n: number): string {
  return Array.from(s).slice(0, n).join('');
}

function truncate(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}
