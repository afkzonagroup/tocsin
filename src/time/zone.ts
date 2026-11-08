// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { invalid } from '../util/errors.js';

/**
 * Time handling. All instants are stored as UTC ISO strings ("2026-01-31T09:00:00.000Z").
 * Wall-clock views use an IANA time zone through the built-in Intl API (no tz database is bundled).
 */

export interface LocalDateTime {
  readonly year: number;
  readonly month: number; // 1-12
  readonly day: number; // 1-31
  readonly hour: number; // 0-23
  readonly minute: number;
  readonly second: number;
  readonly millisecond: number;
}

const MIN_MS = Date.UTC(1970, 0, 1);
const MAX_MS = Date.UTC(9999, 11, 31, 23, 59, 59, 999);

const formatters = new Map<string, Intl.DateTimeFormat>();

function formatter(zone: string): Intl.DateTimeFormat {
  let f = formatters.get(zone);
  if (f === undefined) {
    f = new Intl.DateTimeFormat('en-US', {
      timeZone: zone,
      hourCycle: 'h23',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      era: 'short',
    });
    formatters.set(zone, f);
  }
  return f;
}

/** True when `zone` is an IANA zone name the runtime knows (e.g. "Europe/Vilnius", "UTC"). */
export function isValidTimeZone(zone: string): boolean {
  if (zone.length === 0 || zone.length > 64 || !/^[A-Za-z0-9_+\-/]+$/u.test(zone)) return false;
  try {
    formatter(zone);
    return true;
  } catch {
    return false;
  }
}

export function assertTimeZone(zone: string): string {
  if (!isValidTimeZone(zone)) invalid(`Unknown IANA time zone "${zone.slice(0, 64)}".`);
  return zone;
}

/** Wall-clock fields of instant `ms` in `zone`. */
export function localParts(ms: number, zone: string): LocalDateTime {
  const parts = formatter(zone).formatToParts(new Date(ms));
  const get = (type: Intl.DateTimeFormatPartTypes): number => {
    const p = parts.find((x) => x.type === type);
    if (p === undefined) throw new Error(`Intl did not return ${type}`);
    return Number(p.value);
  };
  return {
    year: get('year'),
    month: get('month'),
    day: get('day'),
    hour: get('hour'),
    minute: get('minute'),
    second: get('second'),
    millisecond: ((ms % 1000) + 1000) % 1000,
  };
}

/** UTC offset of `zone` at instant `ms`, in milliseconds (local = utc + offset). */
export function offsetAt(ms: number, zone: string): number {
  const p = localParts(ms, zone);
  const asUtc = Date.UTC(p.year, p.month - 1, p.day, p.hour, p.minute, p.second, p.millisecond);
  return asUtc - ms;
}

function sameLocal(a: LocalDateTime, b: LocalDateTime): boolean {
  return (
    a.year === b.year &&
    a.month === b.month &&
    a.day === b.day &&
    a.hour === b.hour &&
    a.minute === b.minute &&
    a.second === b.second &&
    a.millisecond === b.millisecond
  );
}

/**
 * All instants whose wall-clock time in `zone` equals `local`, earliest first.
 * Empty when the time falls in a DST gap; two entries when it falls in a DST overlap.
 */
export function instantsForLocal(local: LocalDateTime, zone: string): number[] {
  const naive = Date.UTC(local.year, local.month - 1, local.day, local.hour, local.minute, local.second, local.millisecond);
  const offsets = new Set<number>();
  // Offsets in force a day either side cover every real-world transition (max shift < 24 h).
  for (const probe of [naive - 86_400_000, naive, naive + 86_400_000]) offsets.add(offsetAt(probe, zone));
  const result = new Set<number>();
  for (const off of offsets) {
    const candidate = naive - off;
    if (sameLocal(localParts(candidate, zone), local)) result.add(candidate);
  }
  return [...result].sort((a, b) => a - b);
}

/**
 * Wall-clock time to instant. When the local time happens twice (DST overlap) the first occurrence is
 * returned. When it does not exist (DST gap) it is read with each offset in force around the gap and the
 * earlier instant is returned, i.e. the reading with the offset after the change (02:30 on a 02:00 → 03:00
 * spring-forward day becomes 01:30 local time).
 */
export function earliestInstantForLocal(local: LocalDateTime, zone: string): number {
  const exact = instantsForLocal(local, zone);
  if (exact.length > 0) return exact[0] as number;
  // DST gap: read the wall time with each offset in force around it and take the earlier instant.
  const naive = Date.UTC(local.year, local.month - 1, local.day, local.hour, local.minute, local.second, local.millisecond);
  const candidates = [naive - offsetAt(naive - 86_400_000, zone), naive - offsetAt(naive + 86_400_000, zone)];
  return Math.min(...candidates);
}

export function daysInMonth(year: number, month: number): number {
  return new Date(Date.UTC(year, month, 0)).getUTCDate();
}

/** ISO string for a UTC instant in ms. */
export function toIso(ms: number): string {
  if (!Number.isFinite(ms) || ms < MIN_MS || ms > MAX_MS) invalid('Date is out of the supported range (1970–9999).');
  return new Date(ms).toISOString();
}

/** Milliseconds for a stored ISO instant. Only accepts the canonical UTC form produced by {@link toIso}. */
export function toMs(iso: string): number {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(iso)) invalid(`"${iso.slice(0, 40)}" is not a stored UTC timestamp.`);
  const v = Date.parse(iso);
  if (Number.isNaN(v) || toIso(v) !== iso) invalid(`"${iso.slice(0, 40)}" is not a valid date.`);
  return v;
}

const INPUT_RE =
  /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,3}))?)?(Z|[+-]\d{2}:\d{2})?$/u;

/**
 * Parses user input into a stored UTC ISO string.
 *
 * Accepts `YYYY-MM-DDTHH:mm[:ss[.fff]]` followed by `Z` or `±HH:MM`. Without an offset the
 * value is read as wall-clock time in `zone`; times that fall in a DST gap or overlap are
 * rejected with a message asking for an explicit offset, because guessing could shift a legal
 * deadline by an hour.
 *
 * @example parseInstant('2026-03-29T03:30', 'Europe/Vilnius') // '2026-03-29T00:30:00.000Z'
 */
export function parseInstant(text: string, zone: string): string {
  const m = INPUT_RE.exec(text.trim());
  if (m === null) invalid(`"${text.slice(0, 40)}" is not a date-time. Use e.g. 2026-03-29T14:05 or 2026-03-29T14:05:00+02:00.`);
  const [, y, mo, d, h, mi, s, frac, off] = m;
  const local: LocalDateTime = {
    year: Number(y),
    month: Number(mo),
    day: Number(d),
    hour: Number(h),
    minute: Number(mi),
    second: Number(s ?? '0'),
    millisecond: Number((frac ?? '0').padEnd(3, '0')),
  };
  if (local.year < 1970 || local.month < 1 || local.month > 12 || local.day < 1 || local.day > daysInMonth(local.year, local.month)) {
    invalid(`"${text.slice(0, 40)}" is not a valid calendar date.`);
  }
  if (local.hour > 23 || local.minute > 59 || local.second > 59) invalid(`"${text.slice(0, 40)}" is not a valid time of day.`);
  if (off !== undefined) {
    let offsetMs = 0;
    if (off !== 'Z') {
      const sign = off.startsWith('-') ? -1 : 1;
      const oh = Number(off.slice(1, 3));
      const om = Number(off.slice(4, 6));
      if (oh > 18 || om > 59) invalid(`"${off}" is not a valid UTC offset.`);
      offsetMs = sign * (oh * 60 + om) * 60_000;
    }
    const naive = Date.UTC(local.year, local.month - 1, local.day, local.hour, local.minute, local.second, local.millisecond);
    return toIso(naive - offsetMs);
  }
  const candidates = instantsForLocal(local, zone);
  if (candidates.length === 0) invalid(`${text.trim()} does not exist in ${zone} (clocks skip it). Add an explicit UTC offset.`);
  if (candidates.length > 1) invalid(`${text.trim()} happens twice in ${zone} (clocks go back). Add an explicit UTC offset.`);
  return toIso(candidates[0] as number);
}

function pad(n: number, w = 2): string {
  return String(n).padStart(w, '0');
}

/** Formats a stored instant as wall-clock time in `zone` with its UTC offset, e.g. "2026-03-29 03:30 (UTC+03:00)". */
export function formatInZone(iso: string, zone: string): string {
  const t = toMs(iso);
  const p = localParts(t, zone);
  const off = offsetAt(t, zone) / 60_000;
  const sign = off < 0 ? '-' : '+';
  const abs = Math.abs(off);
  return `${pad(p.year, 4)}-${pad(p.month)}-${pad(p.day)} ${pad(p.hour)}:${pad(p.minute)} (UTC${sign}${pad(Math.floor(abs / 60))}:${pad(abs % 60)})`;
}
