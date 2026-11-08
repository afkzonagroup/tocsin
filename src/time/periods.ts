// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { invalid } from '../util/errors.js';
import { daysInMonth, earliestInstantForLocal, localParts, toIso, toMs } from './zone.js';

/**
 * Periods used by Article 23(4) NIS2.
 *
 * Hours ("within 24 hours", "within 72 hours") are elapsed time: exactly h × 3 600 000 ms after
 * the start instant. A DST change in between therefore moves the wall-clock deadline by an hour,
 * which is correct: 24 hours is 24 hours of real time.
 *
 * Months ("one month after") are calendar months in the configured zone: same day-of-month and
 * same wall-clock time in the following month. When that day does not exist (31 January → February)
 * the last day of the month is used. When the wall-clock time happens twice on that day (DST) the first
 * occurrence is used; when it does not exist, the earlier of its two possible readings
 * ({@link earliestInstantForLocal}). See LEGAL.md "Interpretation choices".
 */

/** Adds an exact number of hours. */
export function addHours(iso: string, hours: number): string {
  if (!Number.isSafeInteger(hours) || hours < 0) invalid('Hours must be a non-negative whole number.');
  return toIso(toMs(iso) + hours * 3_600_000);
}

/** Adds calendar months in `zone`, clamping to the end of shorter months. */
export function addCalendarMonths(iso: string, months: number, zone: string): string {
  if (!Number.isSafeInteger(months) || months < 0 || months > 1200) invalid('Months must be a whole number between 0 and 1200.');
  const start = toMs(iso);
  const p = localParts(start, zone);
  const index = p.year * 12 + (p.month - 1) + months;
  const year = Math.floor(index / 12);
  const month = (index % 12) + 1;
  const day = Math.min(p.day, daysInMonth(year, month));
  return toIso(earliestInstantForLocal({ ...p, year, month, day }, zone));
}

/**
 * Parses a duration such as "45s", "30m", "1h", "1h30m", "2h15m10s" into seconds.
 * Used for availability criteria where the thresholds are "more than 30 minutes" etc.
 */
export function parseDurationSeconds(text: string, what: string): number {
  const t = text.trim();
  const m = /^(?:(\d{1,6})h)?(?:(\d{1,7})m)?(?:(\d{1,9})s)?$/u.exec(t);
  if (t.length === 0 || m === null || (m[1] === undefined && m[2] === undefined && m[3] === undefined)) {
    invalid(`${what} must be a duration such as 45s, 30m, 1h or 1h30m.`);
  }
  const total = Number(m[1] ?? 0) * 3600 + Number(m[2] ?? 0) * 60 + Number(m[3] ?? 0);
  if (total > 10 * 365 * 86_400) invalid(`${what} is longer than ten years.`);
  return total;
}

/** "1h 30m 5s" style rendering of seconds. */
export function formatDuration(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  const out: string[] = [];
  if (h > 0) out.push(`${h}h`);
  if (m > 0) out.push(`${m}m`);
  if (s > 0 || out.length === 0) out.push(`${s}s`);
  return out.join(' ');
}
