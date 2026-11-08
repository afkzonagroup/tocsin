// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { describe, expect, it } from 'vitest';
import { addCalendarMonths, addHours, formatDuration, parseDurationSeconds } from '../src/time/periods.js';
import { earliestInstantForLocal, formatInZone, instantsForLocal, isValidTimeZone, parseInstant, toIso, toMs } from '../src/time/zone.js';

const V = 'Europe/Vilnius'; // EET/EEST: DST starts 2026-03-29 03:00 -> 04:00, ends 2026-10-25 04:00 -> 03:00
const NY = 'America/New_York'; // DST starts 2026-03-08 02:00 -> 03:00

describe('parseInstant', () => {
  it('accepts UTC and explicit offsets', () => {
    expect(parseInstant('2026-03-29T14:05Z', V)).toBe('2026-03-29T14:05:00.000Z');
    expect(parseInstant('2026-03-29T14:05:30.5+02:00', V)).toBe('2026-03-29T12:05:30.500Z');
    expect(parseInstant('2026-03-29 14:05-05:30', V)).toBe('2026-03-29T19:35:00.000Z');
  });

  it('reads times without offset in the configured zone, winter and summer', () => {
    expect(parseInstant('2026-01-15T10:00', V)).toBe('2026-01-15T08:00:00.000Z');
    expect(parseInstant('2026-07-15T10:00', V)).toBe('2026-07-15T07:00:00.000Z');
  });

  it('rejects a wall time inside the spring-forward gap', () => {
    expect(() => parseInstant('2026-03-29T03:30', V)).toThrow(/does not exist/u);
  });

  it('rejects an ambiguous wall time inside the fall-back overlap', () => {
    expect(() => parseInstant('2026-10-25T03:30', V)).toThrow(/happens twice/u);
    expect(parseInstant('2026-10-25T03:30+03:00', V)).toBe('2026-10-25T00:30:00.000Z');
    expect(parseInstant('2026-10-25T03:30+02:00', V)).toBe('2026-10-25T01:30:00.000Z');
  });

  it('rejects invalid dates and formats', () => {
    for (const bad of ['2026-02-29T10:00', '2026-13-01T00:00', '2026-04-31T00:00', '2026-01-01T24:00', '2026-01-01T10:60', '2026-01-01', 'yesterday', '1969-12-31T23:59Z', '2026-01-01T10:00+19:00']) {
      expect(() => parseInstant(bad, V), bad).toThrow();
    }
  });

  it('accepts leap days', () => {
    expect(parseInstant('2028-02-29T12:00Z', V)).toBe('2028-02-29T12:00:00.000Z');
  });
});

describe('zone helpers', () => {
  it('validates IANA zone names', () => {
    expect(isValidTimeZone('Europe/Vilnius')).toBe(true);
    expect(isValidTimeZone('UTC')).toBe(true);
    expect(isValidTimeZone('Mars/Olympus')).toBe(false);
    expect(isValidTimeZone('../etc/passwd')).toBe(false);
    expect(isValidTimeZone('')).toBe(false);
  });

  it('finds both instants of an ambiguous wall time and none in a gap', () => {
    const overlap = instantsForLocal({ year: 2026, month: 10, day: 25, hour: 3, minute: 30, second: 0, millisecond: 0 }, V);
    expect(overlap.map(toIso)).toEqual(['2026-10-25T00:30:00.000Z', '2026-10-25T01:30:00.000Z']);
    expect(instantsForLocal({ year: 2026, month: 3, day: 29, hour: 3, minute: 30, second: 0, millisecond: 0 }, V)).toEqual([]);
  });

  it('chooses the earlier reading for a gap time', () => {
    const t = earliestInstantForLocal({ year: 2026, month: 3, day: 29, hour: 3, minute: 30, second: 0, millisecond: 0 }, V);
    expect(toIso(t)).toBe('2026-03-29T00:30:00.000Z'); // read with the summer offset (+03:00), the earlier instant
  });

  it('formats with the offset in force', () => {
    expect(formatInZone('2026-01-15T08:00:00.000Z', V)).toBe('2026-01-15 10:00 (UTC+02:00)');
    expect(formatInZone('2026-07-15T07:00:00.000Z', V)).toBe('2026-07-15 10:00 (UTC+03:00)');
    expect(formatInZone('2026-07-15T07:00:00.000Z', 'America/St_Johns')).toBe('2026-07-15 04:30 (UTC-02:30)');
  });

  it('only accepts canonical stored timestamps', () => {
    expect(() => toMs('2026-01-01T00:00:00Z')).toThrow();
    expect(() => toMs('2026-02-30T00:00:00.000Z')).toThrow();
    expect(toMs('2026-01-01T00:00:00.000Z')).toBe(Date.UTC(2026, 0, 1));
  });
});

describe('addHours (Article 23(4)(a),(b): elapsed hours)', () => {
  it('adds exact elapsed time', () => {
    expect(addHours('2026-01-10T08:00:00.000Z', 24)).toBe('2026-01-11T08:00:00.000Z');
    expect(addHours('2026-01-10T08:00:00.000Z', 72)).toBe('2026-01-13T08:00:00.000Z');
  });

  it('24 hours across spring-forward ends one wall-clock hour later', () => {
    const aware = parseInstant('2026-03-28T12:00', V); // EET (+02:00)
    const due = addHours(aware, 24);
    expect(formatInZone(due, V)).toBe('2026-03-29 13:00 (UTC+03:00)');
  });

  it('24 hours across fall-back ends one wall-clock hour earlier', () => {
    const aware = parseInstant('2026-10-24T12:00', V); // EEST (+03:00)
    expect(formatInZone(addHours(aware, 24), V)).toBe('2026-10-25 11:00 (UTC+02:00)');
  });

  it('72 hours across a DST change is still 259 200 000 ms', () => {
    const aware = parseInstant('2026-03-27T22:30', V);
    expect(toMs(addHours(aware, 72)) - toMs(aware)).toBe(72 * 3_600_000);
  });

  it('rejects negative or fractional hours', () => {
    expect(() => addHours('2026-01-01T00:00:00.000Z', -1)).toThrow();
    expect(() => addHours('2026-01-01T00:00:00.000Z', 1.5)).toThrow();
  });
});

describe('addCalendarMonths (Article 23(4)(d),(e): "one month")', () => {
  const plus1 = (local: string, zone = V): string => formatInZone(addCalendarMonths(parseInstant(local, zone), 1, zone), zone);

  it('same day and time next month', () => {
    expect(plus1('2026-01-15T10:00')).toBe('2026-02-15 10:00 (UTC+02:00)');
  });

  it('31 January -> last day of February (common year)', () => {
    expect(plus1('2027-01-31T10:00')).toBe('2027-02-28 10:00 (UTC+02:00)');
  });

  it('31 January -> 29 February in a leap year; 29 Feb -> 29 Mar', () => {
    expect(plus1('2028-01-31T10:00')).toBe('2028-02-29 10:00 (UTC+02:00)');
    expect(plus1('2028-02-29T10:00')).toBe('2028-03-29 10:00 (UTC+03:00)');
  });

  it('30 and 29 January -> end of February in a common year', () => {
    expect(plus1('2027-01-30T10:00')).toBe('2027-02-28 10:00 (UTC+02:00)');
    expect(plus1('2027-01-29T10:00')).toBe('2027-02-28 10:00 (UTC+02:00)');
  });

  it('31 March -> 30 April; 31 May -> 30 June; 31 August -> 30 September; 31 October -> 30 November', () => {
    expect(plus1('2026-03-31T09:00')).toBe('2026-04-30 09:00 (UTC+03:00)');
    expect(plus1('2026-05-31T09:00')).toBe('2026-06-30 09:00 (UTC+03:00)');
    expect(plus1('2026-08-31T09:00')).toBe('2026-09-30 09:00 (UTC+03:00)');
    expect(plus1('2026-10-31T09:00')).toBe('2026-11-30 09:00 (UTC+02:00)');
  });

  it('31 December -> 31 January of the next year', () => {
    expect(plus1('2026-12-31T23:59')).toBe('2027-01-31 23:59 (UTC+02:00)');
  });

  it('keeps the wall-clock time across a DST change (elapsed time differs by an hour)', () => {
    const start = parseInstant('2026-03-10T10:00', V);
    const end = addCalendarMonths(start, 1, V);
    expect(formatInZone(end, V)).toBe('2026-04-10 10:00 (UTC+03:00)');
    expect(toMs(end) - toMs(start)).toBe(31 * 86_400_000 - 3_600_000);
  });

  it('target wall time in a DST gap -> earliest reading', () => {
    const start = parseInstant('2026-02-08T02:30', NY);
    expect(addCalendarMonths(start, 1, NY)).toBe('2026-03-08T06:30:00.000Z'); // 02:30 read at -04:00 (01:30 EST)
  });

  it('target wall time in a DST overlap -> earlier of the two instants', () => {
    const start = parseInstant('2026-09-25T03:30', V);
    expect(addCalendarMonths(start, 1, V)).toBe('2026-10-25T00:30:00.000Z');
  });

  it('local date matters, not UTC date (23:30 local on 31 Jan is 21:30 UTC)', () => {
    expect(plus1('2027-01-31T23:30')).toBe('2027-02-28 23:30 (UTC+02:00)');
    // In UTC the same instant is 31 Jan 21:30Z; in Asia/Tokyo it is already 1 Feb.
    const t = parseInstant('2027-01-31T23:30', V);
    expect(formatInZone(addCalendarMonths(t, 1, 'Asia/Tokyo'), 'Asia/Tokyo')).toBe('2027-03-01 06:30 (UTC+09:00)');
  });

  it('adds several months and rejects bad input', () => {
    expect(addCalendarMonths('2026-08-31T09:00:00.000Z', 6, 'UTC')).toBe('2027-02-28T09:00:00.000Z');
    expect(() => addCalendarMonths('2026-08-31T09:00:00.000Z', -1, 'UTC')).toThrow();
  });
});

describe('durations', () => {
  it('parses and formats', () => {
    expect(parseDurationSeconds('45s', 'd')).toBe(45);
    expect(parseDurationSeconds('30m', 'd')).toBe(1800);
    expect(parseDurationSeconds('1h30m', 'd')).toBe(5400);
    expect(parseDurationSeconds('2h15m10s', 'd')).toBe(8110);
    expect(formatDuration(5410)).toBe('1h 30m 10s');
    expect(formatDuration(0)).toBe('0s');
  });

  it('rejects malformed durations', () => {
    for (const bad of ['', 'h', '1d', '30', '-5m', '1.5h', '1m1h']) expect(() => parseDurationSeconds(bad, 'd'), bad).toThrow();
  });
});
