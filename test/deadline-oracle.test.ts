// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Property tests: computeDeadlines against an independently written oracle (test/oracle) over thousands of
 * generated incidents. Awareness times are drawn around daylight-saving changes, month ends and leap days in
 * several zones (including 30-minute and negative DST); submissions, corrections of awareness, trust-service
 * answers, handling conclusion and intermediate requests are drawn at random within what Tocsin accepts.
 */

import { describe, expect, it } from 'vitest';
import type { Incident, IncidentDetails } from '../src/model/types.js';
import { computeDeadlines, type Deadline } from '../src/stages/deadlines.js';
import { oracleDeadlines, plusOneMonth, wallOf, type OracleDeadline } from './oracle/deadline-oracle.js';
import { incident, sub } from './helpers.js';

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const ZONES = [
  'Europe/Vilnius',
  'Europe/Brussels',
  'Europe/Lisbon',
  'Europe/Dublin', // negative DST in tzdata (winter time is the "summer" offset)
  'Atlantic/Azores',
  'Australia/Lord_Howe', // 30-minute DST
  'Pacific/Chatham', // UTC+12:45 / +13:45
  'America/Santiago', // DST changes at midnight
  'UTC',
];

/** Small deterministic PRNG (mulberry32) so failures are reproducible from the seed. */
function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Instants where the zone's UTC offset changes, 2026-2029, found by scanning and bisection. */
function transitions(zone: string): number[] {
  const off = (t: number): number => {
    const w = wallOf(t, zone);
    return Date.UTC(w.y, w.mo - 1, w.d, w.h, w.mi, w.s, w.ms) - t;
  };
  const out: number[] = [];
  const start = Date.UTC(2026, 0, 1);
  const end = Date.UTC(2030, 0, 1);
  for (let t = start; t < end; t += 6 * HOUR) {
    if (off(t) === off(t + 6 * HOUR)) continue;
    let lo = t;
    let hi = t + 6 * HOUR;
    while (hi - lo > 1000) {
      const mid = Math.floor((lo + hi) / 2);
      if (off(mid) === off(lo)) lo = mid;
      else hi = mid;
    }
    out.push(hi);
  }
  return out;
}

const TRANSITIONS = new Map(ZONES.map((z) => [z, transitions(z)]));

/** Month ends and leap days as UTC instants near local midnight and late evening. */
function monthEnds(): number[] {
  const out: number[] = [];
  for (let y = 2026; y <= 2029; y++) {
    for (let m = 0; m < 12; m++) {
      const last = new Date(Date.UTC(y, m + 1, 0)).getUTCDate();
      for (const d of [28, 29, 30, 31]) if (d <= last) out.push(Date.UTC(y, m, d, 12));
    }
  }
  out.push(Date.UTC(2028, 1, 29, 0), Date.UTC(2028, 1, 29, 23));
  return out;
}
const MONTH_ENDS = monthEnds();

const TRI: readonly IncidentDetails['trustServicesImpacted'][] = ['yes', 'no', 'unknown', undefined];

function pick<T>(r: () => number, xs: readonly T[]): T {
  const x = xs[Math.floor(r() * xs.length)];
  if (x === undefined) throw new Error('empty');
  return x;
}

/** An awareness instant: near a DST change, a month end, or anywhere in 2026-2029. */
function awareness(r: () => number, zone: string): number {
  const mode = r();
  const jitter = (span: number): number => Math.round((r() * 2 - 1) * span / 60_000) * 60_000;
  const ts = TRANSITIONS.get(zone) ?? [];
  if (mode < 0.4 && ts.length > 0) {
    // Clocks change 24 h, 72 h or about a month after awareness: start just before such a moment.
    const t = pick(r, ts);
    const lead = pick(r, [0, 24 * HOUR, 72 * HOUR, 30 * DAY, 31 * DAY, 28 * DAY]);
    return t - lead + jitter(3 * HOUR);
  }
  if (mode < 0.7) return pick(r, MONTH_ENDS) + jitter(14 * HOUR);
  return Date.UTC(2026, 0, 1) + Math.floor(r() * 4 * 365 * DAY / 60_000) * 60_000;
}

interface Case {
  readonly inc: Incident;
  readonly zone: string;
  readonly now: number;
}

function generate(seed: number): Case {
  const r = rng(seed);
  const zone = pick(r, ZONES);
  const aware = awareness(r, zone);
  const iso = (t: number): string => new Date(t).toISOString();
  const trustProvider = r() < 0.3;
  const serviceTypes: Incident['serviceTypes'] = trustProvider ? ['trust-service'] : [pick(r, ['cloud', 'dns', 'data-centre', 'online-marketplace'] as const)];
  const submissions: Incident['submissions'] = [];
  // Submissions in stage order, each 0-100 h after the previous event (some on time, some late).
  let t = aware;
  const step = (maxHours: number): number => (t += Math.floor(r() * maxHours * 60) * 60_000);
  const ew = r() < 0.8;
  if (ew) submissions.push(sub('early-warning', iso(step(40))));
  const notif = ew && r() < 0.75;
  if (notif) submissions.push(sub('incident-notification', iso(step(80))));
  // Handling concludes at some point (or not yet).
  const concludedAt = r() < 0.6 ? aware + Math.floor(r() * 70) * DAY + Math.floor(r() * 24) * HOUR : undefined;
  if (notif && r() < 0.3) {
    const at = t + Math.floor(r() * 40) * DAY;
    if (concludedAt === undefined || at < concludedAt) {
      submissions.push(sub('progress-report', iso(at)));
      t = at;
    }
  }
  // A final report can only be submitted once handling has concluded (Tocsin refuses it before).
  if (notif && concludedAt !== undefined && r() < 0.6) {
    const after = Math.max(t, concludedAt);
    submissions.push(sub('final-report', iso(after + Math.floor(r() * 45) * DAY + Math.floor(r() * 24) * HOUR)));
  }
  const intermediateRequests: Incident['intermediateRequests'] = [];
  if (ew && r() < 0.3) {
    const requestedAt = aware + Math.floor(r() * 10) * DAY;
    const dueAt = r() < 0.5 ? iso(requestedAt + Math.floor(r() * 7 + 1) * DAY) : undefined;
    const answered = r() < 0.5 ? { submittedAt: iso(requestedAt + Math.floor(r() * 9) * DAY), recordedAt: iso(requestedAt), contentSha256: '0'.repeat(64), snapshot: {} } : undefined;
    intermediateRequests.push({ id: 'REQ-1', requestedAt: iso(requestedAt), ...(dueAt === undefined ? {} : { dueAt }), ...(answered === undefined ? {} : { submission: answered }) });
  }
  const trustAnswer = TRI[Math.floor(r() * TRI.length)];
  // Corrected awareness: the time is changed after reports were sent (Tocsin allows it with a reason), so
  // submissions may now precede or lag the recorded awareness by up to two days.
  const correctedAware = r() < 0.15 ? aware + Math.round((r() * 2 - 1) * 48 * 60) * 60_000 : aware;
  const inc = incident({
    serviceTypes,
    awareAt: iso(correctedAware),
    submissions,
    intermediateRequests,
    details: trustAnswer === undefined ? {} : { trustServicesImpacted: trustAnswer },
    ...(concludedAt === undefined ? {} : { handlingConcludedAt: iso(concludedAt) }),
  });
  // "Now": before, around or long after the deadlines.
  const now = aware + Math.floor((r() * 120 - 5) * DAY);
  return { inc, zone, now };
}

const comparable = (d: Deadline | OracleDeadline): OracleDeadline => ({
  kind: d.kind,
  ...(d.requestId === undefined ? {} : { requestId: d.requestId }),
  ...(d.dueAt === undefined ? {} : { dueAt: d.dueAt }),
  provisional: d.provisional,
  ...(d.submittedAt === undefined ? {} : { submittedAt: d.submittedAt }),
  state: d.state,
});

const CASES = 20_000;

describe('deadlines agree with an independent oracle', () => {
  it(`${String(CASES)} generated incidents across DST changes, month ends and leap days`, () => {
    const disagreements: string[] = [];
    for (let seed = 1; seed <= CASES; seed++) {
      const { inc, zone, now } = generate(seed);
      const impl = computeDeadlines(inc, zone, now).filter((d) => d.kind !== 'recipients').map(comparable);
      const want = oracleDeadlines(inc, zone, now).map(comparable);
      const key = (d: OracleDeadline): string => `${d.kind}${d.requestId ?? ''}`;
      const sort = (xs: OracleDeadline[]): OracleDeadline[] => [...xs].sort((a, b) => key(a).localeCompare(key(b)));
      if (JSON.stringify(sort(impl)) !== JSON.stringify(sort(want))) {
        disagreements.push(`seed ${String(seed)} ${zone} now=${new Date(now).toISOString()}\n  incident=${JSON.stringify({ awareAt: inc.awareAt, serviceTypes: inc.serviceTypes, details: inc.details, handlingConcludedAt: inc.handlingConcludedAt, submissions: inc.submissions.map((s) => [s.stage, s.submittedAt]), requests: inc.intermediateRequests })}\n  impl=${JSON.stringify(sort(impl))}\n  want=${JSON.stringify(sort(want))}`);
      }
    }
    expect(disagreements.slice(0, 5).join('\n\n')).toBe('');
    expect(disagreements.length).toBe(0);
  });

  it('the generator reaches the edge cases it is meant to', () => {
    let nearTransition = 0;
    let trust24 = 0;
    let progress = 0;
    let overdue = 0;
    let missed = 0;
    let corrected = 0;
    for (let seed = 1; seed <= CASES; seed++) {
      const { inc, zone, now } = generate(seed);
      const aware = Date.parse(inc.awareAt ?? '');
      const ts = TRANSITIONS.get(zone) ?? [];
      if (ts.some((t) => [24 * HOUR, 72 * HOUR].some((h) => Math.abs(aware + h - t) < 3 * HOUR))) nearTransition++;
      const ds = computeDeadlines(inc, zone, now);
      const notif = ds.find((d) => d.kind === 'incident-notification');
      if (notif?.dueAt !== undefined && Date.parse(notif.dueAt) - aware === 24 * HOUR) trust24++;
      if (ds.some((d) => d.kind === 'progress-report')) progress++;
      if (ds.some((d) => d.state === 'overdue' || d.state === 'late')) overdue++;
      if (ds.some((d) => d.state === 'missed')) missed++;
      if (inc.submissions.some((s) => Date.parse(s.submittedAt) < aware)) corrected++;
    }
    expect(nearTransition).toBeGreaterThan(300);
    expect(trust24).toBeGreaterThan(300);
    expect(progress).toBeGreaterThan(100);
    expect(overdue).toBeGreaterThan(1000);
    expect(missed).toBeGreaterThan(50);
    expect(corrected).toBeGreaterThan(200);
  });
});

describe('oracle calendar arithmetic (checked by hand)', () => {
  it('one calendar month: month ends, leap years, DST gaps and repeats', () => {
    // 31 January 10:00 Vilnius (EET) -> 28 February 10:00 (2027) / 29 February (2028).
    expect(plusOneMonth('2027-01-31T08:00:00.000Z', 'Europe/Vilnius')).toBe('2027-02-28T08:00:00.000Z');
    expect(plusOneMonth('2028-01-31T08:00:00.000Z', 'Europe/Vilnius')).toBe('2028-02-29T08:00:00.000Z');
    // 28 February 03:30 EET -> 28 March 03:30, which Vilnius skips (03:00 -> 04:00 on 28 March 2027):
    // read with the offset after the change (EEST, +3) = 00:30 UTC.
    expect(plusOneMonth('2027-02-28T01:30:00.000Z', 'Europe/Vilnius')).toBe('2027-03-28T00:30:00.000Z');
    // 25 October 2026 03:30 happens twice in Vilnius (04:00 EEST -> 03:00 EET); from 25 September 03:30 EEST
    // the first occurrence (EEST, +3) = 00:30 UTC.
    expect(plusOneMonth('2026-09-25T00:30:00.000Z', 'Europe/Vilnius')).toBe('2026-10-25T00:30:00.000Z');
  });
});
