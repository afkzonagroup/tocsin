// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * An independent deadline calculator, used only in tests. It is written from Article 23(4) NIS2 and the
 * readings in LEGAL.md ("How Tocsin counts"), not from src/stages or src/time, and uses its own calendar
 * arithmetic built on Intl. Property tests compare it with computeDeadlines over generated incidents.
 */

import type { Incident } from '../../src/model/types.js';

export interface OracleDeadline {
  readonly kind: string;
  readonly requestId?: string;
  readonly dueAt?: string;
  readonly provisional: boolean;
  readonly submittedAt?: string;
  readonly state: 'open' | 'overdue' | 'met' | 'late' | 'missed';
}

const HOUR = 3_600_000;
const ms = (iso: string): number => Date.parse(iso);
const iso = (t: number): string => new Date(t).toISOString();

// ---- Wall-clock arithmetic in an IANA zone -------------------------------------------------------

interface Wall {
  y: number;
  mo: number; // 1-12
  d: number;
  h: number;
  mi: number;
  s: number;
  ms: number;
}

const formatters = new Map<string, Intl.DateTimeFormat>();
function fmt(zone: string): Intl.DateTimeFormat {
  let f = formatters.get(zone);
  if (f === undefined) {
    f = new Intl.DateTimeFormat('en-GB', {
      timeZone: zone,
      hourCycle: 'h23',
      year: 'numeric',
      month: 'numeric',
      day: 'numeric',
      hour: 'numeric',
      minute: 'numeric',
      second: 'numeric',
    });
    formatters.set(zone, f);
  }
  return f;
}

/** Local wall clock of an instant. */
export function wallOf(t: number, zone: string): Wall {
  const parts: Record<string, number> = {};
  for (const p of fmt(zone).formatToParts(new Date(t))) if (p.type !== 'literal') parts[p.type] = Number(p.value);
  const milli = ((t % 1000) + 1000) % 1000;
  const at = (k: string): number => parts[k] ?? 0;
  return { y: at('year'), mo: at('month'), d: at('day'), h: at('hour'), mi: at('minute'), s: at('second'), ms: milli };
}

/** The wall clock read as if it were UTC (a "local epoch"). */
const localEpoch = (w: Wall): number => Date.UTC(w.y, w.mo - 1, w.d, w.h, w.mi, w.s, w.ms);
/** UTC offset in force at an instant, in ms. */
const offsetAt = (t: number, zone: string): number => localEpoch(wallOf(t, zone)) - t;

/**
 * The instant of a wall-clock time. Repeated times (clocks go back): the first occurrence.
 * Skipped times (clocks go forward): read with the offset in force after the change (LEGAL.md, reading 3).
 */
export function instantOf(w: Wall, zone: string): number {
  const local = localEpoch(w);
  const offsets = new Set<number>();
  for (const probe of [-48, -24, -12, -6, -3, 0, 3, 6, 12, 24, 48]) offsets.add(offsetAt(local + probe * HOUR, zone));
  const hits = [...offsets].map((o) => local - o).filter((t) => localEpoch(wallOf(t, zone)) === local);
  if (hits.length > 0) return Math.min(...hits);
  return local - offsetAt(local + 48 * HOUR, zone);
}

const daysInMonth = (y: number, mo: number): number => new Date(Date.UTC(y, mo, 0)).getUTCDate();

/** Same day and wall-clock time one calendar month later; last day of the month when the day does not exist. */
export function plusOneMonth(at: string, zone: string): string {
  const w = wallOf(ms(at), zone);
  const mo = w.mo === 12 ? 1 : w.mo + 1;
  const y = w.mo === 12 ? w.y + 1 : w.y;
  return iso(instantOf({ ...w, y, mo, d: Math.min(w.d, daysInMonth(y, mo)) }, zone));
}

// ---- Article 23(4) -------------------------------------------------------------------------------

function stateOf(dueAt: string | undefined, submittedAt: string | undefined, now: number): OracleDeadline['state'] {
  if (submittedAt !== undefined) return dueAt !== undefined && ms(submittedAt) > ms(dueAt) ? 'late' : 'met';
  if (dueAt !== undefined && now > ms(dueAt)) return 'overdue';
  return 'open';
}

function deadline(kind: string, dueAt: string | undefined, provisional: boolean, submittedAt: string | undefined, now: number, extra: { requestId?: string } = {}): OracleDeadline {
  return {
    kind,
    ...extra,
    ...(dueAt === undefined ? {} : { dueAt }),
    provisional,
    ...(submittedAt === undefined ? {} : { submittedAt }),
    state: stateOf(dueAt, submittedAt, now),
  };
}

export function oracleDeadlines(i: Incident, zone: string, now: number): OracleDeadline[] {
  if (i.awareAt === undefined) return [];
  const aware = ms(i.awareAt);
  const submitted = (stage: string): string | undefined => i.submissions.find((s) => s.stage === stage)?.submittedAt;
  const out: OracleDeadline[] = [];

  // (a) early warning: aware + 24 h of elapsed time.
  out.push(deadline('early-warning', iso(aware + 24 * HOUR), false, submitted('early-warning'), now));

  // (b) incident notification: aware + 72 h; 24 h for a trust service provider unless the incident
  // does not affect its trust services (an unanswered question counts as affecting them).
  const trust = i.serviceTypes.includes('trust-service') && i.details.trustServicesImpacted !== 'no';
  const notificationDue = iso(aware + (trust ? 24 : 72) * HOUR);
  const notified = submitted('incident-notification');
  out.push(deadline('incident-notification', notificationDue, false, notified, now));

  // (c) intermediate reports: on request, due only when the request sets a date.
  for (const r of i.intermediateRequests) {
    out.push(deadline('intermediate-report', r.dueAt, false, r.submission?.submittedAt, now, { requestId: r.id }));
  }

  // (d) final report: one calendar month after the notification is submitted; before that, estimated
  // from the notification deadline.
  const finalByD = notified === undefined ? plusOneMonth(notificationDue, zone) : plusOneMonth(notified, zone);
  const finalProvisional = notified === undefined;
  const finalSubmitted = submitted('final-report');
  const progressSubmitted = submitted('progress-report');
  const concluded = i.handlingConcludedAt;

  // (e) still ongoing at the point (d) deadline (or a progress report was sent): progress report due at
  // the point (d) date, final report one month after handling concluded.
  const ongoingAtD = concluded === undefined ? now > ms(finalByD) : ms(concluded) > ms(finalByD);
  if (progressSubmitted !== undefined || ongoingAtD) {
    const progress = deadline('progress-report', finalByD, finalProvisional, progressSubmitted, now);
    const missed = progressSubmitted === undefined && concluded !== undefined && progress.state === 'overdue';
    out.push(missed ? { ...progress, state: 'missed' } : progress);
    const finalDue = concluded === undefined ? undefined : plusOneMonth(concluded, zone);
    // No date yet (handling has not concluded): nothing to estimate, so not provisional.
    out.push(deadline('final-report', finalDue, false, finalSubmitted, now));
  } else {
    out.push(deadline('final-report', finalByD, finalProvisional, finalSubmitted, now));
  }
  return out;
}
