// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { describe, expect, it } from 'vitest';
import { computeDeadlines, pendingDeadlines, trustServiceDerogationApplies, type Deadline } from '../src/stages/deadlines.js';
import { assertCanSubmit, assertTimeline, nextStages } from '../src/stages/machine.js';
import { formatInZone } from '../src/time/zone.js';
import { incident, MS, sub } from './helpers.js';

const Z = 'Europe/Vilnius';
const AWARE = '2026-01-10T08:00:00.000Z'; // 10:00 local (EET)

function byKind(ds: readonly Deadline[], kind: Deadline['kind']): Deadline {
  const d = ds.find((x) => x.kind === kind);
  if (d === undefined) throw new Error(`no ${kind}`);
  return d;
}

describe('computeDeadlines', () => {
  it('has no deadlines before awareness is recorded', () => {
    expect(computeDeadlines(incident(), Z, MS(AWARE))).toEqual([]);
  });

  it('early warning 24 h and notification 72 h after becoming aware (Art 23(4)(a),(b))', () => {
    const ds = computeDeadlines(incident({ awareAt: AWARE }), Z, MS(AWARE));
    expect(byKind(ds, 'early-warning').dueAt).toBe('2026-01-11T08:00:00.000Z');
    expect(byKind(ds, 'early-warning').ref.provision).toBe('Article 23(4), point (a)');
    expect(byKind(ds, 'incident-notification').dueAt).toBe('2026-01-13T08:00:00.000Z');
    expect(byKind(ds, 'incident-notification').ref.provision).toBe('Article 23(4), point (b)');
  });

  it('deadline boundary: exactly at the deadline is on time, one millisecond later is late/overdue', () => {
    const due = '2026-01-11T08:00:00.000Z';
    const onTime = computeDeadlines(incident({ awareAt: AWARE, submissions: [sub('early-warning', due)] }), Z, MS(due) + 5);
    expect(byKind(onTime, 'early-warning').state).toBe('met');
    const late = computeDeadlines(incident({ awareAt: AWARE, submissions: [sub('early-warning', '2026-01-11T08:00:00.001Z')] }), Z, MS(due) + 5);
    expect(byKind(late, 'early-warning').state).toBe('late');
    expect(byKind(computeDeadlines(incident({ awareAt: AWARE }), Z, MS(due)), 'early-warning').state).toBe('open');
    expect(byKind(computeDeadlines(incident({ awareAt: AWARE }), Z, MS(due) + 1), 'early-warning').state).toBe('overdue');
  });

  it('trust service provider: incident notification within 24 hours (Art 23(4) last subparagraph)', () => {
    const yes = incident({ awareAt: AWARE, serviceTypes: ['trust-service'], details: { trustServicesImpacted: 'yes' } });
    const d = byKind(computeDeadlines(yes, Z, MS(AWARE)), 'incident-notification');
    expect(d.dueAt).toBe('2026-01-11T08:00:00.000Z');
    expect(d.ref.provision).toBe('Article 23(4), last subparagraph');
    expect(trustServiceDerogationApplies(yes)).toBe(true);
  });

  it('trust service provider with unknown impact uses the earlier 24 h deadline; "no" uses 72 h', () => {
    const unknown = incident({ awareAt: AWARE, serviceTypes: ['trust-service'] });
    expect(byKind(computeDeadlines(unknown, Z, 0), 'incident-notification').dueAt).toBe('2026-01-11T08:00:00.000Z');
    expect(byKind(computeDeadlines(unknown, Z, 0), 'incident-notification').basis).toMatch(/not confirmed/u);
    const no = incident({ awareAt: AWARE, serviceTypes: ['trust-service', 'cloud'], details: { trustServicesImpacted: 'no' } });
    expect(byKind(computeDeadlines(no, Z, 0), 'incident-notification').dueAt).toBe('2026-01-13T08:00:00.000Z');
  });

  it('24 h deadline across the spring DST change keeps elapsed time', () => {
    const aware = '2026-03-28T10:00:00.000Z'; // 12:00 EET
    const ew = byKind(computeDeadlines(incident({ awareAt: aware }), Z, 0), 'early-warning');
    expect(ew.dueAt).toBe('2026-03-29T10:00:00.000Z');
    expect(formatInZone(ew.dueAt ?? '', Z)).toBe('2026-03-29 13:00 (UTC+03:00)');
  });

  it('72 h deadline across the autumn DST change keeps elapsed time', () => {
    const aware = '2026-10-23T21:00:00.000Z'; // 24 Oct 00:00 EEST
    const n = byKind(computeDeadlines(incident({ awareAt: aware }), Z, 0), 'incident-notification');
    expect(n.dueAt).toBe('2026-10-26T21:00:00.000Z');
    expect(formatInZone(n.dueAt ?? '', Z)).toBe('2026-10-26 23:00 (UTC+02:00)');
  });

  it('final report: one month after the notification was submitted (Art 23(4)(d))', () => {
    const inc = incident({
      awareAt: AWARE,
      submissions: [sub('early-warning', '2026-01-10T09:00:00.000Z'), sub('incident-notification', '2027-01-31T08:00:00.000Z')],
      handlingConcludedAt: '2027-02-01T08:00:00.000Z',
    });
    const f = byKind(computeDeadlines(inc, Z, MS('2027-02-02T00:00:00.000Z')), 'final-report');
    expect(formatInZone(f.dueAt ?? '', Z)).toBe('2027-02-28 10:00 (UTC+02:00)');
    expect(f.provisional).toBe(false);
  });

  it('final report is an estimate while the notification has not been submitted', () => {
    const f = byKind(computeDeadlines(incident({ awareAt: AWARE }), Z, MS(AWARE)), 'final-report');
    expect(f.provisional).toBe(true);
    expect(f.dueAt).toBe('2026-02-13T08:00:00.000Z'); // notification deadline + 1 month
    expect(f.basis).toMatch(/progress report is due instead/u);
  });

  it('still ongoing after the final-report deadline: progress report then, final one month after handling concludes (Art 23(4)(e))', () => {
    const base = { awareAt: AWARE, submissions: [sub('early-warning', AWARE), sub('incident-notification', '2026-01-12T08:00:00.000Z')] };
    const afterDue = MS('2026-02-12T08:00:00.001Z');
    const ds = computeDeadlines(incident(base), Z, afterDue);
    expect(byKind(ds, 'progress-report').dueAt).toBe('2026-02-12T08:00:00.000Z');
    expect(byKind(ds, 'progress-report').state).toBe('overdue');
    expect(byKind(ds, 'final-report').dueAt).toBeUndefined();
    expect(byKind(ds, 'final-report').state).toBe('open');

    const concludedLater = computeDeadlines(incident({ ...base, handlingConcludedAt: '2026-03-31T08:00:00.000Z' }), Z, afterDue);
    expect(byKind(concludedLater, 'final-report').dueAt).toBe('2026-04-30T08:00:00.000Z'); // 31 Mar 11:00 EEST -> 30 Apr 11:00 EEST
    expect(byKind(concludedLater, 'progress-report').dueAt).toBe('2026-02-12T08:00:00.000Z');
  });

  it('a progress report not sent before handling concluded is recorded as missed', () => {
    const base = { awareAt: AWARE, submissions: [sub('early-warning', AWARE), sub('incident-notification', '2026-01-12T08:00:00.000Z')] };
    const ds = computeDeadlines(incident({ ...base, handlingConcludedAt: '2026-03-01T08:00:00.000Z' }), Z, MS('2026-03-02T00:00:00.000Z'));
    expect(byKind(ds, 'progress-report').state).toBe('missed');
    expect(pendingDeadlines(ds).map((d) => d.kind)).toEqual(['final-report']);
  });

  it('handling concluded before the deadline: no progress report', () => {
    const inc = incident({ awareAt: AWARE, handlingConcludedAt: '2026-01-20T08:00:00.000Z', submissions: [sub('early-warning', AWARE), sub('incident-notification', AWARE)] });
    const ds = computeDeadlines(inc, Z, MS('2026-03-01T00:00:00.000Z'));
    expect(ds.some((d) => d.kind === 'progress-report')).toBe(false);
    expect(byKind(ds, 'final-report').dueAt).toBe('2026-02-10T08:00:00.000Z');
    expect(byKind(ds, 'final-report').state).toBe('overdue');
  });

  it('handling concluded exactly at the final-report deadline counts as concluded (no progress report)', () => {
    const inc = incident({ awareAt: AWARE, handlingConcludedAt: '2026-02-10T08:00:00.000Z', submissions: [sub('early-warning', AWARE), sub('incident-notification', AWARE)] });
    expect(computeDeadlines(inc, Z, MS('2026-03-01T00:00:00.000Z')).some((d) => d.kind === 'progress-report')).toBe(false);
  });

  it('a submitted progress report makes the final report due one month after handling concludes', () => {
    const inc = incident({
      awareAt: AWARE,
      handlingConcludedAt: '2026-02-05T08:00:00.000Z',
      submissions: [sub('early-warning', AWARE), sub('incident-notification', AWARE), sub('progress-report', '2026-02-01T08:00:00.000Z')],
    });
    const ds = computeDeadlines(inc, Z, MS('2026-02-06T00:00:00.000Z'));
    expect(byKind(ds, 'progress-report').state).toBe('met');
    expect(byKind(ds, 'final-report').dueAt).toBe('2026-03-05T08:00:00.000Z');
  });

  it('intermediate reports: on request; deadline only when the request sets one (Art 23(4)(c))', () => {
    const inc = incident({
      awareAt: AWARE,
      intermediateRequests: [
        { id: 'R-1', requestedAt: '2026-01-11T08:00:00.000Z' },
        { id: 'R-2', requestedAt: '2026-01-12T08:00:00.000Z', dueAt: '2026-01-14T08:00:00.000Z' },
      ],
    });
    const ds = computeDeadlines(inc, Z, MS('2026-01-15T00:00:00.000Z')).filter((d) => d.kind === 'intermediate-report');
    expect(ds.map((d) => [d.requestId, d.dueAt, d.state])).toEqual([
      ['R-1', undefined, 'open'],
      ['R-2', '2026-01-14T08:00:00.000Z', 'overdue'],
    ]);
  });

  it('reminds to notify recipients without a fixed deadline (Art 23(1))', () => {
    const inc = incident({ awareAt: AWARE, details: { recipientsLikelyAffected: 'yes' } });
    const r = byKind(computeDeadlines(inc, Z, MS(AWARE)), 'recipients');
    expect(r.dueAt).toBeUndefined();
    expect(r.state).toBe('open');
    const done = incident({
      awareAt: AWARE,
      details: { recipientsLikelyAffected: 'yes' },
      recipientCommunications: [{ id: 'C-1', kind: 'incident-23-1', communicatedAt: AWARE, audience: 'Customers', summary: 'x' }],
    });
    expect(byKind(computeDeadlines(done, Z, MS(AWARE)), 'recipients').state).toBe('met');
  });

  it('pendingDeadlines sorts by date, undated last, and drops completed ones', () => {
    const inc = incident({ awareAt: AWARE, submissions: [sub('early-warning', AWARE)], intermediateRequests: [{ id: 'R-1', requestedAt: AWARE }] });
    const p = pendingDeadlines(computeDeadlines(inc, Z, MS(AWARE)));
    expect(p.map((d) => d.kind)).toEqual(['incident-notification', 'final-report', 'intermediate-report']);
  });
});

describe('stage machine', () => {
  const now = MS('2026-03-01T00:00:00.000Z');
  const ew = sub('early-warning', '2026-01-10T09:00:00.000Z');
  const notif = sub('incident-notification', '2026-01-11T09:00:00.000Z');

  it('requires awareness first', () => {
    expect(() => assertCanSubmit(incident(), 'early-warning', AWARE, now)).toThrow(/aware/u);
  });

  it('enforces early warning -> notification -> final order', () => {
    const inc = incident({ awareAt: AWARE });
    expect(() => assertCanSubmit(inc, 'incident-notification', AWARE, now)).toThrow(/early warning first/u);
    expect(() => assertCanSubmit(inc, 'final-report', AWARE, now)).toThrow(/notification first/u);
    expect(() => assertCanSubmit(inc, 'progress-report', AWARE, now)).toThrow(/notification first/u);
    expect(() => assertCanSubmit(inc, 'early-warning', AWARE, now)).not.toThrow();
    const withEw = incident({ awareAt: AWARE, submissions: [ew] });
    expect(() => assertCanSubmit(withEw, 'incident-notification', '2026-01-10T08:59:00.000Z', now)).toThrow(/cannot precede/u);
    expect(() => assertCanSubmit(withEw, 'incident-notification', ew.submittedAt, now)).not.toThrow();
    expect(() => assertCanSubmit(withEw, 'early-warning', AWARE, now)).toThrow(/already/u);
  });

  it('final report needs concluded handling; progress report needs an ongoing incident', () => {
    const ongoing = incident({ awareAt: AWARE, submissions: [ew, notif] });
    expect(() => assertCanSubmit(ongoing, 'final-report', '2026-02-01T00:00:00.000Z', now)).toThrow(/ongoing/u);
    expect(() => assertCanSubmit(ongoing, 'progress-report', '2026-02-01T00:00:00.000Z', now)).not.toThrow();
    const concluded = incident({ awareAt: AWARE, submissions: [ew, notif], handlingConcludedAt: '2026-01-20T00:00:00.000Z' });
    expect(() => assertCanSubmit(concluded, 'final-report', '2026-02-01T00:00:00.000Z', now)).not.toThrow();
    expect(() => assertCanSubmit(concluded, 'final-report', '2026-01-19T00:00:00.000Z', now)).toThrow(/ongoing/u);
    expect(() => assertCanSubmit(concluded, 'progress-report', '2026-02-01T00:00:00.000Z', now)).toThrow(/final report instead/u);
  });

  it('closes the incident after the final report', () => {
    const closed = incident({ awareAt: AWARE, submissions: [ew, notif, sub('final-report', '2026-02-01T00:00:00.000Z')], handlingConcludedAt: '2026-01-20T00:00:00.000Z' });
    expect(() => assertCanSubmit(closed, 'progress-report', '2026-02-02T00:00:00.000Z', now)).toThrow(/closed/u);
    expect(nextStages(closed)).toEqual([]);
  });

  it('intermediate report answers an open request and cannot precede it', () => {
    const inc = incident({ awareAt: AWARE, submissions: [ew], intermediateRequests: [{ id: 'R-1', requestedAt: '2026-01-12T00:00:00.000Z' }] });
    expect(() => assertCanSubmit(inc, 'intermediate-report', '2026-01-13T00:00:00.000Z', now)).toThrow(/request id/u);
    expect(() => assertCanSubmit(inc, 'intermediate-report', '2026-01-13T00:00:00.000Z', now, 'R-9')).toThrow(/No intermediate/u);
    expect(() => assertCanSubmit(inc, 'intermediate-report', '2026-01-11T00:00:00.000Z', now, 'R-1')).toThrow(/cannot precede/u);
    expect(() => assertCanSubmit(inc, 'intermediate-report', '2026-01-13T00:00:00.000Z', now, 'R-1')).not.toThrow();
  });

  it('refuses future submission times beyond a 5-minute clock tolerance', () => {
    const inc = incident({ awareAt: AWARE });
    expect(() => assertCanSubmit(inc, 'early-warning', new Date(now + 6 * 60_000).toISOString(), now)).toThrow(/future/u);
    expect(() => assertCanSubmit(inc, 'early-warning', new Date(now + 4 * 60_000).toISOString(), now)).not.toThrow();
  });

  it('checks timeline consistency', () => {
    expect(() => assertTimeline({ occurredAt: '2026-01-02T00:00:00.000Z', detectedAt: '2026-01-01T00:00:00.000Z' }, now)).toThrow(/Detection/u);
    expect(() => assertTimeline({ detectedAt: '2026-01-02T00:00:00.000Z', awareAt: '2026-01-01T00:00:00.000Z' }, now)).toThrow(/Awareness/u);
    expect(() => assertTimeline({ occurredAt: '2026-01-02T00:00:00.000Z', awareAt: '2026-01-01T00:00:00.000Z' }, now)).toThrow(/Awareness/u);
    expect(() => assertTimeline({ occurredAt: '2026-01-02T00:00:00.000Z', handlingConcludedAt: '2026-01-01T00:00:00.000Z' }, now)).toThrow(/Handling/u);
    expect(() => assertTimeline({ awareAt: '2027-01-01T00:00:00.000Z' }, now)).toThrow(/future/u);
    expect(() => assertTimeline({ occurredAt: '2026-01-01T00:00:00.000Z', detectedAt: '2026-01-01T00:00:00.000Z', awareAt: '2026-01-01T00:00:00.000Z' }, now)).not.toThrow();
  });

  it('suggests next stages', () => {
    expect(nextStages(incident())).toEqual([]);
    expect(nextStages(incident({ awareAt: AWARE }))).toEqual(['early-warning']);
    expect(nextStages(incident({ awareAt: AWARE, submissions: [ew] }))).toEqual(['incident-notification']);
    expect(nextStages(incident({ awareAt: AWARE, submissions: [ew, notif], intermediateRequests: [{ id: 'R-1', requestedAt: AWARE }] }))).toEqual(['intermediate-report', 'progress-report']);
    expect(nextStages(incident({ awareAt: AWARE, submissions: [ew, notif], handlingConcludedAt: AWARE }))).toEqual(['final-report']);
  });
});
