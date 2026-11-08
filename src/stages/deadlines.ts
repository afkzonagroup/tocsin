// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { ref, type LegalRef } from '../legal/refs.js';
import type { Incident, Stage, Submission } from '../model/types.js';
import { addCalendarMonths, addHours } from '../time/periods.js';
import { toMs } from '../time/zone.js';

/**
 * Article 23(4) NIS2 deadlines.
 *
 * | Stage | Deadline | Provision |
 * |---|---|---|
 * | Early warning | 24 h after becoming aware | Art 23(4)(a) |
 * | Incident notification | 72 h after becoming aware (24 h for trust service providers, for incidents impacting their trust services) | Art 23(4)(b) and last subparagraph |
 * | Intermediate report | on request; no deadline in the Directive (the request may set one) | Art 23(4)(c) |
 * | Final report | one month after the incident notification was submitted | Art 23(4)(d) |
 * | Progress report | at the final-report deadline, if the incident is still ongoing | Art 23(4)(e) |
 * | Final report (ongoing case) | one month after handling of the incident concluded | Art 23(4)(e) |
 *
 * "Without undue delay" applies to every stage; the deadlines are outer limits.
 */

export type DeadlineKind = Stage | 'recipients';

export type DeadlineState =
  /** Not submitted, not yet due (or no fixed date). */
  | 'open'
  /** Not submitted and the deadline has passed. */
  | 'overdue'
  /** Submitted on or before the deadline. */
  | 'met'
  /** Submitted after the deadline. */
  | 'late'
  /** Not submitted, the deadline passed, and the stage can no longer be submitted (progress report after handling concluded). */
  | 'missed';

export interface Deadline {
  readonly kind: DeadlineKind;
  readonly requestId?: string;
  /** UTC ISO deadline; absent when the law sets none (or it cannot be known yet). */
  readonly dueAt?: string;
  /** True when the date is an estimate because an earlier event has not happened yet. */
  readonly provisional: boolean;
  readonly basis: string;
  readonly ref: LegalRef;
  readonly submittedAt?: string;
  readonly state: DeadlineState;
}

const NIS2 = (p: string): LegalRef => ref('NIS2', p);

/** Whether the 24-hour incident notification for trust service providers applies. Unknown answers count as yes (earlier deadline). */
export function trustServiceDerogationApplies(i: Incident): boolean {
  return i.serviceTypes.includes('trust-service') && i.details.trustServicesImpacted !== 'no';
}

export function submissionOf(i: Incident, stage: Submission['stage']): Submission | undefined {
  return i.submissions.find((s) => s.stage === stage);
}

function state(dueAt: string | undefined, submittedAt: string | undefined, now: number): DeadlineState {
  if (submittedAt !== undefined) return dueAt !== undefined && toMs(submittedAt) > toMs(dueAt) ? 'late' : 'met';
  if (dueAt !== undefined && now > toMs(dueAt)) return 'overdue';
  return 'open';
}

function mk(d: Omit<Deadline, 'state'>, now: number): Deadline {
  return { ...d, state: state(d.dueAt, d.submittedAt, now) };
}

function opt<K extends string, V>(key: K, v: V | undefined): Partial<Record<K, V>> {
  return v === undefined ? {} : ({ [key]: v } as Record<K, V>);
}

/** Final-report and progress-report deadlines (Art 23(4)(d) and (e)). Exported for testing. */
export function finalAndProgress(i: Incident, zone: string, notificationDue: string, now: number): Deadline[] {
  const notif = submissionOf(i, 'incident-notification');
  const finalSub = submissionOf(i, 'final-report');
  const progressSub = submissionOf(i, 'progress-report');
  const base = notif?.submittedAt ?? notificationDue;
  const provisionalBase = notif === undefined;
  const originalFinalDue = addCalendarMonths(base, 1, zone);
  const concluded = i.handlingConcludedAt;
  const ongoingAtOriginal = concluded === undefined || toMs(concluded) > toMs(originalFinalDue);
  const out: Deadline[] = [];

  // Before the final-report deadline nobody knows yet whether the incident will still be ongoing then:
  // show the final report, with the progress-report rule in the basis.
  const undecided = progressSub === undefined && finalSub === undefined && concluded === undefined && now <= toMs(originalFinalDue);
  if (progressSub === undefined && (!ongoingAtOriginal || undecided)) {
    const basisText = provisionalBase
      ? 'one month after the incident notification (estimated from the notification deadline; notification not yet submitted)'
      : 'one month after the incident notification was submitted';
    out.push(
      mk(
        {
          kind: 'final-report',
          dueAt: originalFinalDue,
          provisional: provisionalBase,
          basis: undecided ? `${basisText}; if the incident is still ongoing then, a progress report is due instead and the final report one month after handling concludes` : basisText,
          ref: NIS2('Article 23(4), point (d)'),
          ...opt('submittedAt', finalSub?.submittedAt),
        },
        now,
      ),
    );
    return out;
  }

  // Ongoing at the final-report deadline (or a progress report was already sent): progress report, then final.
  const progress = mk(
    {
      kind: 'progress-report',
      dueAt: originalFinalDue,
      provisional: provisionalBase,
      basis: 'incident still ongoing at the final-report deadline: progress report at that time',
      ref: NIS2('Article 23(4), point (e)'),
      ...opt('submittedAt', progressSub?.submittedAt),
    },
    now,
  );
  // Once handling has concluded a progress report can no longer be sent; an unsent one is recorded as missed.
  out.push(progress.state === 'overdue' && concluded !== undefined ? { ...progress, state: 'missed' } : progress);
  out.push(
    mk(
      {
        kind: 'final-report',
        ...opt('dueAt', concluded === undefined ? undefined : addCalendarMonths(concluded, 1, zone)),
        provisional: false,
        basis:
          concluded === undefined
            ? 'one month after handling of the incident concludes (not concluded yet)'
            : 'one month after handling of the incident concluded',
        ref: NIS2('Article 23(4), point (e)'),
        ...opt('submittedAt', finalSub?.submittedAt),
      },
      now,
    ),
  );
  return out;
}

/**
 * All deadlines of an incident, computed from the recorded awareness time. Empty when awareness of a
 * significant incident has not been recorded.
 *
 * @param zone IANA zone used for calendar-month arithmetic.
 * @param now  Current time in ms (injectable for tests).
 */
export function computeDeadlines(i: Incident, zone: string, now: number = Date.now()): Deadline[] {
  if (i.awareAt === undefined) return [];
  const aware = i.awareAt;
  const ew = submissionOf(i, 'early-warning');
  const notif = submissionOf(i, 'incident-notification');
  const tsp = trustServiceDerogationApplies(i);
  const notificationHours = tsp ? 24 : 72;
  const notificationDue = addHours(aware, notificationHours);
  const out: Deadline[] = [
    mk(
      {
        kind: 'early-warning',
        dueAt: addHours(aware, 24),
        provisional: false,
        basis: 'within 24 hours of becoming aware of the significant incident',
        ref: NIS2('Article 23(4), point (a)'),
        ...opt('submittedAt', ew?.submittedAt),
      },
      now,
    ),
    mk(
      {
        kind: 'incident-notification',
        dueAt: notificationDue,
        provisional: false,
        basis: tsp
          ? `within 24 hours of becoming aware (trust service provider, incident impacting its trust services${i.details.trustServicesImpacted === 'yes' ? '' : ' — impact not confirmed, earlier deadline used'})`
          : 'within 72 hours of becoming aware of the significant incident',
        ref: tsp ? NIS2('Article 23(4), last subparagraph') : NIS2('Article 23(4), point (b)'),
        ...opt('submittedAt', notif?.submittedAt),
      },
      now,
    ),
  ];
  for (const r of i.intermediateRequests) {
    out.push(
      mk(
        {
          kind: 'intermediate-report',
          requestId: r.id,
          ...opt('dueAt', r.dueAt),
          provisional: false,
          basis: r.dueAt === undefined ? 'on request of the CSIRT or competent authority; the request set no date' : 'date set in the request of the CSIRT or competent authority',
          ref: NIS2('Article 23(4), point (c)'),
          ...opt('submittedAt', r.submission?.submittedAt),
        },
        now,
      ),
    );
  }
  out.push(...finalAndProgress(i, zone, notificationDue, now));
  if (i.details.recipientsLikelyAffected === 'yes') {
    const sent = i.recipientCommunications.find((c) => c.kind === 'incident-23-1');
    out.push(
      mk(
        {
          kind: 'recipients',
          provisional: false,
          basis: 'notify recipients of the services without undue delay where appropriate (no fixed deadline)',
          ref: NIS2('Article 23(1), first subparagraph, second sentence'),
          ...opt('submittedAt', sent?.communicatedAt),
        },
        now,
      ),
    );
  }
  return out;
}

/** Deadlines that still need action (open or overdue), soonest first; undated items last. */
export function pendingDeadlines(ds: readonly Deadline[]): Deadline[] {
  return ds
    .filter((d) => d.state === 'open' || d.state === 'overdue')
    .sort((a, b) => (a.dueAt === undefined ? 1 : 0) - (b.dueAt === undefined ? 1 : 0) || (a.dueAt !== undefined && b.dueAt !== undefined ? toMs(a.dueAt) - toMs(b.dueAt) : 0));
}
