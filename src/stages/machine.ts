// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { TocsinError } from '../util/errors.js';
import type { Incident, IntermediateRequest, Stage } from '../model/types.js';
import { toMs } from '../time/zone.js';
import { submissionOf } from './deadlines.js';

/**
 * Stage machine: early warning → incident notification → intermediate report(s) on request →
 * progress report (only if still ongoing at the final-report deadline) → final report.
 *
 * The machine checks order and preconditions of recorded submissions. It does not decide whether an
 * incident is significant; recording the awareness time is the user's statement that it is.
 */

/** Allowed clock skew when a submission time is "now". */
export const FUTURE_TOLERANCE_MS = 5 * 60_000;

function fail(code: 'STAGE_ORDER' | 'CONFLICT', msg: string): never {
  throw new TocsinError(code, msg);
}

function notAfter(a: string, b: string): boolean {
  return toMs(a) <= toMs(b);
}

export function isClosed(i: Incident): boolean {
  return submissionOf(i, 'final-report') !== undefined;
}

export function openRequest(i: Incident, requestId: string): IntermediateRequest {
  const r = i.intermediateRequests.find((x) => x.id === requestId);
  if (r === undefined) throw new TocsinError('NOT_FOUND', `No intermediate-report request ${requestId} on ${i.id}.`);
  if (r.submission !== undefined) fail('CONFLICT', `Intermediate report for request ${requestId} was already submitted.`);
  return r;
}

/**
 * Throws STAGE_ORDER / CONFLICT when `stage` cannot be recorded as submitted at `at`.
 * @param requestId required for "intermediate-report".
 */
export function assertCanSubmit(i: Incident, stage: Stage, at: string, now: number, requestId?: string): void {
  if (i.awareAt === undefined) fail('STAGE_ORDER', 'Record when the entity became aware of the significant incident first.');
  if (toMs(at) > now + FUTURE_TOLERANCE_MS) fail('STAGE_ORDER', 'A submission time cannot be in the future.');
  if (isClosed(i)) fail('CONFLICT', `The final report for ${i.id} was already submitted; the incident is closed.`);
  const ew = submissionOf(i, 'early-warning');
  const notif = submissionOf(i, 'incident-notification');
  switch (stage) {
    case 'early-warning':
      if (ew !== undefined) fail('CONFLICT', 'The early warning was already submitted.');
      return;
    case 'incident-notification':
      if (notif !== undefined) fail('CONFLICT', 'The incident notification was already submitted.');
      if (ew === undefined) fail('STAGE_ORDER', 'Submit the early warning first (it may carry the same time when both are sent together).');
      if (!notAfter(ew.submittedAt, at)) fail('STAGE_ORDER', 'The incident notification cannot precede the early warning.');
      return;
    case 'intermediate-report': {
      if (requestId === undefined) fail('STAGE_ORDER', 'An intermediate report answers a request: give the request id.');
      const r = openRequest(i, requestId);
      if (ew === undefined) fail('STAGE_ORDER', 'Submit the early warning first.');
      if (!notAfter(r.requestedAt, at)) fail('STAGE_ORDER', 'The intermediate report cannot precede the request.');
      return;
    }
    case 'progress-report':
      if (submissionOf(i, 'progress-report') !== undefined) fail('CONFLICT', 'The progress report was already submitted.');
      if (notif === undefined) fail('STAGE_ORDER', 'Submit the incident notification first.');
      if (!notAfter(notif.submittedAt, at)) fail('STAGE_ORDER', 'The progress report cannot precede the incident notification.');
      if (i.handlingConcludedAt !== undefined && notAfter(i.handlingConcludedAt, at)) {
        fail('STAGE_ORDER', 'Handling has concluded: submit the final report instead of a progress report.');
      }
      return;
    case 'final-report':
      if (notif === undefined) fail('STAGE_ORDER', 'Submit the incident notification first.');
      if (!notAfter(notif.submittedAt, at)) fail('STAGE_ORDER', 'The final report cannot precede the incident notification.');
      if (i.handlingConcludedAt === undefined || !notAfter(i.handlingConcludedAt, at)) {
        fail('STAGE_ORDER', 'The incident is still ongoing at that time: record when handling concluded, or submit a progress report (Art 23(4)(e)).');
      }
      return;
  }
}

/** Throws when the timeline would be inconsistent (occurred ≤ detected ≤ aware; occurred ≤ concluded). */
export function assertTimeline(i: Pick<Incident, 'occurredAt' | 'detectedAt' | 'awareAt' | 'handlingConcludedAt'>, now: number): void {
  const { occurredAt, detectedAt, awareAt, handlingConcludedAt } = i;
  for (const [name, v] of [
    ['occurred', occurredAt],
    ['detected', detectedAt],
    ['aware', awareAt],
    ['handling concluded', handlingConcludedAt],
  ] as const) {
    if (v !== undefined && toMs(v) > now + FUTURE_TOLERANCE_MS) fail('STAGE_ORDER', `The ${name} time cannot be in the future.`);
  }
  if (occurredAt !== undefined && detectedAt !== undefined && !notAfter(occurredAt, detectedAt)) fail('STAGE_ORDER', 'Detection cannot precede occurrence.');
  if (detectedAt !== undefined && awareAt !== undefined && !notAfter(detectedAt, awareAt)) fail('STAGE_ORDER', 'Awareness of a significant incident cannot precede its detection.');
  if (occurredAt !== undefined && awareAt !== undefined && !notAfter(occurredAt, awareAt)) fail('STAGE_ORDER', 'Awareness cannot precede occurrence.');
  if (occurredAt !== undefined && handlingConcludedAt !== undefined && !notAfter(occurredAt, handlingConcludedAt)) fail('STAGE_ORDER', 'Handling cannot conclude before the incident occurred.');
}

/** Stages that can be prepared next, in order. */
export function nextStages(i: Incident): Stage[] {
  if (i.awareAt === undefined || isClosed(i)) return [];
  const out: Stage[] = [];
  const ew = submissionOf(i, 'early-warning');
  const notif = submissionOf(i, 'incident-notification');
  if (ew === undefined) return ['early-warning'];
  if (notif === undefined) return ['incident-notification'];
  if (i.intermediateRequests.some((r) => r.submission === undefined)) out.push('intermediate-report');
  if (i.handlingConcludedAt === undefined && submissionOf(i, 'progress-report') === undefined) out.push('progress-report');
  if (i.handlingConcludedAt !== undefined) out.push('final-report');
  return out;
}
