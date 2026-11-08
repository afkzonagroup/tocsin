// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { assessSignificance, type AssessmentResult } from '../assess/assess.js';
import { recurringForCollective } from '../assess/recurring.js';
import { appendAudit, type AuditInput } from '../audit/chain.js';
import type { TocsinConfig } from '../model/config.js';
import type { AssessmentAnswers, Incident, IncidentDetails, IntermediateRequest, RecipientCommunication, ServiceType, Stage } from '../model/types.js';
import { LIMITS, validateAnswers, validateCommunication, validateDetails, validateIncident, validateServiceTypes } from '../model/validate.js';
import { buildReport } from '../reports/content.js';
import { assertCanSubmit, assertTimeline, isClosed, openRequest } from '../stages/machine.js';
import { toIso, toMs } from '../time/zone.js';
import { canonicalJson, sha256Canonical } from '../util/canonical-json.js';
import { TocsinError, invalid } from '../util/errors.js';
import { optStr, str } from '../util/validate.js';
import type { StoreData } from '../store/store.js';

/**
 * Pure register operations. Each takes the current data and returns new data with one audit entry
 * appended. Nothing here touches the disk or the clock (the caller passes `now`).
 */

export interface OpContext {
  readonly now: number;
  readonly actor: string;
}

export interface OpResult<T> {
  readonly data: StoreData;
  readonly result: T;
}

/** Copy of `obj` without `key`. */
function without(obj: Record<string, unknown>, key: string): Record<string, unknown> {
  return Object.fromEntries(Object.entries(obj).filter(([k]) => k !== key));
}

function nowIso(ctx: OpContext): string {
  return toIso(ctx.now);
}

export function validateActor(actor: string): string {
  return str(actor, 'actor', { max: 100, min: 1 });
}

function audit(data: StoreData, ctx: OpContext, a: Omit<AuditInput, 'at' | 'actor'>): StoreData['audit'] {
  return appendAudit(data.audit, { ...a, at: nowIso(ctx), actor: validateActor(ctx.actor) });
}

export function findIncident(data: StoreData, id: string): Incident {
  const inc = data.incidents.find((i) => i.id === id);
  if (inc === undefined) throw new TocsinError('NOT_FOUND', `No incident ${id.slice(0, 20)}.`);
  return inc;
}

/** Replaces one incident (re-validated) and appends an audit entry. */
function replace(data: StoreData, ctx: OpContext, next: Incident, action: string, fields: readonly string[], note?: string): StoreData {
  const checked = validateIncident(JSON.parse(canonicalJson({ ...next, updatedAt: nowIso(ctx) })));
  assertTimeline(checked, ctx.now);
  const incidents = data.incidents.map((i) => (i.id === checked.id ? checked : i));
  return {
    ...data,
    incidents,
    audit: audit(data, ctx, { action, target: checked.id, fields, stateSha256: sha256Canonical(checked), ...(note === undefined ? {} : { note }) }),
  };
}

function assertOpen(i: Incident): void {
  if (isClosed(i)) throw new TocsinError('CONFLICT', `${i.id} is closed (final report submitted). Its record can no longer change.`);
}

/** Records that the store was created. */
export function initStore(data: StoreData, ctx: OpContext): StoreData {
  return { ...data, audit: audit(data, ctx, { action: 'store.created', fields: [] }) };
}

export interface NewIncident {
  readonly title: string;
  readonly serviceTypes: readonly ServiceType[];
  readonly occurredAt?: string;
  readonly detectedAt?: string;
  readonly details?: IncidentDetails;
  readonly linkedIncidentIds?: readonly string[];
}

/** Creates an incident with the next id of the current year (INC-YYYY-NNNN). */
export function createIncident(data: StoreData, input: NewIncident, ctx: OpContext): OpResult<Incident> {
  if (data.incidents.length >= LIMITS.incidents) invalid('The register is full.');
  const year = String(new Date(ctx.now).getUTCFullYear());
  const seq = (data.meta.counters[year] ?? 0) + 1;
  if (seq > 999_999) invalid('Too many incidents this year.');
  const id = `INC-${year}-${String(seq).padStart(4, '0')}`;
  const linked = [...new Set(input.linkedIncidentIds ?? [])];
  for (const l of linked) findIncident(data, l);
  const draft: Incident = {
    id,
    title: str(input.title, 'title', LIMITS.title),
    createdAt: nowIso(ctx),
    updatedAt: nowIso(ctx),
    serviceTypes: validateServiceTypes(input.serviceTypes),
    details: validateDetails(input.details ?? {}),
    submissions: [],
    intermediateRequests: [],
    recipientCommunications: [],
    linkedIncidentIds: linked,
    ...(input.occurredAt === undefined ? {} : { occurredAt: input.occurredAt }),
    ...(input.detectedAt === undefined ? {} : { detectedAt: input.detectedAt }),
  };
  const inc = validateIncident(JSON.parse(canonicalJson(draft)));
  assertTimeline(inc, ctx.now);
  const next: StoreData = {
    meta: { ...data.meta, counters: { ...data.meta.counters, [year]: seq } },
    incidents: [...data.incidents, inc],
    audit: audit(data, ctx, { action: 'incident.created', target: id, fields: Object.keys(draft).sort(), stateSha256: sha256Canonical(inc) }),
  };
  return { data: next, result: inc };
}

/** Value `null` clears a field. */
export type DetailsPatch = { readonly [K in keyof IncidentDetails]?: IncidentDetails[K] | null };

/** Updates free-text and structured details. */
export function updateDetails(data: StoreData, id: string, patch: DetailsPatch, ctx: OpContext): OpResult<Incident> {
  const inc = findIncident(data, id);
  assertOpen(inc);
  const entries = Object.entries(patch as Record<string, unknown>).filter(([, v]) => v !== undefined);
  if (entries.length === 0) invalid('Nothing to change.');
  const fields = entries.map(([k]) => `details.${k}`);
  const cleared = new Set(entries.filter(([, v]) => v === null).map(([k]) => k));
  const set = Object.fromEntries(entries.filter(([, v]) => v !== null));
  const merged = Object.fromEntries(Object.entries({ ...inc.details, ...set }).filter(([k]) => !cleared.has(k)));
  const details = validateDetails(merged);
  const data2 = replace(data, ctx, { ...inc, details }, 'incident.updated', fields);
  return { data: data2, result: findIncident(data2, id) };
}

export interface CorePatch {
  readonly title?: string;
  readonly serviceTypes?: readonly ServiceType[];
  readonly occurredAt?: string | null;
  readonly detectedAt?: string | null;
}

/** Updates title, service types, occurrence or detection time. */
export function updateCore(data: StoreData, id: string, patch: CorePatch, ctx: OpContext): OpResult<Incident> {
  const inc = findIncident(data, id);
  assertOpen(inc);
  let next: Record<string, unknown> = { ...inc };
  const fields: string[] = [];
  if (patch.title !== undefined) {
    next['title'] = str(patch.title, 'title', LIMITS.title);
    fields.push('title');
  }
  if (patch.serviceTypes !== undefined) {
    next['serviceTypes'] = validateServiceTypes(patch.serviceTypes);
    fields.push('serviceTypes');
  }
  for (const k of ['occurredAt', 'detectedAt'] as const) {
    const v = patch[k];
    if (v === undefined) continue;
    fields.push(k);
    next = v === null ? without(next, k) : { ...next, [k]: v };
  }
  if (fields.length === 0) invalid('Nothing to change.');
  const data2 = replace(data, ctx, next as unknown as Incident, 'incident.updated', fields);
  return { data: data2, result: findIncident(data2, id) };
}

/**
 * Records when the entity became aware of the significant incident (starts the Article 23(4) clocks).
 * Changing an existing value after a report was submitted requires a reason, which is audited.
 */
export function recordAwareness(data: StoreData, id: string, awareAt: string, ctx: OpContext, reason?: string): OpResult<Incident> {
  const inc = findIncident(data, id);
  assertOpen(inc);
  const why = optStr(reason, 'reason', { max: 500, multiline: true });
  if (inc.awareAt !== undefined && inc.awareAt !== awareAt && inc.submissions.length > 0 && why === undefined) {
    throw new TocsinError('CONFLICT', 'Reports were already submitted on the basis of the recorded awareness time. Give a reason to change it.');
  }
  const data2 = replace(data, ctx, { ...inc, awareAt }, 'incident.aware', ['awareAt'], why);
  return { data: data2, result: findIncident(data2, id) };
}

/** Records that handling concluded (the incident is no longer ongoing). `null` re-opens it. */
export function recordHandlingConcluded(data: StoreData, id: string, at: string | null, ctx: OpContext): OpResult<Incident> {
  const inc = findIncident(data, id);
  assertOpen(inc);
  const next: Record<string, unknown> = at === null ? without({ ...inc }, 'handlingConcludedAt') : { ...inc, handlingConcludedAt: at };
  const data2 = replace(data, ctx, next as unknown as Incident, 'incident.concluded', ['handlingConcludedAt']);
  return { data: data2, result: findIncident(data2, id) };
}

/**
 * Assesses one incident with its stored answers, the configured turnover and, for a collective incident
 * that links other incidents, the recurring-incident check (IR Art 3(1)(f)).
 */
export function assessIncident(all: readonly Incident[], inc: Incident, cfg: Pick<TocsinConfig, 'turnover' | 'timeZone'>): AssessmentResult {
  const turnover = cfg.turnover?.amountCents;
  const recurring = recurringForCollective(all, inc, turnover, cfg.timeZone);
  return assessSignificance({
    serviceTypes: inc.serviceTypes,
    answers: inc.assessment?.answers ?? {},
    ...(turnover === undefined ? {} : { turnoverCents: turnover }),
    ...(recurring === undefined ? {} : { recurring }),
  });
}

/** Runs and stores the significance assessment. */
export function saveAssessment(
  data: StoreData,
  id: string,
  answers: AssessmentAnswers,
  cfg: Pick<TocsinConfig, 'turnover' | 'timeZone'>,
  ctx: OpContext,
): OpResult<{ incident: Incident; assessment: AssessmentResult }> {
  const inc = findIncident(data, id);
  assertOpen(inc);
  const a = validateAnswers(JSON.parse(canonicalJson(answers)));
  const result = assessIncident(data.incidents, { ...inc, assessment: { assessedAt: nowIso(ctx), answers: a, outcome: 'undetermined', metCriteria: [] } }, cfg);
  const next: Incident = { ...inc, assessment: { assessedAt: nowIso(ctx), answers: a, outcome: result.outcome, metCriteria: result.reasons.map((r) => (r.serviceType === undefined ? r.id : `${r.id} (${r.serviceType})`)) } };
  const data2 = replace(data, ctx, next, 'incident.assessed', ['assessment'], `outcome: ${result.outcome}`);
  return { data: data2, result: { incident: findIncident(data2, id), assessment: result } };
}

function nextSubId(prefix: string, existing: readonly { id: string }[]): string {
  const n = existing.length + 1;
  if (n > 9999) invalid('Too many items.');
  return `${prefix}-${n}`;
}

/** Records a request for an intermediate report (Art 23(4)(c)). */
export function addIntermediateRequest(
  data: StoreData,
  id: string,
  input: { requestedAt: string; requestedBy?: string; dueAt?: string },
  ctx: OpContext,
): OpResult<IntermediateRequest> {
  const inc = findIncident(data, id);
  assertOpen(inc);
  if (inc.awareAt === undefined) throw new TocsinError('STAGE_ORDER', 'Record the awareness time first.');
  if (inc.intermediateRequests.length >= LIMITS.requests) invalid('Too many requests.');
  if (toMs(input.requestedAt) > ctx.now + 5 * 60_000) invalid('The request time cannot be in the future.');
  if (input.dueAt !== undefined && toMs(input.dueAt) < toMs(input.requestedAt)) invalid('The due time cannot precede the request.');
  const by = optStr(input.requestedBy, 'requestedBy', LIMITS.label);
  const req: IntermediateRequest = {
    id: nextSubId('R', inc.intermediateRequests),
    requestedAt: input.requestedAt,
    ...(by === undefined ? {} : { requestedBy: by }),
    ...(input.dueAt === undefined ? {} : { dueAt: input.dueAt }),
  };
  const data2 = replace(data, ctx, { ...inc, intermediateRequests: [...inc.intermediateRequests, req] }, 'request.added', [`intermediateRequests.${req.id}`]);
  return { data: data2, result: req };
}

/** Sets the status-update text of an open intermediate-report request. */
export function setStatusUpdate(data: StoreData, id: string, requestId: string, text: string, ctx: OpContext): OpResult<Incident> {
  const inc = findIncident(data, id);
  assertOpen(inc);
  openRequest(inc, requestId);
  const statusUpdate = str(text, 'statusUpdate', LIMITS.longText);
  const intermediateRequests = inc.intermediateRequests.map((r) => (r.id === requestId ? { ...r, statusUpdate } : r));
  const data2 = replace(data, ctx, { ...inc, intermediateRequests }, 'request.updated', [`intermediateRequests.${requestId}.statusUpdate`]);
  return { data: data2, result: findIncident(data2, id) };
}

export interface SubmitInput {
  readonly stage: Stage;
  readonly submittedAt: string;
  readonly requestId?: string;
  readonly authorityReference?: string;
  /** Record the submission even if prescribed elements are empty (they are listed in the audit note). */
  readonly allowIncomplete?: boolean;
}

/**
 * Records that a report was submitted to the CSIRT / competent authority. A snapshot of the report
 * content is stored with its SHA-256, so what was sent can be reproduced later.
 */
export function recordSubmission(data: StoreData, id: string, input: SubmitInput, cfg: TocsinConfig, ctx: OpContext): OpResult<Incident> {
  const inc = findIncident(data, id);
  assertCanSubmit(inc, input.stage, input.submittedAt, ctx.now, input.requestId);
  const report = buildReport(inc, input.stage, cfg, ctx.now, input.requestId);
  if (report.missing.length > 0 && input.allowIncomplete !== true) {
    throw new TocsinError('VALIDATION', `Prescribed elements are empty: ${report.missing.join(', ')}. Fill them in, or record the submission as incomplete.`);
  }
  const snapshot = JSON.parse(canonicalJson(report)) as unknown;
  const contentSha256 = sha256Canonical(snapshot);
  const ref = optStr(input.authorityReference, 'authorityReference', LIMITS.label);
  const recordedAt = nowIso(ctx);
  let next: Incident;
  if (input.stage === 'intermediate-report') {
    const rid = input.requestId as string;
    next = {
      ...inc,
      intermediateRequests: inc.intermediateRequests.map((r) =>
        r.id === rid ? { ...r, submission: { submittedAt: input.submittedAt, recordedAt, contentSha256, snapshot, ...(ref === undefined ? {} : { authorityReference: ref }) } } : r,
      ),
    };
  } else {
    next = {
      ...inc,
      submissions: [...inc.submissions, { stage: input.stage, submittedAt: input.submittedAt, recordedAt, contentSha256, snapshot, ...(ref === undefined ? {} : { authorityReference: ref }) }],
    };
  }
  const note = report.missing.length > 0 ? `incomplete: ${report.missing.join(', ')}` : undefined;
  const data2 = replace(data, ctx, next, 'report.submitted', [input.stage + (input.requestId === undefined ? '' : `:${input.requestId}`)], note);
  return { data: data2, result: findIncident(data2, id) };
}

/** Records a communication to recipients of services (Art 23(1) second sentence, or Art 23(2)). */
export function addRecipientCommunication(data: StoreData, id: string, input: Omit<RecipientCommunication, 'id'>, ctx: OpContext): OpResult<RecipientCommunication> {
  const inc = findIncident(data, id);
  assertOpen(inc);
  if (inc.recipientCommunications.length >= LIMITS.communications) invalid('Too many communications.');
  if (toMs(input.communicatedAt) > ctx.now + 5 * 60_000) invalid('The communication time cannot be in the future.');
  const c = validateCommunication({ ...input, id: nextSubId('C', inc.recipientCommunications) });
  const data2 = replace(data, ctx, { ...inc, recipientCommunications: [...inc.recipientCommunications, c] }, 'recipients.notified', [`recipientCommunications.${c.id}`]);
  return { data: data2, result: c };
}

/** Audits an event that changes nothing in the register (report generated, export created, …). */
export function logEvent(data: StoreData, action: string, ctx: OpContext, target?: string, note?: string): StoreData {
  if (!/^[a-z][a-z.-]{0,39}$/u.test(action)) invalid('Invalid audit action.');
  return {
    ...data,
    audit: audit(data, ctx, {
      action,
      fields: [],
      ...(target === undefined ? {} : { target }),
      ...(note === undefined ? {} : { note: str(note, 'note', { max: 500, multiline: true }) }),
    }),
  };
}

/** Marks webhook notifications as sent (dedupe keys) and audits it. */
export function markNotified(data: StoreData, keys: readonly string[], ctx: OpContext): StoreData {
  if (keys.length === 0) return data;
  const notified = [...data.meta.notified, ...keys].slice(-5000);
  return { ...logEvent(data, 'webhook.sent', ctx, undefined, `${keys.length} notification(s)`), meta: { ...data.meta, notified } };
}
