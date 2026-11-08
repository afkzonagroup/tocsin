// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { ref, type LegalRef } from '../legal/refs.js';
import type { TocsinConfig } from '../model/config.js';
import { SERVICE_TYPE_LABELS, STAGE_LABELS, type Incident, type Stage } from '../model/types.js';
import { computeDeadlines } from '../stages/deadlines.js';
import { formatInZone } from '../time/zone.js';
import { TocsinError } from '../util/errors.js';
import type { Tri } from '../util/validate.js';

/**
 * Report content per stage. Each stage carries exactly the elements Article 23(4) NIS2 names for it
 * ("legal" elements), plus clearly separated optional elements that national forms usually ask for.
 */

export type Requirement =
  /** The Directive requires this element. */
  | 'required'
  /** Required "where applicable": a position must be stated (yes / no / not yet determined). */
  | 'where-applicable'
  /** Required "where available": may be empty when nothing is available. */
  | 'where-available'
  /** Not prescribed by Article 23(4). */
  | 'optional';

export interface ReportElement {
  readonly key: string;
  readonly label: string;
  readonly requirement: Requirement;
  readonly ref?: LegalRef;
  readonly value?: string | readonly string[];
  readonly note?: string;
}

export interface ReportContent {
  readonly format: 'tocsin-report';
  readonly formatVersion: 1;
  readonly stage: Stage;
  readonly stageLabel: string;
  readonly legalBasis: LegalRef;
  readonly incidentId: string;
  readonly title: string;
  readonly generatedAt: string;
  readonly timeZone: string;
  readonly requestId?: string;
  /** Elements Article 23(4) prescribes for this stage. */
  readonly elements: readonly ReportElement[];
  /** Optional elements (identification, timeline). Not prescribed by Article 23(4). */
  readonly optional: readonly ReportElement[];
  /** Keys of prescribed elements that are still empty. */
  readonly missing: readonly string[];
  readonly attribution: { readonly text: string; readonly url: string };
}

/** AGPL-3.0 section 7(b) attribution, see LICENSE-ADDITIONAL-TERMS.md. */
export const ATTRIBUTION = { text: 'Tocsin by AFKzona Group', url: 'https://afkzonagroup.lt' } as const;

const NIS2 = (p: string): LegalRef => ref('NIS2', p);

const STAGE_BASIS: Readonly<Record<Stage, LegalRef>> = {
  'early-warning': NIS2('Article 23(4), point (a)'),
  'incident-notification': NIS2('Article 23(4), point (b)'),
  'intermediate-report': NIS2('Article 23(4), point (c)'),
  'progress-report': NIS2('Article 23(4), point (e)'),
  'final-report': NIS2('Article 23(4), point (d)'),
};

export function triText(t: Tri | undefined): string | undefined {
  if (t === undefined) return undefined;
  return t === 'yes' ? 'Yes' : t === 'no' ? 'No' : 'Not yet determined';
}

function el(key: string, label: string, requirement: Requirement, value: string | readonly string[] | undefined, legal?: LegalRef, note?: string): ReportElement {
  return {
    key,
    label,
    requirement,
    ...(legal === undefined ? {} : { ref: legal }),
    ...(value === undefined || (typeof value === 'string' && value.trim() === '') ? {} : { value }),
    ...(note === undefined ? {} : { note }),
  };
}

function joinTri(t: Tri | undefined, note: string | undefined): string | undefined {
  const base = triText(t);
  if (base === undefined) return undefined;
  return note === undefined ? base : `${base}. ${note}`;
}

function crossBorder(i: Incident, key: string, legal: LegalRef, requirement: Requirement, label: string): ReportElement {
  const states = i.details.affectedMemberStates;
  const parts = [joinTri(i.details.crossBorderImpact, i.details.crossBorderImpactDetails)];
  if (states !== undefined && states.length > 0) parts.push(`Member States concerned: ${states.join(', ')}`);
  const value = parts[0] === undefined ? undefined : parts.filter((p): p is string => p !== undefined).join('. ');
  return el(key, label, requirement, value, legal);
}

function suspected(i: Incident, legal: LegalRef): ReportElement {
  return el(
    'suspectedUnlawfulOrMalicious',
    'Suspected of being caused by unlawful or malicious acts',
    'where-applicable',
    joinTri(i.details.suspectedUnlawfulOrMalicious, i.details.suspectedUnlawfulOrMaliciousNote),
    legal,
  );
}

function legalElements(i: Incident, stage: Stage, requestId: string | undefined): ReportElement[] {
  const d = i.details;
  switch (stage) {
    case 'early-warning':
      return [
        suspected(i, NIS2('Article 23(4), point (a)')),
        crossBorder(i, 'crossBorderImpact', NIS2('Article 23(4), point (a)'), 'where-applicable', 'Could have a cross-border impact'),
      ];
    case 'incident-notification':
      return [
        el('severity', 'Initial assessment: severity', 'required', d.severity, NIS2('Article 23(4), point (b)')),
        el('impact', 'Initial assessment: impact', 'required', d.impact, NIS2('Article 23(4), point (b)')),
        el(
          'indicatorsOfCompromise',
          'Indicators of compromise',
          'where-available',
          d.indicatorsOfCompromise !== undefined && d.indicatorsOfCompromise.length > 0 ? d.indicatorsOfCompromise : undefined,
          NIS2('Article 23(4), point (b)'),
        ),
        { ...suspected(i, NIS2('Article 23(4), point (b)')), note: 'Update of the early-warning information.' },
        {
          ...crossBorder(i, 'crossBorderImpact', NIS2('Article 23(4), point (b)'), 'where-applicable', 'Could have a cross-border impact'),
          note: 'Update of the early-warning information.',
        },
      ];
    case 'intermediate-report': {
      const r = i.intermediateRequests.find((x) => x.id === requestId);
      if (r === undefined) throw new TocsinError('NOT_FOUND', `No intermediate-report request ${requestId ?? '(none given)'} on ${i.id}.`);
      return [el('statusUpdate', 'Relevant status updates', 'required', r.statusUpdate, NIS2('Article 23(4), point (c)'))];
    }
    case 'progress-report':
      return [
        el(
          'progressStatus',
          'Progress of the ongoing incident',
          'required',
          d.progressStatus,
          NIS2('Article 23(4), point (e)'),
          'Article 23(4)(e) requires a progress report but does not list its content. This field is the minimum the tool asks for.',
        ),
      ];
    case 'final-report':
      return [
        el('description', 'Detailed description of the incident', 'required', d.description, NIS2('Article 23(4), point (d)(i)')),
        el('severity', 'Severity', 'required', d.severity, NIS2('Article 23(4), point (d)(i)')),
        el('impact', 'Impact', 'required', d.impact, NIS2('Article 23(4), point (d)(i)')),
        el('threatTypeOrRootCause', 'Type of threat or root cause that is likely to have triggered the incident', 'required', d.threatTypeOrRootCause, NIS2('Article 23(4), point (d)(ii)')),
        el('mitigationApplied', 'Applied mitigation measures', 'required', d.mitigationApplied, NIS2('Article 23(4), point (d)(iii)')),
        el('mitigationOngoing', 'Ongoing mitigation measures', 'required', d.mitigationOngoing, NIS2('Article 23(4), point (d)(iii)'), 'Write "None" if no measures are ongoing.'),
        crossBorder(i, 'crossBorderImpact', NIS2('Article 23(4), point (d)(iv)'), 'where-applicable', 'Cross-border impact of the incident'),
      ];
  }
}

function optionalElements(i: Incident, stage: Stage, cfg: TocsinConfig, now: number, requestId: string | undefined): ReportElement[] {
  const z = cfg.timeZone;
  const t = (iso: string | undefined): string | undefined => (iso === undefined ? undefined : `${formatInZone(iso, z)} — ${iso}`);
  const deadline = computeDeadlines(i, z, now).find((d) => d.kind === stage && (stage !== 'intermediate-report' || d.requestId === requestId));
  const out: ReportElement[] = [
    el('entityName', 'Entity', 'optional', cfg.entity.name),
    el('entityCategory', 'Entity category', 'optional', cfg.entity.category),
    el('memberState', 'Member State of establishment', 'optional', cfg.entity.memberState),
    el(
      'contact',
      'Contact',
      'optional',
      [cfg.entity.contactName, cfg.entity.contactEmail, cfg.entity.contactPhone].filter((x): x is string => x !== undefined).join(', ') || undefined,
    ),
    el('recipient', cfg.authority.role === 'csirt' ? 'Recipient (CSIRT)' : 'Recipient (competent authority)', 'optional', cfg.authority.name, NIS2('Article 23(1)')),
    el('incidentId', 'Incident reference', 'optional', i.id),
    el('internalReference', 'Internal reference', 'optional', i.details.internalReference),
    el('serviceTypes', 'Affected service types', 'optional', i.serviceTypes.map((s) => SERVICE_TYPE_LABELS[s])),
    el('summary', 'Summary', 'optional', i.details.summary),
    el('occurredAt', 'Incident occurred', 'optional', t(i.occurredAt)),
    el('detectedAt', 'Incident detected', 'optional', t(i.detectedAt)),
    el('awareAt', 'Became aware of the significant incident', 'optional', t(i.awareAt), ref('IR2024_2690', 'recital 31')),
    el('deadline', 'Deadline for this report', 'optional', deadline?.dueAt === undefined ? undefined : `${t(deadline.dueAt) ?? ''} (${deadline.basis})`),
  ];
  if (i.assessment !== undefined && i.assessment.metCriteria.length > 0) {
    out.push(el('significanceCriteria', 'Significance criteria met (as assessed by the entity)', 'optional', [...i.assessment.metCriteria]));
  }
  if (stage === 'final-report' || stage === 'progress-report') out.push(el('handlingConcludedAt', 'Handling of the incident concluded', 'optional', t(i.handlingConcludedAt)));
  if (stage === 'progress-report') {
    out.push(
      el('description', 'Description so far', 'optional', i.details.description),
      el('threatTypeOrRootCause', 'Type of threat or root cause so far', 'optional', i.details.threatTypeOrRootCause),
      el('mitigationApplied', 'Mitigation measures applied so far', 'optional', i.details.mitigationApplied),
      el('mitigationOngoing', 'Ongoing mitigation measures', 'optional', i.details.mitigationOngoing),
    );
  }
  return out;
}

/**
 * Builds the content of a report for one stage from the current incident record.
 *
 * @param requestId the intermediate-report request this report answers (stage "intermediate-report" only).
 * @example
 * const c = buildReport(incident, 'early-warning', config, Date.now());
 * c.missing // keys of prescribed elements without a value
 */
export function buildReport(i: Incident, stage: Stage, cfg: TocsinConfig, now: number, requestId?: string): ReportContent {
  const elements = legalElements(i, stage, requestId);
  const optional = optionalElements(i, stage, cfg, now, requestId);
  if (stage === 'intermediate-report') {
    const r = i.intermediateRequests.find((x) => x.id === requestId);
    if (r !== undefined) {
      optional.push(
        el('requestedAt', 'Request received', 'optional', `${formatInZone(r.requestedAt, cfg.timeZone)} — ${r.requestedAt}`),
        el('requestedBy', 'Requested by', 'optional', r.requestedBy),
      );
    }
  }
  const missing = elements.filter((e) => e.value === undefined && e.requirement !== 'where-available').map((e) => e.key);
  return {
    format: 'tocsin-report',
    formatVersion: 1,
    stage,
    stageLabel: STAGE_LABELS[stage],
    legalBasis: STAGE_BASIS[stage],
    incidentId: i.id,
    title: i.title,
    generatedAt: new Date(now).toISOString(),
    timeZone: cfg.timeZone,
    ...(requestId === undefined ? {} : { requestId }),
    elements,
    optional,
    missing,
    attribution: ATTRIBUTION,
  };
}
