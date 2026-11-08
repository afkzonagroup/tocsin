// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { invalid } from '../util/errors.js';
import {
  arr,
  asRecord,
  MAX_CENTS,
  MAX_COUNT,
  nonNegInt,
  oneOf,
  onlyKeys,
  optNonNegInt,
  optStr,
  str,
  tri,
  type StringRule,
  type Tri,
} from '../util/validate.js';
import { toMs } from '../time/zone.js';
import {
  SERVICE_TYPES,
  type AssessmentAnswers,
  type Incident,
  type IncidentDetails,
  type IntermediateRequest,
  type RecipientCommunication,
  type ServiceMetrics,
  type ServiceType,
  type StoredAssessment,
  type Submission,
} from './types.js';

export const LIMITS = {
  title: { max: 200, min: 1 },
  shortText: { max: 2_000, multiline: true },
  longText: { max: 20_000, multiline: true },
  label: { max: 200 },
  ioc: { max: 512 },
  iocCount: 500,
  memberStates: 32,
  incidents: 100_000,
  requests: 100,
  communications: 200,
  linked: 100,
  submissions: 10,
} as const;

export const INCIDENT_ID_RE = /^INC-\d{4}-\d{4,6}$/u;
const SUB_ID_RE = /^[A-Z]{1,3}-\d{1,4}$/u;
const ROOT_CAUSE_KEY: StringRule = { max: 64, min: 1, pattern: /^[a-z0-9][a-z0-9._-]*$/u };
/** ISO 3166-1 alpha-2 codes as used by the EU (Greece = EL), upper case. */
const MEMBER_STATE: StringRule = { max: 2, min: 2, pattern: /^[A-Z]{2}$/u };

const SECONDS_MAX = 10 * 365 * 86_400;

export function instant(v: unknown, what: string): string {
  const s = str(v, what, { max: 24 });
  toMs(s);
  return s;
}

function optInstant(v: unknown, what: string): string | undefined {
  return v === undefined ? undefined : instant(v, what);
}

function optTri(v: unknown, what: string): Tri | undefined {
  return v === undefined ? undefined : tri(v, what);
}

/** Assigns `value` to `key` only when defined (exactOptionalPropertyTypes-friendly). */
function put<T extends object, K extends keyof T>(target: T, key: K, value: T[K] | undefined): void {
  if (value !== undefined) target[key] = value;
}

const METRIC_KEYS = [
  'completeUnavailabilitySeconds',
  'usersCompletelyUnavailable',
  'limitedAvailabilitySeconds',
  'usersLimitedAvailability',
  'totalUsersInUnion',
  'slowResponsePeriodSeconds',
  'slowResponseAverageMs',
  'dataCompromised',
  'dataCompromisedMalicious',
  'usersDataCompromise',
  'dnsMisconfigurationOnly',
  'dnsIncorrectDomainNames',
  'dnsDomainNamesManaged',
  'physicalAccessCompromised',
  'weeklyUnavailabilitySeconds',
] as const satisfies readonly (keyof ServiceMetrics)[];

export function validateServiceMetrics(v: unknown, what: string): ServiceMetrics {
  const o = asRecord(v, what);
  onlyKeys(o, METRIC_KEYS, what);
  const m: ServiceMetrics = {};
  put(m, 'completeUnavailabilitySeconds', optNonNegInt(o['completeUnavailabilitySeconds'], `${what}.completeUnavailabilitySeconds`, SECONDS_MAX));
  put(m, 'usersCompletelyUnavailable', optNonNegInt(o['usersCompletelyUnavailable'], `${what}.usersCompletelyUnavailable`, MAX_COUNT));
  put(m, 'limitedAvailabilitySeconds', optNonNegInt(o['limitedAvailabilitySeconds'], `${what}.limitedAvailabilitySeconds`, SECONDS_MAX));
  put(m, 'usersLimitedAvailability', optNonNegInt(o['usersLimitedAvailability'], `${what}.usersLimitedAvailability`, MAX_COUNT));
  put(m, 'totalUsersInUnion', optNonNegInt(o['totalUsersInUnion'], `${what}.totalUsersInUnion`, MAX_COUNT));
  put(m, 'slowResponsePeriodSeconds', optNonNegInt(o['slowResponsePeriodSeconds'], `${what}.slowResponsePeriodSeconds`, SECONDS_MAX));
  put(m, 'slowResponseAverageMs', optNonNegInt(o['slowResponseAverageMs'], `${what}.slowResponseAverageMs`, 86_400_000));
  put(m, 'dataCompromised', optTri(o['dataCompromised'], `${what}.dataCompromised`));
  put(m, 'dataCompromisedMalicious', optTri(o['dataCompromisedMalicious'], `${what}.dataCompromisedMalicious`));
  put(m, 'usersDataCompromise', optNonNegInt(o['usersDataCompromise'], `${what}.usersDataCompromise`, MAX_COUNT));
  put(m, 'dnsMisconfigurationOnly', optTri(o['dnsMisconfigurationOnly'], `${what}.dnsMisconfigurationOnly`));
  put(m, 'dnsIncorrectDomainNames', optNonNegInt(o['dnsIncorrectDomainNames'], `${what}.dnsIncorrectDomainNames`, MAX_COUNT));
  put(m, 'dnsDomainNamesManaged', optNonNegInt(o['dnsDomainNamesManaged'], `${what}.dnsDomainNamesManaged`, MAX_COUNT));
  put(m, 'physicalAccessCompromised', optTri(o['physicalAccessCompromised'], `${what}.physicalAccessCompromised`));
  put(m, 'weeklyUnavailabilitySeconds', optNonNegInt(o['weeklyUnavailabilitySeconds'], `${what}.weeklyUnavailabilitySeconds`, 7 * 86_400));
  for (const [usersKey] of [['usersCompletelyUnavailable'], ['usersLimitedAvailability'], ['usersDataCompromise']] as const) {
    const users = m[usersKey];
    if (users !== undefined && m.totalUsersInUnion !== undefined && users > m.totalUsersInUnion) {
      invalid(`${what}.${usersKey} cannot exceed totalUsersInUnion.`);
    }
  }
  if (m.dnsIncorrectDomainNames !== undefined && m.dnsDomainNamesManaged !== undefined && m.dnsIncorrectDomainNames > m.dnsDomainNamesManaged) {
    invalid(`${what}.dnsIncorrectDomainNames cannot exceed dnsDomainNamesManaged.`);
  }
  return m;
}

const ANSWER_KEYS = [
  'scheduledMaintenanceOnly',
  'directFinancialLossCents',
  'tradeSecretExfiltration',
  'deathOfNaturalPerson',
  'considerableHealthDamage',
  'maliciousUnauthorisedAccess',
  'accessCapableOfSevereDisruption',
  'severeDisruptionOrFinancialLoss',
  'considerableDamageToOthers',
  'services',
] as const satisfies readonly (keyof AssessmentAnswers)[];

export function validateAnswers(v: unknown): AssessmentAnswers {
  const o = asRecord(v, 'answers');
  onlyKeys(o, ANSWER_KEYS, 'answers');
  const a: AssessmentAnswers = {};
  put(a, 'scheduledMaintenanceOnly', optTri(o['scheduledMaintenanceOnly'], 'scheduledMaintenanceOnly'));
  put(a, 'directFinancialLossCents', optNonNegInt(o['directFinancialLossCents'], 'directFinancialLossCents', MAX_CENTS));
  put(a, 'tradeSecretExfiltration', optTri(o['tradeSecretExfiltration'], 'tradeSecretExfiltration'));
  put(a, 'deathOfNaturalPerson', optTri(o['deathOfNaturalPerson'], 'deathOfNaturalPerson'));
  put(a, 'considerableHealthDamage', optTri(o['considerableHealthDamage'], 'considerableHealthDamage'));
  put(a, 'maliciousUnauthorisedAccess', optTri(o['maliciousUnauthorisedAccess'], 'maliciousUnauthorisedAccess'));
  put(a, 'accessCapableOfSevereDisruption', optTri(o['accessCapableOfSevereDisruption'], 'accessCapableOfSevereDisruption'));
  put(a, 'severeDisruptionOrFinancialLoss', optTri(o['severeDisruptionOrFinancialLoss'], 'severeDisruptionOrFinancialLoss'));
  put(a, 'considerableDamageToOthers', optTri(o['considerableDamageToOthers'], 'considerableDamageToOthers'));
  if (o['services'] !== undefined) {
    const s = asRecord(o['services'], 'answers.services');
    onlyKeys(s, SERVICE_TYPES, 'answers.services');
    const services: Partial<Record<ServiceType, ServiceMetrics>> = {};
    for (const t of SERVICE_TYPES) {
      if (s[t] !== undefined) services[t] = validateServiceMetrics(s[t], `services.${t}`);
    }
    a.services = services;
  }
  return a;
}

const DETAIL_KEYS = [
  'summary',
  'description',
  'severity',
  'impact',
  'suspectedUnlawfulOrMalicious',
  'suspectedUnlawfulOrMaliciousNote',
  'crossBorderImpact',
  'crossBorderImpactDetails',
  'affectedMemberStates',
  'indicatorsOfCompromise',
  'threatTypeOrRootCause',
  'mitigationApplied',
  'mitigationOngoing',
  'progressStatus',
  'rootCauseKey',
  'recipientsLikelyAffected',
  'trustServicesImpacted',
  'internalReference',
] as const satisfies readonly (keyof IncidentDetails)[];

export type DetailKey = (typeof DETAIL_KEYS)[number];
export const DETAIL_FIELDS: readonly DetailKey[] = DETAIL_KEYS;

export function validateDetails(v: unknown): IncidentDetails {
  const o = asRecord(v, 'details');
  onlyKeys(o, DETAIL_KEYS, 'details');
  const d: IncidentDetails = {};
  put(d, 'summary', optStr(o['summary'], 'summary', LIMITS.shortText));
  put(d, 'description', optStr(o['description'], 'description', LIMITS.longText));
  put(d, 'severity', optStr(o['severity'], 'severity', LIMITS.shortText));
  put(d, 'impact', optStr(o['impact'], 'impact', LIMITS.longText));
  put(d, 'suspectedUnlawfulOrMalicious', optTri(o['suspectedUnlawfulOrMalicious'], 'suspectedUnlawfulOrMalicious'));
  put(d, 'suspectedUnlawfulOrMaliciousNote', optStr(o['suspectedUnlawfulOrMaliciousNote'], 'suspectedUnlawfulOrMaliciousNote', LIMITS.shortText));
  put(d, 'crossBorderImpact', optTri(o['crossBorderImpact'], 'crossBorderImpact'));
  put(d, 'crossBorderImpactDetails', optStr(o['crossBorderImpactDetails'], 'crossBorderImpactDetails', LIMITS.longText));
  if (o['affectedMemberStates'] !== undefined) {
    const list = arr(o['affectedMemberStates'], 'affectedMemberStates', LIMITS.memberStates).map((x, i) => str(x, `affectedMemberStates[${i}]`, MEMBER_STATE));
    d.affectedMemberStates = [...new Set(list)];
  }
  if (o['indicatorsOfCompromise'] !== undefined) {
    d.indicatorsOfCompromise = arr(o['indicatorsOfCompromise'], 'indicatorsOfCompromise', LIMITS.iocCount).map((x, i) =>
      str(x, `indicatorsOfCompromise[${i}]`, { ...LIMITS.ioc, min: 1 }),
    );
  }
  put(d, 'threatTypeOrRootCause', optStr(o['threatTypeOrRootCause'], 'threatTypeOrRootCause', LIMITS.longText));
  put(d, 'mitigationApplied', optStr(o['mitigationApplied'], 'mitigationApplied', LIMITS.longText));
  put(d, 'mitigationOngoing', optStr(o['mitigationOngoing'], 'mitigationOngoing', LIMITS.longText));
  put(d, 'progressStatus', optStr(o['progressStatus'], 'progressStatus', LIMITS.longText));
  put(d, 'rootCauseKey', optStr(o['rootCauseKey'], 'rootCauseKey', ROOT_CAUSE_KEY));
  put(d, 'recipientsLikelyAffected', optTri(o['recipientsLikelyAffected'], 'recipientsLikelyAffected'));
  put(d, 'trustServicesImpacted', optTri(o['trustServicesImpacted'], 'trustServicesImpacted'));
  put(d, 'internalReference', optStr(o['internalReference'], 'internalReference', LIMITS.label));
  return d;
}

export function validateServiceTypes(v: unknown): ServiceType[] {
  const list = arr(v, 'serviceTypes', SERVICE_TYPES.length).map((x) => oneOf(x, SERVICE_TYPES, 'serviceType'));
  if (list.length === 0) invalid('At least one service type is required.');
  return [...new Set(list)];
}

function validateAssessment(v: unknown): StoredAssessment {
  const o = asRecord(v, 'assessment');
  onlyKeys(o, ['assessedAt', 'answers', 'outcome', 'metCriteria'], 'assessment');
  return {
    assessedAt: instant(o['assessedAt'], 'assessment.assessedAt'),
    answers: validateAnswers(o['answers']),
    outcome: oneOf(o['outcome'], ['significant', 'not-significant', 'undetermined'] as const, 'assessment.outcome'),
    metCriteria: arr(o['metCriteria'], 'assessment.metCriteria', 200).map((x) => str(x, 'criterion id', { max: 64 })),
  };
}

function validateSnapshotHash(v: unknown): string {
  return str(v, 'contentSha256', { max: 64, min: 64, pattern: /^[0-9a-f]{64}$/u });
}

function validateSubmission(v: unknown): Submission {
  const o = asRecord(v, 'submission');
  onlyKeys(o, ['stage', 'submittedAt', 'recordedAt', 'authorityReference', 'contentSha256', 'snapshot'], 'submission');
  const s: Submission = {
    stage: oneOf(o['stage'], ['early-warning', 'incident-notification', 'progress-report', 'final-report'] as const, 'submission.stage'),
    submittedAt: instant(o['submittedAt'], 'submission.submittedAt'),
    recordedAt: instant(o['recordedAt'], 'submission.recordedAt'),
    contentSha256: validateSnapshotHash(o['contentSha256']),
    snapshot: o['snapshot'],
  };
  const ref = optStr(o['authorityReference'], 'authorityReference', LIMITS.label);
  return ref === undefined ? s : { ...s, authorityReference: ref };
}

function validateRequest(v: unknown): IntermediateRequest {
  const o = asRecord(v, 'intermediate request');
  onlyKeys(o, ['id', 'requestedAt', 'requestedBy', 'dueAt', 'statusUpdate', 'submission'], 'intermediate request');
  const r: IntermediateRequest = {
    id: str(o['id'], 'request id', { max: 8, pattern: SUB_ID_RE }),
    requestedAt: instant(o['requestedAt'], 'requestedAt'),
  };
  const by = optStr(o['requestedBy'], 'requestedBy', LIMITS.label);
  const due = optInstant(o['dueAt'], 'dueAt');
  const out: IntermediateRequest = { ...r, ...(by === undefined ? {} : { requestedBy: by }), ...(due === undefined ? {} : { dueAt: due }) };
  put(out, 'statusUpdate', optStr(o['statusUpdate'], 'statusUpdate', LIMITS.longText));
  if (o['submission'] !== undefined) {
    const so = asRecord(o['submission'], 'request submission');
    onlyKeys(so, ['submittedAt', 'recordedAt', 'authorityReference', 'contentSha256', 'snapshot'], 'request submission');
    const ref = optStr(so['authorityReference'], 'authorityReference', LIMITS.label);
    out.submission = {
      submittedAt: instant(so['submittedAt'], 'submittedAt'),
      recordedAt: instant(so['recordedAt'], 'recordedAt'),
      contentSha256: validateSnapshotHash(so['contentSha256']),
      snapshot: so['snapshot'],
      ...(ref === undefined ? {} : { authorityReference: ref }),
    };
  }
  return out;
}

export function validateCommunication(v: unknown): RecipientCommunication {
  const o = asRecord(v, 'recipient communication');
  onlyKeys(o, ['id', 'kind', 'communicatedAt', 'audience', 'summary', 'measuresOrRemedies'], 'recipient communication');
  const c: RecipientCommunication = {
    id: str(o['id'], 'communication id', { max: 8, pattern: SUB_ID_RE }),
    kind: oneOf(o['kind'], ['incident-23-1', 'cyber-threat-23-2'] as const, 'kind'),
    communicatedAt: instant(o['communicatedAt'], 'communicatedAt'),
    audience: str(o['audience'], 'audience', { ...LIMITS.label, min: 1 }),
    summary: str(o['summary'], 'summary', { ...LIMITS.shortText, min: 1 }),
  };
  const m = optStr(o['measuresOrRemedies'], 'measuresOrRemedies', LIMITS.longText);
  return m === undefined ? c : { ...c, measuresOrRemedies: m };
}

const INCIDENT_KEYS = [
  'id',
  'title',
  'createdAt',
  'updatedAt',
  'serviceTypes',
  'occurredAt',
  'detectedAt',
  'awareAt',
  'handlingConcludedAt',
  'details',
  'assessment',
  'submissions',
  'intermediateRequests',
  'recipientCommunications',
  'linkedIncidentIds',
] as const satisfies readonly (keyof Incident)[];

/** Full structural validation of an incident record (used when loading the store and importing). */
export function validateIncident(v: unknown): Incident {
  const o = asRecord(v, 'incident');
  onlyKeys(o, INCIDENT_KEYS, 'incident');
  const inc: Incident = {
    id: str(o['id'], 'incident id', { max: 16, pattern: INCIDENT_ID_RE }),
    title: str(o['title'], 'title', LIMITS.title),
    createdAt: instant(o['createdAt'], 'createdAt'),
    updatedAt: instant(o['updatedAt'], 'updatedAt'),
    serviceTypes: validateServiceTypes(o['serviceTypes']),
    details: validateDetails(o['details'] ?? {}),
    submissions: arr(o['submissions'] ?? [], 'submissions', LIMITS.submissions).map(validateSubmission),
    intermediateRequests: arr(o['intermediateRequests'] ?? [], 'intermediateRequests', LIMITS.requests).map(validateRequest),
    recipientCommunications: arr(o['recipientCommunications'] ?? [], 'recipientCommunications', LIMITS.communications).map(validateCommunication),
    linkedIncidentIds: arr(o['linkedIncidentIds'] ?? [], 'linkedIncidentIds', LIMITS.linked).map((x) => str(x, 'linked id', { max: 16, pattern: INCIDENT_ID_RE })),
  };
  put(inc, 'occurredAt', optInstant(o['occurredAt'], 'occurredAt'));
  put(inc, 'detectedAt', optInstant(o['detectedAt'], 'detectedAt'));
  put(inc, 'awareAt', optInstant(o['awareAt'], 'awareAt'));
  put(inc, 'handlingConcludedAt', optInstant(o['handlingConcludedAt'], 'handlingConcludedAt'));
  if (o['assessment'] !== undefined) inc.assessment = validateAssessment(o['assessment']);
  return inc;
}

export { nonNegInt };
