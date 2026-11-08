// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { ref, type LegalRef } from '../legal/refs.js';
import type { AssessmentAnswers, ServiceMetrics, ServiceType } from '../model/types.js';

/**
 * Questions the assessment may need. Yes/no questions are matters of judgement: the tool never
 * answers them itself. Numeric questions are measurements; recital hints say how the Regulation
 * expects them to be measured.
 */

export type QuestionKind = 'tri' | 'count' | 'duration' | 'cents' | 'milliseconds';

export type GeneralKey = Exclude<keyof AssessmentAnswers, 'services'>;
export type MetricKey = keyof ServiceMetrics;

export interface Question {
  /** "scheduledMaintenanceOnly" or "services.cloud.limitedAvailabilitySeconds". */
  readonly id: string;
  readonly kind: QuestionKind;
  readonly text: string;
  readonly help?: string;
  readonly ref: LegalRef;
}

const IR = (p: string): LegalRef => ref('IR2024_2690', p);
const NIS2 = (p: string): LegalRef => ref('NIS2', p);

export const GENERAL_QUESTIONS: Readonly<Record<GeneralKey, Omit<Question, 'id'>>> = {
  scheduledMaintenanceOnly: {
    kind: 'tri',
    text: 'Is this only a scheduled interruption of service or a planned consequence of scheduled maintenance?',
    help: 'Such events are not significant incidents (also interruptions under a pre-determined contractual agreement, recital 33).',
    ref: IR('Article 3(2)'),
  },
  directFinancialLossCents: {
    kind: 'cents',
    text: 'Direct financial loss the incident has caused or is capable of causing (EUR).',
    help: 'Count the losses listed in recital 36 (replacement, staff, contractual fees, redress, forgone revenue, communication, advisory costs). Exclude administrative fines, day-to-day running costs, post-incident improvements and insurance premiums. Estimate when actual amounts are not known.',
    ref: IR('Article 3(1), point (a)'),
  },
  tradeSecretExfiltration: {
    kind: 'tri',
    text: 'Has the incident caused, or is it capable of causing, the exfiltration of trade secrets of the entity (Article 2(1) of Directive (EU) 2016/943)?',
    ref: IR('Article 3(1), point (b)'),
  },
  deathOfNaturalPerson: {
    kind: 'tri',
    text: 'Has the incident caused, or is it capable of causing, the death of a natural person?',
    ref: IR('Article 3(1), point (c)'),
  },
  considerableHealthDamage: {
    kind: 'tri',
    text: "Has the incident caused, or is it capable of causing, considerable damage to a natural person's health?",
    help: 'Consider whether it caused or can cause severe injuries and ill-health. You need not collect information you do not have access to (recital 37).',
    ref: IR('Article 3(1), point (d)'),
  },
  maliciousUnauthorisedAccess: {
    kind: 'tri',
    text: 'Did a successful, suspectedly malicious and unauthorised access to network and information systems occur?',
    ref: IR('Article 3(1), point (e)'),
  },
  accessCapableOfSevereDisruption: {
    kind: 'tri',
    text: 'Is that access capable of causing severe operational disruption?',
    help: 'For instance, a threat actor pre-positioned in the systems to disrupt services later (recital 39).',
    ref: IR('Article 3(1), point (e)'),
  },
  severeDisruptionOrFinancialLoss: {
    kind: 'tri',
    text: 'Has the incident caused, or is it capable of causing, severe operational disruption of the services or financial loss for the entity?',
    help: 'Check national rules or guidance: some Member States set thresholds for this test.',
    ref: NIS2('Article 23(3), point (a)'),
  },
  considerableDamageToOthers: {
    kind: 'tri',
    text: 'Has the incident affected, or is it capable of affecting, other natural or legal persons by causing considerable material or non-material damage?',
    ref: NIS2('Article 23(3), point (b)'),
  },
};

const USERS_HELP =
  'Count customers with a contract giving access and the natural and legal persons associated with business customers (IR Art 3(3)). If you cannot count, use your estimate of the possible maximum (recital 32).';
const DURATION_HELP =
  'Measure from the disruption of the proper provision of the service until recovery; if the start is unknown, from detection or the earliest log record (recitals 34 and 35). Enter e.g. 45m or 1h30m.';

export const METRIC_QUESTIONS: Readonly<Record<MetricKey, Omit<Question, 'id' | 'ref'>>> = {
  completeUnavailabilitySeconds: { kind: 'duration', text: 'How long was the service completely unavailable (longest period)?', help: DURATION_HELP },
  usersCompletelyUnavailable: { kind: 'count', text: 'How many users in the Union was the service completely unavailable for?', help: USERS_HELP },
  limitedAvailabilitySeconds: {
    kind: 'duration',
    text: 'How long was the availability of the service limited?',
    help: `Limited availability: considerably slower than average response time, or not all functionalities available (recital 38). ${DURATION_HELP}`,
  },
  usersLimitedAvailability: { kind: 'count', text: 'How many users in the Union were impacted by limited availability?', help: USERS_HELP },
  totalUsersInUnion: { kind: 'count', text: 'How many users does the service have in the Union in total?', help: USERS_HELP },
  slowResponsePeriodSeconds: { kind: 'duration', text: 'For how long was the average response time to DNS requests elevated?', help: DURATION_HELP },
  slowResponseAverageMs: { kind: 'milliseconds', text: 'What was the average response time to DNS requests during that period (milliseconds)?' },
  dataCompromised: { kind: 'tri', text: 'Was the integrity, confidentiality or authenticity of stored, transmitted or processed data related to the provision of the service compromised?' },
  dataCompromisedMalicious: { kind: 'tri', text: 'Was that compromise the result of a suspectedly malicious action?' },
  usersDataCompromise: { kind: 'count', text: 'How many users in the Union are impacted by the data compromise?', help: USERS_HELP },
  dnsMisconfigurationOnly: { kind: 'tri', text: 'Is the only problem that domain-name data is not correct because of misconfiguration?' },
  dnsIncorrectDomainNames: { kind: 'count', text: 'For how many domain names is the data not correct?' },
  dnsDomainNamesManaged: { kind: 'count', text: 'How many domain names does the DNS service provider manage?' },
  physicalAccessCompromised: { kind: 'tri', text: 'Was physical access (or, for trust services, its protection for restricted areas) compromised?' },
  weeklyUnavailabilitySeconds: {
    kind: 'duration',
    text: 'In the calendar week concerned, for how long in total was the trust service unavailable to users or relying parties?',
  },
};

/**
 * Where an article names narrower data than "the provision of the service", the question uses its words:
 * IR Art 5(c) covers only the authoritative resolution service, Art 6(c) the technical operation of the TLD.
 */
const DATA_SCOPE: Partial<Record<ServiceType, string>> = {
  dns: 'related to the provision of the authoritative domain name resolution service',
  'tld-registry': 'related to the technical operation of the TLD',
};

/** Builds the question for a metric of a given service type. */
export function metricQuestion(service: ServiceType, key: MetricKey, legal: LegalRef): Question {
  const base = METRIC_QUESTIONS[key];
  let text = service === 'trust-service' ? base.text.replace('users in the Union', 'users or relying parties in the Union') : base.text;
  const scope = DATA_SCOPE[service];
  if (key === 'dataCompromised' && scope !== undefined) text = text.replace('related to the provision of the service', scope);
  return { id: `services.${service}.${key}`, ...base, text, ref: legal };
}

export function generalQuestion(key: GeneralKey): Question {
  return { id: key, ...GENERAL_QUESTIONS[key] };
}

const CLOUD_LIKE: readonly MetricKey[] = ['completeUnavailabilitySeconds', 'limitedAvailabilitySeconds', 'usersLimitedAvailability', 'totalUsersInUnion', 'dataCompromised', 'dataCompromisedMalicious', 'usersDataCompromise'];
const PLATFORM_LIKE: readonly MetricKey[] = ['usersCompletelyUnavailable', 'usersLimitedAvailability', 'totalUsersInUnion', 'dataCompromised', 'dataCompromisedMalicious', 'usersDataCompromise'];

/** Measurements used by each entity-specific article of IR 2024/2690. */
export const METRICS_BY_TYPE: Readonly<Record<Exclude<ServiceType, 'other'>, { readonly article: string; readonly metrics: readonly MetricKey[] }>> = {
  dns: { article: '5', metrics: ['completeUnavailabilitySeconds', 'slowResponsePeriodSeconds', 'slowResponseAverageMs', 'dataCompromised', 'dnsMisconfigurationOnly', 'dnsIncorrectDomainNames', 'dnsDomainNamesManaged'] },
  'tld-registry': { article: '6', metrics: ['completeUnavailabilitySeconds', 'slowResponsePeriodSeconds', 'slowResponseAverageMs', 'dataCompromised'] },
  cloud: { article: '7', metrics: CLOUD_LIKE },
  'data-centre': { article: '8', metrics: ['completeUnavailabilitySeconds', 'limitedAvailabilitySeconds', 'dataCompromised', 'dataCompromisedMalicious', 'physicalAccessCompromised'] },
  cdn: { article: '9', metrics: CLOUD_LIKE },
  'managed-service': { article: '10', metrics: CLOUD_LIKE },
  'managed-security-service': { article: '10', metrics: CLOUD_LIKE },
  'online-marketplace': { article: '11', metrics: PLATFORM_LIKE },
  'online-search-engine': { article: '12', metrics: PLATFORM_LIKE },
  'social-network': { article: '13', metrics: PLATFORM_LIKE },
  'trust-service': { article: '14', metrics: ['completeUnavailabilitySeconds', 'weeklyUnavailabilitySeconds', 'usersLimitedAvailability', 'totalUsersInUnion', 'physicalAccessCompromised', 'dataCompromised', 'usersDataCompromise'] },
};

const IR_GENERAL: readonly GeneralKey[] = [
  'scheduledMaintenanceOnly',
  'directFinancialLossCents',
  'tradeSecretExfiltration',
  'deathOfNaturalPerson',
  'considerableHealthDamage',
  'maliciousUnauthorisedAccess',
  'accessCapableOfSevereDisruption',
];

/** Every question that can matter for the given service types, answered or not, in a stable order. */
export function questionsFor(serviceTypes: readonly ServiceType[]): Question[] {
  const out: Question[] = [];
  const relevant = serviceTypes.filter((t): t is Exclude<ServiceType, 'other'> => t !== 'other');
  if (relevant.length > 0) out.push(...IR_GENERAL.map(generalQuestion));
  for (const t of relevant) {
    const spec = METRICS_BY_TYPE[t];
    out.push(...spec.metrics.map((m) => metricQuestion(t, m, IR(`Article ${spec.article}`))));
  }
  if (serviceTypes.includes('other')) out.push(generalQuestion('severeDisruptionOrFinancialLoss'), generalQuestion('considerableDamageToOthers'));
  return out;
}
