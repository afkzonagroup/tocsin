// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import type { Tri } from '../util/validate.js';

/**
 * Type of service affected by the incident.
 *
 * The first eleven are the "relevant entities" of Implementing Regulation (EU) 2024/2690
 * (Article 1), for which Articles 3 to 14 of that Regulation define a significant incident.
 * `other` covers every other essential or important entity, for which only the general test of
 * Article 23(3) NIS2 applies (plus any national rules, which this tool does not encode).
 */
export const SERVICE_TYPES = [
  'dns',
  'tld-registry',
  'cloud',
  'data-centre',
  'cdn',
  'managed-service',
  'managed-security-service',
  'online-marketplace',
  'online-search-engine',
  'social-network',
  'trust-service',
  'other',
] as const;
export type ServiceType = (typeof SERVICE_TYPES)[number];

export const SERVICE_TYPE_LABELS: Readonly<Record<ServiceType, string>> = {
  dns: 'DNS service provider',
  'tld-registry': 'TLD name registry',
  cloud: 'Cloud computing service provider',
  'data-centre': 'Data centre service provider',
  cdn: 'Content delivery network provider',
  'managed-service': 'Managed service provider',
  'managed-security-service': 'Managed security service provider',
  'online-marketplace': 'Provider of an online marketplace',
  'online-search-engine': 'Provider of an online search engine',
  'social-network': 'Provider of a social networking services platform',
  'trust-service': 'Trust service provider',
  other: 'Other essential or important entity',
};

/** Measurements for one affected service. All optional: missing values make a criterion "unknown". */
export interface ServiceMetrics {
  /** Longest period of complete unavailability, seconds. IR Arts 5(a), 6(a), 7(a), 8(a), 9(a), 10(a), 14(a). */
  completeUnavailabilitySeconds?: number;
  /** Users in the Union for whom the service was completely unavailable. IR Arts 11(a), 12(a), 13(a). */
  usersCompletelyUnavailable?: number;
  /** Duration of limited availability, seconds. IR Arts 7(b), 8(b), 9(b), 10(b). */
  limitedAvailabilitySeconds?: number;
  /** Users (or relying parties) in the Union impacted by limited availability. IR Arts 7(b), 9(b), 10(b), 11(b), 12(b), 13(b), 14(c). */
  usersLimitedAvailability?: number;
  /** Total users (or users and relying parties) of the service in the Union. Needed for the "5 %" / "1 %" / "0.1 %" tests. */
  totalUsersInUnion?: number;
  /** DNS / TLD: length of the period with an average response time above 10 s, seconds. IR Arts 5(b), 6(b). */
  slowResponsePeriodSeconds?: number;
  /** DNS / TLD: average response time to DNS requests during that period, milliseconds. */
  slowResponseAverageMs?: number;
  /** Integrity, confidentiality or authenticity of the relevant data compromised. */
  dataCompromised?: Tri;
  /** …as a result of a suspectedly malicious action. IR Arts 7(c), 8(c), 9(c), 10(c), 11(c), 12(c), 13(c). */
  dataCompromisedMalicious?: Tri;
  /** Users (or relying parties) in the Union impacted by the data compromise. IR Arts 7(d), 9(d), 10(d), 11(d), 12(d), 13(d), 14(e). */
  usersDataCompromise?: number;
  /** DNS only: the only problem is incorrect data caused by misconfiguration. IR Art 5(c) exception. */
  dnsMisconfigurationOnly?: Tri;
  /** DNS only: number of domain names whose data is not correct. */
  dnsIncorrectDomainNames?: number;
  /** DNS only: number of domain names managed by the provider. */
  dnsDomainNamesManaged?: number;
  /** Data centre: physical access compromised (IR 8(d)). Trust service: physical access to restricted area or its protection compromised (IR 14(d)). */
  physicalAccessCompromised?: Tri;
  /** Trust service: total unavailability to users or relying parties in the calendar week, seconds. IR Art 14(b). */
  weeklyUnavailabilitySeconds?: number;
}

/** Answers used by the significance assessment. */
export interface AssessmentAnswers {
  /** IR Art 3(2): only a scheduled interruption or planned consequence of scheduled maintenance. */
  scheduledMaintenanceOnly?: Tri;
  /** IR Art 3(1)(a): direct financial loss (caused or capable of being caused), in euro cents. */
  directFinancialLossCents?: number;
  /** IR Art 3(1)(b). */
  tradeSecretExfiltration?: Tri;
  /** IR Art 3(1)(c). */
  deathOfNaturalPerson?: Tri;
  /** IR Art 3(1)(d). */
  considerableHealthDamage?: Tri;
  /** IR Art 3(1)(e): successful, suspectedly malicious and unauthorised access occurred … */
  maliciousUnauthorisedAccess?: Tri;
  /** … which is capable of causing severe operational disruption. */
  accessCapableOfSevereDisruption?: Tri;
  /** NIS2 Art 23(3)(a): severe operational disruption of the services or financial loss for the entity. */
  severeDisruptionOrFinancialLoss?: Tri;
  /** NIS2 Art 23(3)(b): considerable material or non-material damage to other natural or legal persons. */
  considerableDamageToOthers?: Tri;
  /** Per affected service. */
  services?: Partial<Record<ServiceType, ServiceMetrics>>;
}

export const STAGES = ['early-warning', 'incident-notification', 'intermediate-report', 'progress-report', 'final-report'] as const;
export type Stage = (typeof STAGES)[number];

export const STAGE_LABELS: Readonly<Record<Stage, string>> = {
  'early-warning': 'Early warning',
  'incident-notification': 'Incident notification',
  'intermediate-report': 'Intermediate report',
  'progress-report': 'Progress report',
  'final-report': 'Final report',
};

/** Free-text and structured facts the reports are built from. */
export interface IncidentDetails {
  summary?: string;
  description?: string;
  severity?: string;
  impact?: string;
  suspectedUnlawfulOrMalicious?: Tri;
  suspectedUnlawfulOrMaliciousNote?: string;
  crossBorderImpact?: Tri;
  crossBorderImpactDetails?: string;
  affectedMemberStates?: string[];
  indicatorsOfCompromise?: string[];
  threatTypeOrRootCause?: string;
  mitigationApplied?: string;
  mitigationOngoing?: string;
  progressStatus?: string;
  /** Free label that groups incidents with the same apparent root cause (IR Art 4(b)). Human judgement. */
  rootCauseKey?: string;
  /** Art 23(1) second sentence: likely to adversely affect the provision of services to recipients. */
  recipientsLikelyAffected?: Tri;
  /** Art 23(4) last subparagraph: the incident has an impact on the provision of trust services. */
  trustServicesImpacted?: Tri;
  /** Optional free reference used inside the entity (ticket number etc.). */
  internalReference?: string;
}

export interface StoredAssessment {
  readonly assessedAt: string;
  readonly answers: AssessmentAnswers;
  readonly outcome: 'significant' | 'not-significant' | 'undetermined';
  readonly metCriteria: readonly string[];
}

export interface Submission {
  readonly stage: Exclude<Stage, 'intermediate-report'>;
  readonly submittedAt: string;
  readonly recordedAt: string;
  readonly authorityReference?: string;
  /** SHA-256 of the canonical JSON of {@link snapshot}. */
  readonly contentSha256: string;
  /** The report content as submitted. */
  readonly snapshot: unknown;
}

export interface IntermediateRequest {
  readonly id: string;
  readonly requestedAt: string;
  readonly requestedBy?: string;
  /** Deadline set by the CSIRT / competent authority in its request, if any. Art 23(4)(c) sets none. */
  readonly dueAt?: string;
  statusUpdate?: string;
  submission?: {
    readonly submittedAt: string;
    readonly recordedAt: string;
    readonly authorityReference?: string;
    readonly contentSha256: string;
    readonly snapshot: unknown;
  };
}

export interface RecipientCommunication {
  readonly id: string;
  /** Art 23(1) incident notice to recipients, or Art 23(2) communication on a significant cyber threat. */
  readonly kind: 'incident-23-1' | 'cyber-threat-23-2';
  readonly communicatedAt: string;
  readonly audience: string;
  readonly summary: string;
  readonly measuresOrRemedies?: string;
}

export interface Incident {
  readonly id: string;
  title: string;
  readonly createdAt: string;
  updatedAt: string;
  serviceTypes: ServiceType[];
  occurredAt?: string;
  detectedAt?: string;
  /** Moment the entity became aware of the significant incident (recital 31 IR 2024/2690). Starts the clocks. */
  awareAt?: string;
  /** The incident is no longer ongoing and its handling has concluded (Art 23(4)(e)). */
  handlingConcludedAt?: string;
  details: IncidentDetails;
  assessment?: StoredAssessment;
  submissions: Submission[];
  intermediateRequests: IntermediateRequest[];
  recipientCommunications: RecipientCommunication[];
  /** IDs of individually non-significant incidents this one collects under IR Art 4. */
  linkedIncidentIds: string[];
}
