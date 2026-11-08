// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { ref, type LegalRef } from '../legal/refs.js';
import { SERVICE_TYPE_LABELS, type AssessmentAnswers, type ServiceMetrics, type ServiceType } from '../model/types.js';
import type { Tri } from '../util/validate.js';
import { formatDuration } from '../time/periods.js';
import { generalQuestion, metricQuestion, type GeneralKey, type MetricKey, type Question } from './questions.js';
import {
  all,
  exceedsShareOrCap,
  financialLossStatus,
  FIVE_PERCENT,
  formatEuro,
  fromTri,
  moreThan,
  ONE_HOUR,
  ONE_HUNDRED,
  ONE_MILLION,
  ONE_PERCENT,
  ONE_TENTH_PERCENT,
  TEN_SECONDS_MS,
  THIRTY_MINUTES,
  TWENTY_MINUTES,
  TWO_HUNDRED_THOUSAND,
  type Share,
  type Status,
} from './thresholds.js';

export type { Status } from './thresholds.js';

/** Result of one criterion. */
export interface CriterionResult {
  /** Stable id, e.g. "IR-3-1-a", "IR-7-b", "NIS2-23-3-a". */
  readonly id: string;
  readonly ref: LegalRef;
  /** The criterion in short form, thresholds included. */
  readonly criterion: string;
  readonly status: Status;
  /** Why the status was reached, with the numbers used. */
  readonly reason: string;
  readonly serviceType?: ServiceType;
  /** Questions that must be answered to decide an "unknown" criterion. */
  readonly questions: readonly Question[];
}

export interface AssessmentInput {
  readonly serviceTypes: readonly ServiceType[];
  readonly answers: AssessmentAnswers;
  /** Total annual turnover in the preceding financial year, euro cents (IR Art 3(1)(a)). */
  readonly turnoverCents?: number;
  /** Result of the recurring-incident check for this incident (IR Art 3(1)(f) and Art 4), when known. */
  readonly recurring?: { readonly status: Status; readonly reason: string };
}

export interface AssessmentResult {
  readonly outcome: 'significant' | 'not-significant' | 'undetermined';
  /** The criteria that are met (the reasons for "significant"). */
  readonly reasons: readonly CriterionResult[];
  /** Every criterion that was evaluated. */
  readonly criteria: readonly CriterionResult[];
  /** De-duplicated questions still open. */
  readonly openQuestions: readonly Question[];
  readonly notes: readonly string[];
}

const IR = (p: string): LegalRef => ref('IR2024_2690', p);

/** Relevant entity types under IR 2024/2690 Article 1. */
export function isRelevantEntityType(t: ServiceType): boolean {
  return t !== 'other';
}

function unknownTri(t: Tri | undefined): boolean {
  return t === undefined || t === 'unknown';
}

interface Ctx {
  readonly service: ServiceType;
  readonly m: ServiceMetrics;
  readonly article: string;
}

function q(ctx: Ctx, keys: readonly MetricKey[], point: string): Question[] {
  return keys.filter((k) => ctx.m[k] === undefined || ctx.m[k] === 'unknown').map((k) => metricQuestion(ctx.service, k, IR(`Article ${ctx.article}, point (${point})`)));
}

function result(ctx: Ctx, point: string, criterion: string, status: Status, reason: string, questions: Question[]): CriterionResult {
  return {
    id: `IR-${ctx.article}-${point}`,
    ref: IR(`Article ${ctx.article}, point (${point})`),
    criterion,
    status,
    reason,
    serviceType: ctx.service,
    questions: status === 'unknown' ? questions : [],
  };
}

function dur(s: number | undefined): string {
  return s === undefined ? 'not given' : formatDuration(s);
}

function num(n: number | undefined): string {
  return n === undefined ? 'not given' : n.toLocaleString('en-GB');
}

// ---------- shared criterion shapes ----------

function completeUnavailableMoreThan(ctx: Ctx, point: string, limit: number, label: string): CriterionResult {
  const v = ctx.m.completeUnavailabilitySeconds;
  const s = moreThan(v, limit);
  return result(ctx, point, `Completely unavailable for more than ${label}`, s, `Complete unavailability: ${dur(v)}; threshold: more than ${label}.`, q(ctx, ['completeUnavailabilitySeconds'], point));
}

function completeUnavailableAtAll(ctx: Ctx, point: string, criterion: string): CriterionResult {
  const v = ctx.m.completeUnavailabilitySeconds;
  const s = moreThan(v, 0);
  return result(ctx, point, criterion, s, `Complete unavailability: ${dur(v)}; any complete unavailability meets this criterion.`, q(ctx, ['completeUnavailabilitySeconds'], point));
}

function usersThreshold(
  ctx: Ctx,
  point: string,
  criterion: string,
  countKey: 'usersLimitedAvailability' | 'usersCompletelyUnavailable' | 'usersDataCompromise',
  share: Share,
  cap: number,
): { status: Status; reason: string; questions: Question[] } {
  const count = ctx.m[countKey];
  const total = ctx.m.totalUsersInUnion;
  const status = exceedsShareOrCap(count, total, share, cap);
  const reason = `${criterion}: ${num(count)} of ${num(total)} users in the Union; threshold: more than ${share.label} or more than ${cap.toLocaleString('en-GB')}, whichever is smaller.`;
  const questions = q(ctx, count !== undefined && count > cap ? [countKey] : [countKey, 'totalUsersInUnion'], point);
  return { status, reason, questions };
}

function limitedForUsersAndHour(ctx: Ctx, point: string): CriterionResult {
  const u = usersThreshold(ctx, point, 'Users impacted by limited availability', 'usersLimitedAvailability', FIVE_PERCENT, ONE_MILLION);
  const d = moreThan(ctx.m.limitedAvailabilitySeconds, ONE_HOUR);
  return result(
    ctx,
    point,
    'Availability limited for more than 5 % of users in the Union or more than 1 million users (whichever is smaller), for more than one hour',
    all(u.status, d),
    `${u.reason} Duration: ${dur(ctx.m.limitedAvailabilitySeconds)}; threshold: more than 1h.`,
    [...u.questions, ...q(ctx, ['limitedAvailabilitySeconds'], point)],
  );
}

function compromisedMalicious(ctx: Ctx, point: string): CriterionResult {
  const s = all(fromTri(ctx.m.dataCompromised), fromTri(ctx.m.dataCompromisedMalicious));
  return result(
    ctx,
    point,
    'Integrity, confidentiality or authenticity of service data compromised as a result of a suspectedly malicious action',
    s,
    `Data compromised: ${ctx.m.dataCompromised ?? 'not answered'}; suspectedly malicious action: ${ctx.m.dataCompromisedMalicious ?? 'not answered'}.`,
    q(ctx, ['dataCompromised', 'dataCompromisedMalicious'], point),
  );
}

function compromisedUsers(ctx: Ctx, point: string, share: Share, cap: number): CriterionResult {
  const u = usersThreshold(ctx, point, 'Users impacted by the data compromise', 'usersDataCompromise', share, cap);
  const s = all(fromTri(ctx.m.dataCompromised), u.status);
  return result(
    ctx,
    point,
    `Integrity, confidentiality or authenticity of service data compromised with an impact on more than ${share.label} of users in the Union or more than ${cap.toLocaleString('en-GB')} (whichever is smaller)`,
    s,
    `Data compromised: ${ctx.m.dataCompromised ?? 'not answered'}. ${u.reason}`,
    [...q(ctx, ['dataCompromised'], point), ...u.questions],
  );
}

function slowResponse(ctx: Ctx, point: string): CriterionResult {
  const s = all(moreThan(ctx.m.slowResponsePeriodSeconds, ONE_HOUR), moreThan(ctx.m.slowResponseAverageMs, TEN_SECONDS_MS));
  return result(
    ctx,
    point,
    'For a period of more than one hour, the average response time to DNS requests is more than 10 seconds',
    s,
    `Period: ${dur(ctx.m.slowResponsePeriodSeconds)}; average response time: ${ctx.m.slowResponseAverageMs === undefined ? 'not given' : `${ctx.m.slowResponseAverageMs} ms`}.`,
    q(ctx, ['slowResponsePeriodSeconds', 'slowResponseAverageMs'], point),
  );
}

function physical(ctx: Ctx, point: string, criterion: string): CriterionResult {
  return result(ctx, point, criterion, fromTri(ctx.m.physicalAccessCompromised), `Physical access compromised: ${ctx.m.physicalAccessCompromised ?? 'not answered'}.`, q(ctx, ['physicalAccessCompromised'], point));
}

// ---------- IR Article 5 DNS (c): exception for misconfiguration ----------

function dnsIntegrity(ctx: Ctx): CriterionResult {
  const m = ctx.m;
  const point = 'c';
  const criterion =
    'Integrity, confidentiality or authenticity of data related to the authoritative resolution service compromised, except where fewer than 1 000 domain names, amounting to no more than 1 % of the domain names managed, are not correct because of misconfiguration';
  const compromised = fromTri(m.dataCompromised);
  if (compromised !== 'met') {
    return result(ctx, point, criterion, compromised, `Data compromised: ${m.dataCompromised ?? 'not answered'}.`, q(ctx, ['dataCompromised'], point));
  }
  // The exception needs all three: misconfiguration only, fewer than 1 000 names, no more than 1 %.
  const incorrect = m.dnsIncorrectDomainNames;
  const managed = m.dnsDomainNamesManaged;
  const countsKnown = incorrect !== undefined && managed !== undefined;
  const countsInException = countsKnown && incorrect < 1000 && incorrect * 100 <= managed;
  const countsOutsideException = (incorrect !== undefined && incorrect >= 1000) || (countsKnown && incorrect * 100 > managed);
  const counts = `${num(incorrect)} incorrect of ${num(managed)} domain names managed`;
  if (m.dnsMisconfigurationOnly === 'no' || countsOutsideException) {
    return result(ctx, point, criterion, 'met', `Data compromised; the misconfiguration exception does not apply (misconfiguration only: ${m.dnsMisconfigurationOnly ?? 'not answered'}; ${counts}).`, []);
  }
  if (m.dnsMisconfigurationOnly === 'yes' && countsInException) {
    return result(ctx, point, criterion, 'not-met', `Only misconfiguration, ${counts}: within the exception (fewer than 1 000 and no more than 1 %).`, []);
  }
  return result(ctx, point, criterion, 'unknown', `Data compromised; the misconfiguration exception cannot be checked yet (${counts}).`, q(ctx, ['dnsMisconfigurationOnly', 'dnsIncorrectDomainNames', 'dnsDomainNamesManaged'], point));
}

// ---------- entity-specific criteria, IR Articles 5 to 14 ----------

type Evaluator = (ctx: Ctx) => CriterionResult[];

const SPECIFIC: Readonly<Record<Exclude<ServiceType, 'other'>, { article: string; evaluate: Evaluator }>> = {
  dns: {
    article: '5',
    evaluate: (c) => [completeUnavailableMoreThan(c, 'a', THIRTY_MINUTES, '30 minutes'), slowResponse(c, 'b'), dnsIntegrity(c)],
  },
  'tld-registry': {
    article: '6',
    evaluate: (c) => [
      completeUnavailableAtAll(c, 'a', 'An authoritative domain name resolution service is completely unavailable'),
      slowResponse(c, 'b'),
      result(
        c,
        'c',
        'Integrity, confidentiality or authenticity of data related to the technical operation of the TLD compromised',
        fromTri(c.m.dataCompromised),
        `Data compromised: ${c.m.dataCompromised ?? 'not answered'}.`,
        q(c, ['dataCompromised'], 'c'),
      ),
    ],
  },
  cloud: { article: '7', evaluate: (c) => cloudLike(c) },
  'data-centre': {
    article: '8',
    evaluate: (c) => [
      completeUnavailableAtAll(c, 'a', 'A data centre service of a data centre operated by the provider is completely unavailable'),
      result(
        c,
        'b',
        'Availability of a data centre service limited for more than one hour',
        moreThan(c.m.limitedAvailabilitySeconds, ONE_HOUR),
        `Limited availability: ${dur(c.m.limitedAvailabilitySeconds)}; threshold: more than 1h.`,
        q(c, ['limitedAvailabilitySeconds'], 'b'),
      ),
      compromisedMalicious(c, 'c'),
      physical(c, 'd', 'Physical access to a data centre operated by the provider is compromised'),
    ],
  },
  cdn: { article: '9', evaluate: (c) => cloudLike(c) },
  'managed-service': { article: '10', evaluate: (c) => cloudLike(c) },
  'managed-security-service': { article: '10', evaluate: (c) => cloudLike(c) },
  'online-marketplace': { article: '11', evaluate: (c) => platformLike(c) },
  'online-search-engine': { article: '12', evaluate: (c) => platformLike(c) },
  'social-network': { article: '13', evaluate: (c) => platformLike(c) },
  'trust-service': {
    article: '14',
    evaluate: (c) => {
      const lim = usersThreshold(c, 'c', 'Users or relying parties impacted by limited availability', 'usersLimitedAvailability', ONE_PERCENT, TWO_HUNDRED_THOUSAND);
      return [
        completeUnavailableMoreThan(c, 'a', TWENTY_MINUTES, '20 minutes'),
        result(
          c,
          'b',
          'Trust service unavailable to users or relying parties for more than one hour calculated on a calendar week basis',
          moreThan(c.m.weeklyUnavailabilitySeconds, ONE_HOUR),
          `Unavailability in the calendar week: ${dur(c.m.weeklyUnavailabilitySeconds)}; threshold: more than 1h.`,
          q(c, ['weeklyUnavailabilitySeconds'], 'b'),
        ),
        result(
          c,
          'c',
          'More than 1 % of users or relying parties in the Union, or more than 200 000 (whichever is smaller), impacted by limited availability',
          lim.status,
          lim.reason.replace('users in the Union', 'users or relying parties in the Union'),
          lim.questions,
        ),
        physical(c, 'd', 'Physical access to a restricted area holding network and information systems, or the protection of such access, is compromised'),
        compromisedUsers(c, 'e', ONE_TENTH_PERCENT, ONE_HUNDRED),
      ];
    },
  },
};

/** IR Arts 7, 9 and 10 share the same four criteria. */
function cloudLike(c: Ctx): CriterionResult[] {
  return [completeUnavailableMoreThan(c, 'a', THIRTY_MINUTES, '30 minutes'), limitedForUsersAndHour(c, 'b'), compromisedMalicious(c, 'c'), compromisedUsers(c, 'd', FIVE_PERCENT, ONE_MILLION)];
}

/** IR Arts 11, 12 and 13 share the same four criteria. */
function platformLike(c: Ctx): CriterionResult[] {
  const a = usersThreshold(c, 'a', 'Users for whom the service was completely unavailable', 'usersCompletelyUnavailable', FIVE_PERCENT, ONE_MILLION);
  const b = usersThreshold(c, 'b', 'Users impacted by limited availability', 'usersLimitedAvailability', FIVE_PERCENT, ONE_MILLION);
  return [
    result(c, 'a', 'Completely unavailable for more than 5 % of users in the Union or more than 1 million users (whichever is smaller)', a.status, a.reason, a.questions),
    result(c, 'b', 'More than 5 % of users in the Union or more than 1 million users (whichever is smaller) impacted by limited availability', b.status, b.reason, b.questions),
    compromisedMalicious(c, 'c'),
    compromisedUsers(c, 'd', FIVE_PERCENT, ONE_MILLION),
  ];
}

// ---------- general criteria ----------

function general(answers: AssessmentAnswers, turnoverCents: number | undefined, recurring: AssessmentInput['recurring']): CriterionResult[] {
  const g = (key: GeneralKey): Question[] => [generalQuestion(key)];
  const loss = answers.directFinancialLossCents;
  const lossStatus = financialLossStatus(loss, turnoverCents);
  const lossQuestions: Question[] = [];
  if (loss === undefined) lossQuestions.push(generalQuestion('directFinancialLossCents'));
  const threshold =
    turnoverCents === undefined
      ? 'EUR 500 000 or 5 % of turnover (turnover not configured)'
      : `the lower of EUR 500 000 and 5 % of turnover (5 % of ${formatEuro(turnoverCents)} is about ${formatEuro(Math.floor(turnoverCents / 20))})`;
  const tri = (key: GeneralKey, point: string, criterion: string): CriterionResult => {
    const v = answers[key] as Tri | undefined;
    const status = fromTri(v);
    return { id: `IR-3-1-${point}`, ref: IR(`Article 3(1), point (${point})`), criterion, status, reason: `Answer: ${v ?? 'not answered'}.`, questions: status === 'unknown' ? g(key) : [] };
  };
  const access = all(fromTri(answers.maliciousUnauthorisedAccess), fromTri(answers.accessCapableOfSevereDisruption));
  const accessQuestions = (['maliciousUnauthorisedAccess', 'accessCapableOfSevereDisruption'] as const).filter((k) => unknownTri(answers[k])).map(generalQuestion);
  const out: CriterionResult[] = [
    {
      id: 'IR-3-1-a',
      ref: IR('Article 3(1), point (a)'),
      criterion: 'Direct financial loss exceeding EUR 500 000 or 5 % of total annual turnover in the preceding financial year, whichever is lower',
      status: lossStatus,
      reason:
        `Loss: ${loss === undefined ? 'not given' : formatEuro(loss)}; threshold: more than ${threshold}.` +
        (lossStatus === 'unknown' && loss !== undefined ? ' Configure the turnover to decide.' : ''),
      questions: lossStatus === 'unknown' ? lossQuestions : [],
    },
    tri('tradeSecretExfiltration', 'b', 'Exfiltration of trade secrets of the entity (caused or capable of being caused)'),
    tri('deathOfNaturalPerson', 'c', 'Death of a natural person (caused or capable of being caused)'),
    tri('considerableHealthDamage', 'd', "Considerable damage to a natural person's health (caused or capable of being caused)"),
    {
      id: 'IR-3-1-e',
      ref: IR('Article 3(1), point (e)'),
      criterion: 'Successful, suspectedly malicious and unauthorised access to network and information systems, capable of causing severe operational disruption',
      status: access,
      reason: `Access: ${answers.maliciousUnauthorisedAccess ?? 'not answered'}; capable of severe disruption: ${answers.accessCapableOfSevereDisruption ?? 'not answered'}.`,
      questions: access === 'unknown' ? accessQuestions : [],
    },
    {
      id: 'IR-3-1-f',
      ref: IR('Article 3(1), point (f), and Article 4'),
      criterion: 'Recurring incidents: at least twice within 6 months, same apparent root cause, collectively meeting point (a)',
      status: recurring?.status ?? 'not-met',
      reason: recurring?.reason ?? 'Not evaluated for a single incident. Run the recurring-incident check across the register.',
      questions: [],
    },
  ];
  return out;
}

function nis2General(answers: AssessmentAnswers): CriterionResult[] {
  const mk = (key: 'severeDisruptionOrFinancialLoss' | 'considerableDamageToOthers', point: string, criterion: string): CriterionResult => {
    const v = answers[key];
    const status = fromTri(v);
    return {
      id: `NIS2-23-3-${point}`,
      ref: ref('NIS2', `Article 23(3), point (${point})`),
      criterion,
      status,
      reason: `Answer: ${v ?? 'not answered'} (human judgement).`,
      serviceType: 'other',
      questions: status === 'unknown' ? [generalQuestion(key)] : [],
    };
  };
  return [
    mk('severeDisruptionOrFinancialLoss', 'a', 'Has caused or is capable of causing severe operational disruption of the services or financial loss for the entity'),
    mk('considerableDamageToOthers', 'b', 'Has affected or is capable of affecting other natural or legal persons by causing considerable material or non-material damage'),
  ];
}

/**
 * Assesses whether an incident is significant.
 *
 * - For the relevant entities of IR 2024/2690 (DNS, TLD, cloud, data centre, CDN, MSP, MSSP, online
 *   marketplaces, search engines, social networks, trust services) the criteria of Articles 3 to 14 of
 *   that Regulation are applied. Recital 30 says they are exhaustive (without prejudice to Article 5 NIS2).
 * - For other entities, the two tests of Article 23(3) NIS2 are asked as questions; national rules may
 *   specify them further and are not encoded.
 *
 * The outcome is "significant" when any criterion is met, "not-significant" when every criterion is
 * answered and none is met (or IR Art 3(2) applies), and "undetermined" otherwise.
 *
 * @example
 * assessSignificance({ serviceTypes: ['cloud'], answers: { services: { cloud: { completeUnavailabilitySeconds: 1801 } } } }).outcome
 * // 'significant' (IR Art 7(a): more than 30 minutes)
 */
export function assessSignificance(input: AssessmentInput): AssessmentResult {
  const { answers } = input;
  const relevant = input.serviceTypes.filter(isRelevantEntityType);
  const notes: string[] = [];
  const criteria: CriterionResult[] = [];

  if (relevant.length > 0) {
    criteria.push(...general(answers, input.turnoverCents, input.recurring));
    const seen = new Set<string>();
    for (const t of relevant) {
      const spec = SPECIFIC[t as Exclude<ServiceType, 'other'>];
      const ctx: Ctx = { service: t, m: answers.services?.[t] ?? {}, article: spec.article };
      for (const r of spec.evaluate(ctx)) {
        const key = `${r.id}|${t}`;
        if (!seen.has(key)) {
          seen.add(key);
          criteria.push(r);
        }
      }
    }
    if (input.turnoverCents === undefined) notes.push('Turnover is not configured: the 5 % limit of IR Art 3(1)(a) cannot be applied; only EUR 500 000 is checked.');
  }
  if (input.serviceTypes.includes('other')) {
    criteria.push(...nis2General(answers));
    notes.push(
      `${SERVICE_TYPE_LABELS.other}: IR 2024/2690 does not apply. Article 23(3) NIS2 is applied as two questions; check national rules and guidance, which may set thresholds.`,
    );
  }

  const met = criteria.filter((c) => c.status === 'met');
  const unknown = criteria.filter((c) => c.status === 'unknown');

  if (relevant.length > 0 && answers.scheduledMaintenanceOnly === 'yes' && !input.serviceTypes.includes('other')) {
    return {
      outcome: 'not-significant',
      reasons: [],
      criteria,
      openQuestions: [],
      notes: [...notes, 'IR Art 3(2): scheduled interruptions of service and planned consequences of scheduled maintenance are not significant incidents.'],
    };
  }

  const openQuestions: Question[] = [];
  const ids = new Set<string>();
  const addQ = (qs: readonly Question[]): void => {
    for (const x of qs) {
      if (!ids.has(x.id)) {
        ids.add(x.id);
        openQuestions.push(x);
      }
    }
  };
  if (relevant.length > 0 && unknownTri(answers.scheduledMaintenanceOnly)) {
    addQ([generalQuestion('scheduledMaintenanceOnly')]);
    if (met.length > 0) notes.push('Significant unless IR Art 3(2) applies (only a scheduled interruption or planned maintenance consequence): answer that question.');
  }
  for (const c of unknown) addQ(c.questions);

  const outcome = met.length > 0 ? 'significant' : unknown.length > 0 ? 'undetermined' : 'not-significant';
  return { outcome, reasons: met, criteria, openQuestions, notes };
}
