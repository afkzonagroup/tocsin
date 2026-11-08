// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { describe, expect, it } from 'vitest';
import { applyAnswerText, answerText } from '../src/assess/answers.js';
import { assessSignificance, type CriterionResult } from '../src/assess/assess.js';
import { findRecurringIncidents } from '../src/assess/recurring.js';
import { questionsFor } from '../src/assess/questions.js';
import { exceedsShareOrCap, FIVE_PERCENT, financialLossStatus, formatEuro, ONE_PERCENT, ONE_TENTH_PERCENT } from '../src/assess/thresholds.js';
import type { AssessmentAnswers, ServiceMetrics, ServiceType } from '../src/model/types.js';
import { incident } from './helpers.js';

function crit(type: ServiceType, m: ServiceMetrics, id: string, extra: AssessmentAnswers = {}, turnoverCents?: number): CriterionResult {
  const r = assessSignificance({ serviceTypes: [type], answers: { ...extra, services: { [type]: m } }, ...(turnoverCents === undefined ? {} : { turnoverCents }) });
  const c = r.criteria.find((x) => x.id === id && (x.serviceType === undefined || x.serviceType === type));
  if (c === undefined) throw new Error(`criterion ${id} not evaluated for ${type}`);
  return c;
}

const status = (type: ServiceType, m: ServiceMetrics, id: string): string => crit(type, m, id).status;

describe('threshold arithmetic (exact integers, strict "more than")', () => {
  it('"more than 5 % or more than 1 million, whichever is smaller"', () => {
    expect(exceedsShareOrCap(50, 1000, FIVE_PERCENT, 1_000_000)).toBe('not-met');
    expect(exceedsShareOrCap(51, 1000, FIVE_PERCENT, 1_000_000)).toBe('met');
    // 5 % of 100 million is 5 million; 1 million is smaller, so it is the threshold.
    expect(exceedsShareOrCap(1_000_000, 100_000_000, FIVE_PERCENT, 1_000_000)).toBe('not-met');
    expect(exceedsShareOrCap(1_000_001, 100_000_000, FIVE_PERCENT, 1_000_000)).toBe('met');
    // 5 % of 21 = 1.05 -> 2 users exceed it, 1 does not.
    expect(exceedsShareOrCap(1, 21, FIVE_PERCENT, 1_000_000)).toBe('not-met');
    expect(exceedsShareOrCap(2, 21, FIVE_PERCENT, 1_000_000)).toBe('met');
  });

  it('unknown inputs', () => {
    expect(exceedsShareOrCap(undefined, 1000, FIVE_PERCENT, 1_000_000)).toBe('unknown');
    expect(exceedsShareOrCap(10, undefined, FIVE_PERCENT, 1_000_000)).toBe('unknown');
    expect(exceedsShareOrCap(0, undefined, FIVE_PERCENT, 1_000_000)).toBe('not-met');
    expect(exceedsShareOrCap(1_000_001, undefined, FIVE_PERCENT, 1_000_000)).toBe('met');
  });

  it('1 % / 200 000 and 0,1 % / 100 (trust services)', () => {
    expect(exceedsShareOrCap(100, 10_000, ONE_PERCENT, 200_000)).toBe('not-met');
    expect(exceedsShareOrCap(101, 10_000, ONE_PERCENT, 200_000)).toBe('met');
    expect(exceedsShareOrCap(200_000, 100_000_000, ONE_PERCENT, 200_000)).toBe('not-met');
    expect(exceedsShareOrCap(200_001, 100_000_000, ONE_PERCENT, 200_000)).toBe('met');
    expect(exceedsShareOrCap(50, 50_000, ONE_TENTH_PERCENT, 100)).toBe('not-met');
    expect(exceedsShareOrCap(51, 50_000, ONE_TENTH_PERCENT, 100)).toBe('met');
    expect(exceedsShareOrCap(100, 1_000_000, ONE_TENTH_PERCENT, 100)).toBe('not-met');
    expect(exceedsShareOrCap(101, 1_000_000, ONE_TENTH_PERCENT, 100)).toBe('met');
  });

  it('IR Art 3(1)(a): EUR 500 000 or 5 % of turnover, whichever is lower', () => {
    expect(financialLossStatus(50_000_000, undefined)).toBe('unknown'); // exactly EUR 500 000, turnover unknown
    expect(financialLossStatus(50_000_001, undefined)).toBe('met');
    expect(financialLossStatus(50_000_000, 10_000_000_000)).toBe('not-met'); // turnover 100 M: 5 % = 5 M, cap 500 k lower
    expect(financialLossStatus(50_000_001, 10_000_000_000)).toBe('met');
    expect(financialLossStatus(5_000_000, 100_000_000)).toBe('not-met'); // turnover 1 M: 5 % = EUR 50 000
    expect(financialLossStatus(5_000_001, 100_000_000)).toBe('met');
    expect(financialLossStatus(4, 99)).toBe('not-met'); // 5 % of 99 cents = 4.95
    expect(financialLossStatus(5, 99)).toBe('met');
    expect(financialLossStatus(0, 0)).toBe('not-met');
    expect(formatEuro(50_000_001)).toBe('EUR 500 000.01');
  });
});

describe('IR 2024/2690 Article 3(1) general criteria', () => {
  const general = (answers: AssessmentAnswers, id: string, turnoverCents?: number): string =>
    assessSignificance({ serviceTypes: ['cloud'], answers, ...(turnoverCents === undefined ? {} : { turnoverCents }) }).criteria.find((c) => c.id === id)?.status ?? 'missing';

  it('(a) financial loss', () => {
    expect(general({ directFinancialLossCents: 50_000_001 }, 'IR-3-1-a')).toBe('met');
    expect(general({ directFinancialLossCents: 5_000_000 }, 'IR-3-1-a', 100_000_000)).toBe('not-met');
    expect(general({}, 'IR-3-1-a')).toBe('unknown');
  });

  it('(b)-(d) are yes/no questions', () => {
    for (const [key, id] of [
      ['tradeSecretExfiltration', 'IR-3-1-b'],
      ['deathOfNaturalPerson', 'IR-3-1-c'],
      ['considerableHealthDamage', 'IR-3-1-d'],
    ] as const) {
      expect(general({ [key]: 'yes' }, id)).toBe('met');
      expect(general({ [key]: 'no' }, id)).toBe('not-met');
      expect(general({ [key]: 'unknown' }, id)).toBe('unknown');
      expect(general({}, id)).toBe('unknown');
    }
  });

  it('(e) needs a successful malicious unauthorised access AND capability of severe disruption', () => {
    expect(general({ maliciousUnauthorisedAccess: 'yes', accessCapableOfSevereDisruption: 'yes' }, 'IR-3-1-e')).toBe('met');
    expect(general({ maliciousUnauthorisedAccess: 'yes', accessCapableOfSevereDisruption: 'no' }, 'IR-3-1-e')).toBe('not-met');
    expect(general({ maliciousUnauthorisedAccess: 'no' }, 'IR-3-1-e')).toBe('not-met');
    expect(general({ maliciousUnauthorisedAccess: 'yes' }, 'IR-3-1-e')).toBe('unknown');
  });

  it('(f) recurring is reported through the register check', () => {
    expect(general({}, 'IR-3-1-f')).toBe('not-met');
    const r = assessSignificance({ serviceTypes: ['cloud'], answers: {}, recurring: { status: 'met', reason: 'x' } });
    expect(r.outcome).toBe('significant');
  });

  it('Art 3(2): scheduled maintenance is not a significant incident', () => {
    const r = assessSignificance({ serviceTypes: ['cloud'], answers: { scheduledMaintenanceOnly: 'yes', services: { cloud: { completeUnavailabilitySeconds: 7200 } } } });
    expect(r.outcome).toBe('not-significant');
    expect(r.notes.join(' ')).toMatch(/Art 3\(2\)/u);
  });

  it('asks about Art 3(2) when a criterion is met but maintenance was not ruled out', () => {
    const r = assessSignificance({ serviceTypes: ['cloud'], answers: { services: { cloud: { completeUnavailabilitySeconds: 7200 } } } });
    expect(r.outcome).toBe('significant');
    expect(r.openQuestions.map((q) => q.id)).toContain('scheduledMaintenanceOnly');
  });
});

describe('IR Article 5 — DNS service providers', () => {
  it('(a) complete unavailability more than 30 minutes', () => {
    expect(status('dns', { completeUnavailabilitySeconds: 1800 }, 'IR-5-a')).toBe('not-met');
    expect(status('dns', { completeUnavailabilitySeconds: 1801 }, 'IR-5-a')).toBe('met');
    expect(status('dns', {}, 'IR-5-a')).toBe('unknown');
  });

  it('(b) average response time more than 10 s for more than one hour', () => {
    expect(status('dns', { slowResponsePeriodSeconds: 3601, slowResponseAverageMs: 10_001 }, 'IR-5-b')).toBe('met');
    expect(status('dns', { slowResponsePeriodSeconds: 3600, slowResponseAverageMs: 20_000 }, 'IR-5-b')).toBe('not-met');
    expect(status('dns', { slowResponsePeriodSeconds: 7200, slowResponseAverageMs: 10_000 }, 'IR-5-b')).toBe('not-met');
    expect(status('dns', { slowResponsePeriodSeconds: 7200 }, 'IR-5-b')).toBe('unknown');
  });

  it('(c) data compromised, except fewer than 1 000 names and no more than 1 % incorrect by misconfiguration', () => {
    const c = (m: ServiceMetrics): string => status('dns', m, 'IR-5-c');
    expect(c({ dataCompromised: 'no' })).toBe('not-met');
    expect(c({ dataCompromised: 'yes', dnsMisconfigurationOnly: 'no' })).toBe('met');
    expect(c({ dataCompromised: 'yes', dnsMisconfigurationOnly: 'yes', dnsIncorrectDomainNames: 999, dnsDomainNamesManaged: 99_900 })).toBe('not-met'); // exactly 1 %
    expect(c({ dataCompromised: 'yes', dnsMisconfigurationOnly: 'yes', dnsIncorrectDomainNames: 999, dnsDomainNamesManaged: 99_899 })).toBe('met'); // over 1 %
    expect(c({ dataCompromised: 'yes', dnsMisconfigurationOnly: 'yes', dnsIncorrectDomainNames: 1000, dnsDomainNamesManaged: 10_000_000 })).toBe('met'); // not fewer than 1 000
    expect(c({ dataCompromised: 'yes', dnsMisconfigurationOnly: 'yes' })).toBe('unknown');
    expect(c({ dataCompromised: 'yes', dnsIncorrectDomainNames: 5, dnsDomainNamesManaged: 10_000 })).toBe('unknown'); // misconfiguration not answered
    expect(c({ dataCompromised: 'yes', dnsIncorrectDomainNames: 1000 })).toBe('met'); // cannot be within the exception
  });
});

describe('IR Article 6 — TLD name registries', () => {
  it('(a) any complete unavailability of the authoritative service', () => {
    expect(status('tld-registry', { completeUnavailabilitySeconds: 0 }, 'IR-6-a')).toBe('not-met');
    expect(status('tld-registry', { completeUnavailabilitySeconds: 1 }, 'IR-6-a')).toBe('met');
  });
  it('(b) slow responses and (c) data compromise', () => {
    expect(status('tld-registry', { slowResponsePeriodSeconds: 3601, slowResponseAverageMs: 10_001 }, 'IR-6-b')).toBe('met');
    expect(status('tld-registry', { slowResponsePeriodSeconds: 3600, slowResponseAverageMs: 10_001 }, 'IR-6-b')).toBe('not-met');
    expect(status('tld-registry', { dataCompromised: 'yes' }, 'IR-6-c')).toBe('met');
    expect(status('tld-registry', { dataCompromised: 'no' }, 'IR-6-c')).toBe('not-met');
  });
});

describe('data-compromise questions use the scope each article names', () => {
  const text = (type: ServiceType): string => questionsFor([type]).find((q) => q.id === `services.${type}.dataCompromised`)?.text ?? '';
  it('DNS: authoritative service only (Art 5(c)); TLD: technical operation (Art 6(c)); others: the service', () => {
    expect(text('dns')).toContain('authoritative domain name resolution service');
    expect(text('tld-registry')).toContain('technical operation of the TLD');
    expect(text('cloud')).toContain('related to the provision of the service');
  });
});

describe.each([
  ['cloud', '7'],
  ['cdn', '9'],
  ['managed-service', '10'],
  ['managed-security-service', '10'],
] as const)('IR Article %s-type criteria (%s: Article %s)', (type, art) => {
  it(`(a) completely unavailable for more than 30 minutes — Art ${art}(a)`, () => {
    expect(status(type, { completeUnavailabilitySeconds: 1800 }, `IR-${art}-a`)).toBe('not-met');
    expect(status(type, { completeUnavailabilitySeconds: 1801 }, `IR-${art}-a`)).toBe('met');
  });

  it(`(b) limited for > 5 % / > 1 M users for more than one hour — Art ${art}(b)`, () => {
    const b = (m: ServiceMetrics): string => status(type, m, `IR-${art}-b`);
    expect(b({ usersLimitedAvailability: 51, totalUsersInUnion: 1000, limitedAvailabilitySeconds: 3601 })).toBe('met');
    expect(b({ usersLimitedAvailability: 50, totalUsersInUnion: 1000, limitedAvailabilitySeconds: 3601 })).toBe('not-met');
    expect(b({ usersLimitedAvailability: 51, totalUsersInUnion: 1000, limitedAvailabilitySeconds: 3600 })).toBe('not-met');
    expect(b({ usersLimitedAvailability: 1_000_001, limitedAvailabilitySeconds: 3601 })).toBe('met');
    expect(b({ usersLimitedAvailability: 1_000_000, totalUsersInUnion: 50_000_000, limitedAvailabilitySeconds: 7200 })).toBe('not-met');
    expect(b({ usersLimitedAvailability: 51, totalUsersInUnion: 1000 })).toBe('unknown');
  });

  it(`(c) data compromised as a result of a suspectedly malicious action — Art ${art}(c)`, () => {
    expect(status(type, { dataCompromised: 'yes', dataCompromisedMalicious: 'yes' }, `IR-${art}-c`)).toBe('met');
    expect(status(type, { dataCompromised: 'yes', dataCompromisedMalicious: 'no' }, `IR-${art}-c`)).toBe('not-met');
    expect(status(type, { dataCompromised: 'yes' }, `IR-${art}-c`)).toBe('unknown');
  });

  it(`(d) data compromised with impact on > 5 % / > 1 M users — Art ${art}(d)`, () => {
    expect(status(type, { dataCompromised: 'yes', usersDataCompromise: 51, totalUsersInUnion: 1000 }, `IR-${art}-d`)).toBe('met');
    expect(status(type, { dataCompromised: 'yes', usersDataCompromise: 50, totalUsersInUnion: 1000 }, `IR-${art}-d`)).toBe('not-met');
    expect(status(type, { dataCompromised: 'no', usersDataCompromise: 5_000_000 }, `IR-${art}-d`)).toBe('not-met');
  });
});

describe('IR Article 8 — data centre service providers', () => {
  it('(a) any complete unavailability; (b) limited availability more than one hour', () => {
    expect(status('data-centre', { completeUnavailabilitySeconds: 1 }, 'IR-8-a')).toBe('met');
    expect(status('data-centre', { completeUnavailabilitySeconds: 0 }, 'IR-8-a')).toBe('not-met');
    expect(status('data-centre', { limitedAvailabilitySeconds: 3600 }, 'IR-8-b')).toBe('not-met');
    expect(status('data-centre', { limitedAvailabilitySeconds: 3601 }, 'IR-8-b')).toBe('met');
  });
  it('(c) malicious data compromise; (d) physical access compromised', () => {
    expect(status('data-centre', { dataCompromised: 'yes', dataCompromisedMalicious: 'yes' }, 'IR-8-c')).toBe('met');
    expect(status('data-centre', { physicalAccessCompromised: 'yes' }, 'IR-8-d')).toBe('met');
    expect(status('data-centre', { physicalAccessCompromised: 'no' }, 'IR-8-d')).toBe('not-met');
  });
});

describe.each([
  ['online-marketplace', '11'],
  ['online-search-engine', '12'],
  ['social-network', '13'],
] as const)('IR Article %s-type criteria (%s: Article %s)', (type, art) => {
  it(`(a) completely unavailable for > 5 % / > 1 M users (no duration) — Art ${art}(a)`, () => {
    expect(status(type, { usersCompletelyUnavailable: 51, totalUsersInUnion: 1000 }, `IR-${art}-a`)).toBe('met');
    expect(status(type, { usersCompletelyUnavailable: 50, totalUsersInUnion: 1000 }, `IR-${art}-a`)).toBe('not-met');
    expect(status(type, { usersCompletelyUnavailable: 1_000_001 }, `IR-${art}-a`)).toBe('met');
  });
  it(`(b) > 5 % / > 1 M users impacted by limited availability — Art ${art}(b)`, () => {
    expect(status(type, { usersLimitedAvailability: 1_000_000, totalUsersInUnion: 30_000_000 }, `IR-${art}-b`)).toBe('not-met');
    expect(status(type, { usersLimitedAvailability: 1_000_001, totalUsersInUnion: 30_000_000 }, `IR-${art}-b`)).toBe('met');
  });
  it(`(c) malicious compromise and (d) compromise affecting > 5 % / > 1 M users — Art ${art}(c),(d)`, () => {
    expect(status(type, { dataCompromised: 'yes', dataCompromisedMalicious: 'yes' }, `IR-${art}-c`)).toBe('met');
    expect(status(type, { dataCompromised: 'yes', usersDataCompromise: 1_000_001 }, `IR-${art}-d`)).toBe('met');
    expect(status(type, { dataCompromised: 'yes', usersDataCompromise: 5, totalUsersInUnion: 100 }, `IR-${art}-d`)).toBe('not-met');
  });
});

describe('IR Article 14 — trust service providers', () => {
  it('(a) completely unavailable for more than 20 minutes', () => {
    expect(status('trust-service', { completeUnavailabilitySeconds: 1200 }, 'IR-14-a')).toBe('not-met');
    expect(status('trust-service', { completeUnavailabilitySeconds: 1201 }, 'IR-14-a')).toBe('met');
  });
  it('(b) unavailable more than one hour on a calendar-week basis', () => {
    expect(status('trust-service', { weeklyUnavailabilitySeconds: 3600 }, 'IR-14-b')).toBe('not-met');
    expect(status('trust-service', { weeklyUnavailabilitySeconds: 3601 }, 'IR-14-b')).toBe('met');
  });
  it('(c) > 1 % or > 200 000 users or relying parties impacted by limited availability', () => {
    expect(status('trust-service', { usersLimitedAvailability: 100, totalUsersInUnion: 10_000 }, 'IR-14-c')).toBe('not-met');
    expect(status('trust-service', { usersLimitedAvailability: 101, totalUsersInUnion: 10_000 }, 'IR-14-c')).toBe('met');
    expect(status('trust-service', { usersLimitedAvailability: 200_001 }, 'IR-14-c')).toBe('met');
    expect(crit('trust-service', { usersLimitedAvailability: 1 }, 'IR-14-c').reason).toMatch(/relying parties/u);
  });
  it('(d) physical access to restricted areas or its protection compromised', () => {
    expect(status('trust-service', { physicalAccessCompromised: 'yes' }, 'IR-14-d')).toBe('met');
  });
  it('(e) data compromised with impact on > 0,1 % or > 100 users or relying parties', () => {
    expect(status('trust-service', { dataCompromised: 'yes', usersDataCompromise: 100, totalUsersInUnion: 1_000_000 }, 'IR-14-e')).toBe('not-met');
    expect(status('trust-service', { dataCompromised: 'yes', usersDataCompromise: 101, totalUsersInUnion: 1_000_000 }, 'IR-14-e')).toBe('met');
    expect(status('trust-service', { dataCompromised: 'yes', usersDataCompromise: 51, totalUsersInUnion: 50_000 }, 'IR-14-e')).toBe('met');
    expect(status('trust-service', { dataCompromised: 'yes', usersDataCompromise: 50, totalUsersInUnion: 50_000 }, 'IR-14-e')).toBe('not-met');
  });
});

describe('outcome', () => {
  it('other entities: Article 23(3) NIS2 as two questions, no IR thresholds', () => {
    const open = assessSignificance({ serviceTypes: ['other'], answers: {} });
    expect(open.outcome).toBe('undetermined');
    expect(open.criteria.map((c) => c.id)).toEqual(['NIS2-23-3-a', 'NIS2-23-3-b']);
    expect(open.openQuestions.map((q) => q.id)).toEqual(['severeDisruptionOrFinancialLoss', 'considerableDamageToOthers']);
    expect(assessSignificance({ serviceTypes: ['other'], answers: { considerableDamageToOthers: 'yes' } }).outcome).toBe('significant');
    expect(assessSignificance({ serviceTypes: ['other'], answers: { severeDisruptionOrFinancialLoss: 'no', considerableDamageToOthers: 'no' } }).outcome).toBe('not-significant');
  });

  it('not significant only when every criterion is answered and none is met', () => {
    const answers: AssessmentAnswers = {
      scheduledMaintenanceOnly: 'no',
      directFinancialLossCents: 0,
      tradeSecretExfiltration: 'no',
      deathOfNaturalPerson: 'no',
      considerableHealthDamage: 'no',
      maliciousUnauthorisedAccess: 'no',
      services: { 'data-centre': { completeUnavailabilitySeconds: 0, limitedAvailabilitySeconds: 0, dataCompromised: 'no', physicalAccessCompromised: 'no' } },
    };
    const r = assessSignificance({ serviceTypes: ['data-centre'], answers });
    expect(r.outcome).toBe('not-significant');
    expect(r.openQuestions).toEqual([]);
  });

  it('reasons carry article references and open questions are de-duplicated', () => {
    const r = assessSignificance({ serviceTypes: ['cloud', 'cdn'], answers: { services: { cloud: { completeUnavailabilitySeconds: 4000 } } } });
    expect(r.reasons.map((x) => [x.id, x.ref.provision])).toEqual([['IR-7-a', 'Article 7, point (a)']]);
    const ids = r.openQuestions.map((q) => q.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids).toContain('services.cdn.completeUnavailabilitySeconds');
  });
});

describe('text answers', () => {
  it('parses each kind and clears with an empty value', () => {
    const a = applyAnswerText({}, [
      ['directFinancialLossCents', '500000.01'],
      ['deathOfNaturalPerson', 'no'],
      ['services.cloud.completeUnavailabilitySeconds', '1h1s'],
      ['services.cloud.totalUsersInUnion', '1000'],
      ['services.dns.slowResponseAverageMs', '10001'],
    ]);
    expect(a).toEqual({ directFinancialLossCents: 50_000_001, deathOfNaturalPerson: 'no', services: { cloud: { completeUnavailabilitySeconds: 3601, totalUsersInUnion: 1000 }, dns: { slowResponseAverageMs: 10_001 } } });
    expect(answerText(a, 'directFinancialLossCents')).toBe('500000.01');
    expect(answerText(a, 'services.cloud.completeUnavailabilitySeconds')).toBe('1h1s');
    const cleared = applyAnswerText(a, [['services.dns.slowResponseAverageMs', ''], ['deathOfNaturalPerson', '']]);
    expect(cleared.services?.dns).toBeUndefined();
    expect(cleared.deathOfNaturalPerson).toBeUndefined();
  });

  it('rejects unknown ids, bad values and inconsistent counts', () => {
    expect(() => applyAnswerText({}, [['__proto__', 'yes']])).toThrow(/Unknown question/u);
    expect(() => applyAnswerText({}, [['services.toString.x', '1']])).toThrow(/Unknown question/u);
    expect(() => applyAnswerText({}, [['deathOfNaturalPerson', 'maybe']])).toThrow();
    expect(() => applyAnswerText({}, [['directFinancialLossCents', '1,5']])).toThrow();
    expect(() => applyAnswerText({}, [['services.cloud.totalUsersInUnion', '-1']])).toThrow();
    expect(() => applyAnswerText({}, [['services.cloud.totalUsersInUnion', '10'], ['services.cloud.usersLimitedAvailability', '11']])).toThrow(/cannot exceed/u);
  });
});

describe('IR Article 4 — recurring incidents', () => {
  const Z = 'Europe/Vilnius';
  const ns = (id: string, occurredAt: string, loss: number | undefined, key = 'phishing-mfa') =>
    incident({
      id,
      occurredAt,
      details: { rootCauseKey: key },
      assessment: { assessedAt: occurredAt, answers: loss === undefined ? {} : { directFinancialLossCents: loss }, outcome: 'not-significant', metCriteria: [] },
    });

  it('two non-significant incidents within 6 months with the same root cause that together exceed the loss threshold', () => {
    const f = findRecurringIncidents([ns('INC-2026-0001', '2026-01-10T10:00:00.000Z', 30_000_000), ns('INC-2026-0002', '2026-05-10T10:00:00.000Z', 20_000_001)], undefined, Z);
    expect(f).toHaveLength(1);
    expect(f[0]?.status).toBe('met');
    expect(f[0]?.incidentIds).toEqual(['INC-2026-0001', 'INC-2026-0002']);
  });

  it('combined loss exactly at the threshold is not enough', () => {
    const f = findRecurringIncidents([ns('INC-2026-0001', '2026-01-10T10:00:00.000Z', 30_000_000), ns('INC-2026-0002', '2026-02-10T10:00:00.000Z', 20_000_000)], undefined, Z);
    expect(f[0]?.status).toBe('unknown'); // EUR 500 000 exactly, turnover unknown -> cannot rule out the 5 % limit
    const g = findRecurringIncidents([ns('INC-2026-0001', '2026-01-10T10:00:00.000Z', 30_000_000), ns('INC-2026-0002', '2026-02-10T10:00:00.000Z', 20_000_000)], 100_000_000_000, Z);
    expect(g[0]?.status).toBe('not-met');
  });

  it('six calendar months is inclusive; one millisecond later is outside', () => {
    const inside = findRecurringIncidents([ns('INC-2026-0001', '2026-01-31T10:00:00.000Z', 30_000_000), ns('INC-2026-0002', '2026-07-31T09:00:00.000Z', 30_000_000)], undefined, Z);
    expect(inside[0]?.status).toBe('met'); // 31 Jan 12:00 EET -> 31 Jul 12:00 EEST = 09:00Z
    const outside = findRecurringIncidents([ns('INC-2026-0001', '2026-01-31T10:00:00.000Z', 30_000_000), ns('INC-2026-0002', '2026-07-31T09:00:00.001Z', 30_000_000)], undefined, Z);
    expect(outside).toEqual([]);
  });

  it('ignores different root causes, significant incidents and collective incidents', () => {
    const significant = incident({ id: 'INC-2026-0003', occurredAt: '2026-01-11T10:00:00.000Z', details: { rootCauseKey: 'phishing-mfa' }, assessment: { assessedAt: '2026-01-11T10:00:00.000Z', answers: { directFinancialLossCents: 90_000_000 }, outcome: 'significant', metCriteria: ['IR-3-1-a'] } });
    const f = findRecurringIncidents([ns('INC-2026-0001', '2026-01-10T10:00:00.000Z', 30_000_000), ns('INC-2026-0002', '2026-01-12T10:00:00.000Z', 30_000_000, 'other-cause'), significant], undefined, Z);
    expect(f).toEqual([]);
  });

  it('only counts incidents of IR 2024/2690 relevant entities', () => {
    const other = (id: string, when: string) => ({ ...ns(id, when, 40_000_000), serviceTypes: ['other' as const] });
    expect(findRecurringIncidents([other('INC-2026-0001', '2026-01-10T10:00:00.000Z'), other('INC-2026-0002', '2026-01-12T10:00:00.000Z')], undefined, Z)).toEqual([]);
  });

  it('lists every question for the chosen service types', () => {
    const ids = questionsFor(['dns', 'other']).map((q) => q.id);
    expect(ids).toContain('scheduledMaintenanceOnly');
    expect(ids).toContain('services.dns.dnsDomainNamesManaged');
    expect(ids).toContain('considerableDamageToOthers');
    expect(questionsFor(['other']).map((q) => q.id)).toEqual(['severeDisruptionOrFinancialLoss', 'considerableDamageToOthers']);
    expect(questionsFor(['trust-service']).find((q) => q.id === 'services.trust-service.usersLimitedAvailability')?.text).toMatch(/relying parties/u);
  });

  it('missing losses make the result undetermined rather than "not met"', () => {
    const f = findRecurringIncidents([ns('INC-2026-0001', '2026-01-10T10:00:00.000Z', 1000), ns('INC-2026-0002', '2026-01-12T10:00:00.000Z', undefined)], undefined, Z);
    expect(f[0]?.status).toBe('unknown');
    expect(f[0]?.missingLossIds).toEqual(['INC-2026-0002']);
  });
});
