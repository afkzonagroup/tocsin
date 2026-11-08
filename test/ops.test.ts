// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { describe, expect, it } from 'vitest';
import { verifyAudit } from '../src/audit/chain.js';
import {
  addIntermediateRequest,
  addRecipientCommunication,
  createIncident,
  initStore,
  logEvent,
  markNotified,
  recordAwareness,
  recordHandlingConcluded,
  recordSubmission,
  saveAssessment,
  setStatusUpdate,
  updateCore,
  updateDetails,
} from '../src/registry/ops.js';
import { validateIncident } from '../src/model/validate.js';
import { validateReportContent } from '../src/reports/render.js';
import { emptyData, type StoreData } from '../src/store/store.js';
import { sha256Canonical } from '../src/util/canonical-json.js';
import { CFG } from './helpers.js';

const T0 = Date.UTC(2026, 0, 10, 8);
const at = (h: number): string => new Date(T0 + h * 3_600_000).toISOString();
const ctx = (h = 0) => ({ now: T0 + h * 3_600_000, actor: 'alice' });

function fresh(): StoreData {
  return createIncident(initStore(emptyData(at(0)), ctx()), { title: 'Outage', serviceTypes: ['cloud'], detectedAt: at(0) }, ctx()).data;
}

const ID = 'INC-2026-0001';

describe('register operations', () => {
  it('numbers incidents per year and audits every change with a state hash', () => {
    let d = fresh();
    d = createIncident(d, { title: 'Second', serviceTypes: ['dns'] }, ctx()).data;
    expect(d.incidents.map((i) => i.id)).toEqual(['INC-2026-0001', 'INC-2026-0002']);
    const next = createIncident(d, { title: 'Next year', serviceTypes: ['dns'] }, { now: Date.UTC(2027, 0, 1), actor: 'a' });
    expect(next.result.id).toBe('INC-2027-0001');
    const last = d.audit.at(-1);
    expect(last).toMatchObject({ action: 'incident.created', target: 'INC-2026-0002', actor: 'alice' });
    expect(last?.stateSha256).toBe(sha256Canonical(d.incidents[1]));
    expect(verifyAudit(d.audit).ok).toBe(true);
  });

  it('updates details and core fields, null clears, nothing-to-change is refused', () => {
    let d = updateDetails(fresh(), ID, { severity: 'High', impact: 'All users' }, ctx()).data;
    d = updateDetails(d, ID, { severity: null }, ctx()).data;
    expect(d.incidents[0]?.details).toEqual({ impact: 'All users' });
    expect(d.audit.at(-1)?.fields).toEqual(['details.severity']);
    expect(() => updateDetails(d, ID, {}, ctx())).toThrow(/Nothing/u);
    d = updateCore(d, ID, { title: 'Renamed', serviceTypes: ['cdn', 'cdn'], occurredAt: at(-1) }, ctx()).data;
    expect(d.incidents[0]).toMatchObject({ title: 'Renamed', serviceTypes: ['cdn'], occurredAt: at(-1) });
    d = updateCore(d, ID, { occurredAt: null }, ctx()).data;
    expect(d.incidents[0]?.occurredAt).toBeUndefined();
    expect(() => updateCore(d, ID, { occurredAt: at(1) }, ctx(2))).toThrow(/Detection cannot precede/u);
    expect(() => updateCore(d, ID, { occurredAt: at(1) }, ctx())).toThrow(/future/u);
    expect(() => updateCore(d, ID, {}, ctx())).toThrow(/Nothing/u);
    expect(() => updateDetails(d, 'INC-2026-0099', { severity: 'x' }, ctx())).toThrow(/No incident/u);
  });

  it('stores the assessment outcome and met criteria', () => {
    const r = saveAssessment(fresh(), ID, { services: { cloud: { completeUnavailabilitySeconds: 3600 } } }, { turnover: { financialYear: '2025', amountCents: 1 }, timeZone: 'UTC' }, ctx());
    expect(r.result.incident.assessment).toMatchObject({ outcome: 'significant', metCriteria: ['IR-7-a (cloud)'] });
    expect(r.data.audit.at(-1)?.note).toBe('outcome: significant');
  });

  it('runs the reporting lifecycle and snapshots each submission', () => {
    let d = recordAwareness(fresh(), ID, at(1), ctx(1)).data;
    d = updateDetails(d, ID, { suspectedUnlawfulOrMalicious: 'yes', crossBorderImpact: 'no', severity: 'High', impact: 'EU-wide' }, ctx(2)).data;
    d = recordSubmission(d, ID, { stage: 'early-warning', submittedAt: at(3), authorityReference: 'EW-9' }, CFG, ctx(3)).data;
    d = recordSubmission(d, ID, { stage: 'incident-notification', submittedAt: at(20) }, CFG, ctx(20)).data;
    const req = addIntermediateRequest(d, ID, { requestedAt: at(30), requestedBy: 'CSIRT duty officer', dueAt: at(40) }, ctx(30));
    d = req.data;
    expect(req.result.id).toBe('R-1');
    expect(() => recordSubmission(d, ID, { stage: 'intermediate-report', submittedAt: at(31), requestId: 'R-1' }, CFG, ctx(31))).toThrow(/statusUpdate/u);
    d = setStatusUpdate(d, ID, 'R-1', 'Containment complete', ctx(31)).data;
    d = recordSubmission(d, ID, { stage: 'intermediate-report', submittedAt: at(32), requestId: 'R-1' }, CFG, ctx(32)).data;
    expect(() => setStatusUpdate(d, ID, 'R-1', 'again', ctx(33))).toThrow(/already submitted/u);
    const com = addRecipientCommunication(d, ID, { kind: 'incident-23-1', communicatedAt: at(5), audience: 'All customers', summary: 'Outage notice', measuresOrRemedies: 'Rotate API keys' }, ctx(33));
    d = com.data;
    expect(com.result.id).toBe('C-1');
    d = updateDetails(d, ID, { description: 'D', threatTypeOrRootCause: 'R', mitigationApplied: 'M', mitigationOngoing: 'None' }, ctx(40)).data;
    d = recordHandlingConcluded(d, ID, at(50), ctx(50)).data;
    d = recordSubmission(d, ID, { stage: 'final-report', submittedAt: at(60) }, CFG, ctx(60)).data;

    const inc = d.incidents[0];
    if (inc === undefined) throw new Error('missing');
    expect(inc.submissions.map((s) => s.stage)).toEqual(['early-warning', 'incident-notification', 'final-report']);
    for (const s of inc.submissions) {
      expect(s.contentSha256).toBe(sha256Canonical(s.snapshot));
      expect(validateReportContent(s.snapshot).stage).toBe(s.stage);
    }
    expect(inc.intermediateRequests[0]?.submission?.contentSha256).toBe(sha256Canonical(inc.intermediateRequests[0]?.submission?.snapshot));
    expect(validateIncident(JSON.parse(JSON.stringify(inc)))).toEqual(inc);
    expect(verifyAudit(d.audit).ok).toBe(true);

    // Closed: no further changes.
    expect(() => updateDetails(d, ID, { severity: 'Low' }, ctx(61))).toThrow(/closed/u);
    expect(() => recordAwareness(d, ID, at(0), ctx(61), 'x')).toThrow(/closed/u);
    expect(() => addIntermediateRequest(d, ID, { requestedAt: at(61) }, ctx(61))).toThrow(/closed/u);
    expect(() => recordHandlingConcluded(d, ID, null, ctx(61))).toThrow(/closed/u);
  });

  it('records incomplete submissions only on request, and notes the gaps', () => {
    const d = recordAwareness(fresh(), ID, at(1), ctx(1)).data;
    expect(() => recordSubmission(d, ID, { stage: 'early-warning', submittedAt: at(2) }, CFG, ctx(2))).toThrow(/Prescribed elements are empty/u);
    const r = recordSubmission(d, ID, { stage: 'early-warning', submittedAt: at(2), allowIncomplete: true }, CFG, ctx(2));
    expect(r.data.audit.at(-1)?.note).toBe('incomplete: suspectedUnlawfulOrMalicious, crossBorderImpact');
  });

  it('validates request and communication input', () => {
    const d = recordAwareness(fresh(), ID, at(1), ctx(1)).data;
    expect(() => addIntermediateRequest(fresh(), ID, { requestedAt: at(1) }, ctx(1))).toThrow(/awareness/u);
    expect(() => addIntermediateRequest(d, ID, { requestedAt: at(5) }, ctx(1))).toThrow(/future/u);
    expect(() => addIntermediateRequest(d, ID, { requestedAt: at(1), dueAt: at(0) }, ctx(1))).toThrow(/precede/u);
    expect(() => addRecipientCommunication(d, ID, { kind: 'incident-23-1', communicatedAt: at(1), audience: '', summary: 's' }, ctx(1))).toThrow(/too short/u);
    expect(() => addRecipientCommunication(d, ID, { kind: 'incident-23-1', communicatedAt: at(9), audience: 'a', summary: 's' }, ctx(1))).toThrow(/future/u);
  });

  it('logs events and webhook deliveries in the audit chain', () => {
    let d = logEvent(fresh(), 'report.exported', ctx(), ID, 'early-warning as md');
    expect(() => logEvent(d, 'Bad Action', ctx())).toThrow();
    d = markNotified(d, ['k1', 'k2'], ctx());
    expect(d.meta.notified).toEqual(['k1', 'k2']);
    expect(markNotified(d, [], ctx())).toBe(d);
    expect(verifyAudit(d.audit).ok).toBe(true);
    expect(() => createIncident(d, { title: 'x', serviceTypes: ['cloud'] }, { now: T0, actor: '' })).toThrow(/actor/u);
  });
});

describe('record validation', () => {
  it('rejects unknown fields, bad ids and bad timestamps', () => {
    const inc = fresh().incidents[0];
    expect(() => validateIncident({ ...inc, extra: 1 })).toThrow(/unknown field/u);
    expect(() => validateIncident({ ...inc, id: '../../etc' })).toThrow();
    expect(() => validateIncident({ ...inc, awareAt: '2026-01-01' })).toThrow();
    expect(() => validateIncident({ ...inc, serviceTypes: [] })).toThrow(/At least one/u);
    expect(() => validateIncident({ ...inc, details: { affectedMemberStates: ['lt'] } })).toThrow();
    expect(() => validateIncident({ ...inc, details: { indicatorsOfCompromise: [''] } })).toThrow();
    expect(() => validateIncident({ ...inc, details: { rootCauseKey: 'Bad Key' } })).toThrow();
    expect(() => validateIncident({ ...inc, details: { description: 'x'.repeat(20_001) } })).toThrow(/too long/u);
    expect(() => validateIncident({ ...inc, submissions: [{ stage: 'intermediate-report', submittedAt: at(0), recordedAt: at(0), contentSha256: '0'.repeat(64), snapshot: {} }] })).toThrow();
    expect(validateIncident({ ...inc, details: { summary: 'line 1\nline 2\ttab' } }).details.summary).toBe('line 1\nline 2\ttab');
    expect(() => validateIncident({ ...inc, title: 'two\nlines' })).toThrow(/control/u);
  });
});

describe('collective incidents (IR Art 3(1)(f) and Art 4)', () => {
  const BIG = { timeZone: 'UTC', turnover: { financialYear: '2025', amountCents: 100_000_000_000 } };
  it('a collective incident linking a recurring group is significant through point (f)', async () => {
    const { assessIncident } = await import('../src/registry/ops.js');
    let d = initStore(emptyData(at(0)), ctx());
    for (const [i, loss] of [[0, 30_000_000], [1, 30_000_000]] as const) {
      d = createIncident(d, { title: `Phish ${i}`, serviceTypes: ['cloud'], details: { rootCauseKey: 'phishing' } }, ctx(i)).data;
      d = saveAssessment(d, `INC-2026-000${i + 1}`, { directFinancialLossCents: loss, scheduledMaintenanceOnly: 'no', tradeSecretExfiltration: 'no', deathOfNaturalPerson: 'no', considerableHealthDamage: 'no', maliciousUnauthorisedAccess: 'no', services: { cloud: { completeUnavailabilitySeconds: 0, limitedAvailabilitySeconds: 0, usersLimitedAvailability: 0, totalUsersInUnion: 100, dataCompromised: 'no', dataCompromisedMalicious: 'no', usersDataCompromise: 0 } } }, BIG, ctx(i)).data;
    }
    expect(d.incidents.map((i) => i.assessment?.outcome)).toEqual(['not-significant', 'not-significant']);
    d = createIncident(d, { title: 'Recurring phishing', serviceTypes: ['cloud'], linkedIncidentIds: ['INC-2026-0001', 'INC-2026-0002'] }, ctx(2)).data;
    const collective = d.incidents[2];
    if (collective === undefined) throw new Error('missing');
    const r = assessIncident(d.incidents, collective, BIG);
    expect(r.reasons.map((x) => x.id)).toEqual(['IR-3-1-f']);
    expect(() => createIncident(d, { title: 'x', serviceTypes: ['cloud'], linkedIncidentIds: ['INC-2026-0099'] }, ctx(3))).toThrow(/No incident/u);
    const lone = createIncident(d, { title: 'Bad group', serviceTypes: ['cloud'], linkedIncidentIds: ['INC-2026-0001'] }, ctx(3));
    const loneInc = lone.result;
    expect(assessIncident(lone.data.incidents, loneInc, BIG).criteria.find((c) => c.id === 'IR-3-1-f')?.status).toBe('not-met');
  });
});
