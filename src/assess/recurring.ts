// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { ref, type LegalRef } from '../legal/refs.js';
import type { Incident } from '../model/types.js';
import { addCalendarMonths } from '../time/periods.js';
import { toMs } from '../time/zone.js';
import { financialLossStatus, formatEuro, type Status } from './thresholds.js';

/**
 * IR 2024/2690 Article 4 (recurring incidents). Incidents that individually are not significant are
 * collectively one significant incident when (a) they occurred at least twice within 6 months,
 * (b) they have the same apparent root cause and (c) together they meet Article 3(1)(a).
 *
 * "Same apparent root cause" is human judgement: the tool groups incidents by the `rootCauseKey`
 * label the user assigns. "Within 6 months" is read as: the later incident occurred no later than
 * six calendar months after the earlier one (boundary inclusive, so the check errs towards reporting).
 */

export interface RecurringFinding {
  readonly rootCauseKey: string;
  readonly status: Status;
  readonly incidentIds: readonly string[];
  readonly windowStart: string;
  readonly windowEnd: string;
  readonly totalLossCents: number;
  readonly missingLossIds: readonly string[];
  readonly reason: string;
  readonly ref: LegalRef;
}

/** The time an incident occurred: occurrence, else detection, else record creation. */
export function occurrenceTime(i: Incident): string {
  return i.occurredAt ?? i.detectedAt ?? i.createdAt;
}

/** Article 4 is part of IR 2024/2690, so only incidents of its relevant entities count. */
function candidate(i: Incident): boolean {
  return i.linkedIncidentIds.length === 0 && i.assessment?.outcome === 'not-significant' && i.serviceTypes.some((t) => t !== 'other');
}

const RANK: Readonly<Record<Status, number>> = { met: 2, unknown: 1, 'not-met': 0 };

/**
 * Checks the register for recurring incidents. Only incidents of relevant entities (IR 2024/2690 Art 1)
 * that were assessed as not significant and carry a root-cause label are considered. Returns one finding per root-cause label that has at least two such
 * incidents within six months, best window first (met, then unknown).
 */
export function findRecurringIncidents(incidents: readonly Incident[], turnoverCents: number | undefined, zone: string): RecurringFinding[] {
  const groups = new Map<string, Incident[]>();
  for (const i of incidents) {
    const key = i.details.rootCauseKey;
    if (key === undefined || !candidate(i)) continue;
    const list = groups.get(key) ?? [];
    list.push(i);
    groups.set(key, list);
  }
  const findings: RecurringFinding[] = [];
  for (const [key, list] of [...groups.entries()].sort(([a], [b]) => a.localeCompare(b))) {
    const sorted = [...list].sort((a, b) => toMs(occurrenceTime(a)) - toMs(occurrenceTime(b)) || a.id.localeCompare(b.id));
    let best: RecurringFinding | undefined;
    for (let s = 0; s < sorted.length; s++) {
      const first = sorted[s] as Incident;
      const start = occurrenceTime(first);
      const end = addCalendarMonths(start, 6, zone);
      const members = sorted.slice(s).filter((x) => toMs(occurrenceTime(x)) <= toMs(end));
      if (members.length < 2) continue;
      let total = 0;
      const missing: string[] = [];
      for (const m of members) {
        const loss = m.assessment?.answers.directFinancialLossCents;
        if (loss === undefined) missing.push(m.id);
        else total += loss;
      }
      let status = financialLossStatus(total, turnoverCents);
      if (status === 'not-met' && missing.length > 0) status = 'unknown';
      const reason =
        `${members.length} incidents with root cause "${key}" between ${start} and ${end}; combined direct financial loss ${formatEuro(total)}` +
        (missing.length > 0 ? ` (loss not given for ${missing.join(', ')})` : '') +
        `; threshold: more than EUR 500 000 or 5 % of turnover, whichever is lower${turnoverCents === undefined ? ' (turnover not configured)' : ''}.`;
      const finding: RecurringFinding = {
        rootCauseKey: key,
        status,
        incidentIds: members.map((m) => m.id),
        windowStart: start,
        windowEnd: end,
        totalLossCents: total,
        missingLossIds: missing,
        reason,
        ref: ref('IR2024_2690', 'Article 4 and Article 3(1), point (f)'),
      };
      if (best === undefined || RANK[finding.status] > RANK[best.status]) best = finding;
    }
    if (best !== undefined) findings.push(best);
  }
  return findings.sort((a, b) => RANK[b.status] - RANK[a.status]);
}

/**
 * Recurring-incident status for a collective incident that links individually non-significant incidents
 * (IR Art 3(1)(f)). Undefined when the incident links nothing.
 */
export function recurringForCollective(
  all: readonly Incident[],
  collective: Incident,
  turnoverCents: number | undefined,
  zone: string,
): { status: Status; reason: string } | undefined {
  if (collective.linkedIncidentIds.length === 0) return undefined;
  const linked = all.filter((i) => collective.linkedIncidentIds.includes(i.id));
  const findings = findRecurringIncidents(linked, turnoverCents, zone);
  const best = findings[0];
  if (best === undefined) {
    return { status: 'not-met', reason: 'The linked incidents do not form a recurring group (at least two incidents assessed as not significant, same root-cause label, within 6 months).' };
  }
  return { status: best.status, reason: best.reason };
}
