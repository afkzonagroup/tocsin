// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { SERVICE_TYPES, type AssessmentAnswers, type ServiceType } from '../model/types.js';
import { validateAnswers } from '../model/validate.js';
import { parseDurationSeconds } from '../time/periods.js';
import { invalid } from '../util/errors.js';
import { MAX_COUNT, parseEuroToCents, parseIntText, TRI_VALUES, type Tri } from '../util/validate.js';
import { GENERAL_QUESTIONS, METRIC_QUESTIONS, type GeneralKey, type MetricKey, type QuestionKind } from './questions.js';

/**
 * Text answers (CLI `--answer id=value`, web form fields) → typed assessment answers.
 * Question ids: a general key ("deathOfNaturalPerson") or "services.<type>.<metric>".
 */

export interface AnswerTarget {
  readonly kind: QuestionKind;
  readonly general?: GeneralKey;
  readonly service?: ServiceType;
  readonly metric?: MetricKey;
}

export function answerTarget(id: string): AnswerTarget {
  if (Object.hasOwn(GENERAL_QUESTIONS, id)) {
    const key = id as GeneralKey;
    return { kind: GENERAL_QUESTIONS[key].kind, general: key };
  }
  const m = /^services\.([a-z-]{1,40})\.([A-Za-z]{1,40})$/u.exec(id);
  if (m !== null && (SERVICE_TYPES as readonly string[]).includes(m[1] ?? '') && Object.hasOwn(METRIC_QUESTIONS, m[2] ?? '')) {
    const metric = m[2] as MetricKey;
    return { kind: METRIC_QUESTIONS[metric].kind, service: m[1] as ServiceType, metric };
  }
  invalid(`Unknown question id "${id.slice(0, 60)}".`);
}

/** Parses a text value for a question kind. Empty string means "clear". */
export function parseAnswerValue(kind: QuestionKind, value: string, what: string): Tri | number | undefined {
  const v = value.trim();
  if (v === '') return undefined;
  switch (kind) {
    case 'tri':
      if (!(TRI_VALUES as readonly string[]).includes(v)) invalid(`${what} must be yes, no or unknown.`);
      return v as Tri;
    case 'count':
      return parseIntText(v, what, MAX_COUNT);
    case 'milliseconds':
      return parseIntText(v, what, 86_400_000);
    case 'duration':
      return parseDurationSeconds(v, what);
    case 'cents':
      return parseEuroToCents(v, what);
  }
}

/** Applies text assignments to existing answers and validates the result. */
export function applyAnswerText(base: AssessmentAnswers, assignments: readonly (readonly [string, string])[]): AssessmentAnswers {
  const general = new Map<string, unknown>(Object.entries(base).filter(([k]) => k !== 'services'));
  const services = new Map<string, Map<string, unknown>>(Object.entries(base.services ?? {}).map(([k, v]) => [k, new Map<string, unknown>(Object.entries(v))]));
  for (const [id, raw] of assignments) {
    const t = answerTarget(id);
    const value = parseAnswerValue(t.kind, raw, id);
    if (t.general !== undefined) {
      if (value === undefined) general.delete(t.general);
      else general.set(t.general, value);
    } else if (t.service !== undefined && t.metric !== undefined) {
      const m = services.get(t.service) ?? new Map<string, unknown>();
      if (value === undefined) m.delete(t.metric);
      else m.set(t.metric, value);
      services.set(t.service, m);
    }
  }
  const svc = Object.fromEntries([...services].filter(([, m]) => m.size > 0).map(([k, m]) => [k, Object.fromEntries(m)]));
  return validateAnswers({ ...Object.fromEntries(general), ...(Object.keys(svc).length > 0 ? { services: svc } : {}) });
}

/** Current text value of a question (for pre-filling forms). */
export function answerText(a: AssessmentAnswers, id: string): string {
  const t = answerTarget(id);
  let v: unknown;
  if (t.general !== undefined) v = a[t.general];
  else if (t.service !== undefined && t.metric !== undefined) v = (a.services?.[t.service])?.[t.metric];
  if (v === undefined) return '';
  if (t.kind === 'cents' && typeof v === 'number') return `${Math.floor(v / 100)}.${String(v % 100).padStart(2, '0')}`;
  if (t.kind === 'duration' && typeof v === 'number') {
    const h = Math.floor(v / 3600);
    const m = Math.floor((v % 3600) / 60);
    const s = v % 60;
    return `${h > 0 ? `${h}h` : ''}${m > 0 ? `${m}m` : ''}${s > 0 || v === 0 ? `${s}s` : ''}`;
  }
  return typeof v === 'string' || typeof v === 'number' ? String(v) : '';
}
