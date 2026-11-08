// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import type { IncidentDetails, ServiceType } from '../model/types.js';
import type { NewIncident } from '../registry/ops.js';
import { toIso } from '../time/zone.js';
import { TocsinError } from '../util/errors.js';
import { codePointSlice, isRecord } from '../util/validate.js';

/**
 * Importers for incident-tool exports whose JSON format is publicly documented. They create draft
 * incidents only: title, detection time, a summary line, an internal reference and (MISP) indicators
 * of compromise. They never set awareness, significance or any reporting stage — those are decisions.
 *
 * - PagerDuty REST API v2, "Get an incident" (`{ "incident": {…} }`) and "List incidents"
 *   (`{ "incidents": […] }`): https://docs.pagerduty.com/developer/api/reference/rest/incidents/get-incident
 * - incident.io API v2, "Show incident" (`{ "incident": {…} }`) and "List incidents"
 *   (`{ "incidents": […] }`), schema IncidentV2: https://docs.incident.io/api-reference (OpenAPI at
 *   https://api.incident.io/v1/openapiV3.json)
 * - MISP core format, Event (`{ "Event": {…} }`), Internet-Draft draft-dulaunoy-misp-core-format:
 *   https://github.com/MISP/misp-rfc
 */

export const IMPORT_FORMATS = ['pagerduty', 'incident-io', 'misp'] as const;
export type ImportFormat = (typeof IMPORT_FORMATS)[number];

export const MAX_IMPORT_BYTES = 10 * 1024 * 1024;
export const MAX_IMPORT_INCIDENTS = 1000;

function fail(msg: string): never {
  throw new TocsinError('IMPORT_FORMAT', msg);
}

function text(v: unknown, max: number): string | undefined {
  if (typeof v !== 'string') return undefined;
  // Strip control and bidi-override characters; collapse whitespace for single-line fields.
  // eslint-disable-next-line no-control-regex -- removing control characters from foreign input is the purpose
  const clean = v.replace(/[\u0000-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]/gu, ' ').replace(/\s+/gu, ' ').trim();
  if (clean === '') return undefined;
  return codePointSlice(clean, max);
}

/** ISO 8601 with offset → stored UTC ISO (fraction truncated to milliseconds). Undefined when absent or invalid. */
export function importTimestamp(v: unknown): string | undefined {
  if (typeof v !== 'string') return undefined;
  const m = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})$/u.exec(v.trim());
  if (m === null) return undefined;
  const t = Date.parse(`${m[1] ?? ''}.${(m[2] ?? '0').slice(0, 3).padEnd(3, '0')}${m[3] ?? ''}`);
  if (Number.isNaN(t)) return undefined;
  try {
    return toIso(t);
  } catch {
    return undefined;
  }
}

function list(v: unknown, singleKey: string, listKey: string): unknown[] {
  if (Array.isArray(v)) return v as unknown[];
  if (!isRecord(v)) fail('Expected a JSON object or array.');
  const single = v[singleKey];
  const many = v[listKey];
  if (single !== undefined) return [single];
  if (Array.isArray(many)) return many as unknown[];
  fail(`Expected "${singleKey}" or "${listKey}" at the top level.`);
}

function draft(title: string | undefined, fallback: string, serviceTypes: readonly ServiceType[], details: IncidentDetails, detectedAt: string | undefined): NewIncident {
  return {
    title: title ?? fallback,
    serviceTypes,
    details,
    ...(detectedAt === undefined ? {} : { detectedAt }),
  };
}

function pagerDuty(root: unknown, serviceTypes: readonly ServiceType[]): NewIncident[] {
  return list(root, 'incident', 'incidents').map((x, i) => {
    if (!isRecord(x)) fail(`incident ${i} is not an object.`);
    const num = typeof x['incident_number'] === 'number' && Number.isSafeInteger(x['incident_number']) ? x['incident_number'] : undefined;
    const ref = num !== undefined ? `PagerDuty #${num}` : text(x['id'], 40) === undefined ? undefined : `PagerDuty ${text(x['id'], 40) ?? ''}`;
    const status = text(x['status'], 40);
    const urgency = text(x['urgency'], 40);
    const service = isRecord(x['service']) ? text(x['service']['summary'], 120) : undefined;
    const bits = [status === undefined ? undefined : `status ${status}`, urgency === undefined ? undefined : `urgency ${urgency}`, service === undefined ? undefined : `service ${service}`].filter(
      (b): b is string => b !== undefined,
    );
    const details: IncidentDetails = {
      summary: `Imported from PagerDuty${bits.length > 0 ? ` (${bits.join(', ')})` : ''}. Created there ${text(x['created_at'], 40) ?? 'at an unknown time'}.`,
      ...(ref === undefined ? {} : { internalReference: ref }),
    };
    return draft(text(x['title'], 200) ?? text(x['summary'], 200), `PagerDuty incident ${i + 1}`, serviceTypes, details, importTimestamp(x['created_at']));
  });
}

function incidentIo(root: unknown, serviceTypes: readonly ServiceType[]): NewIncident[] {
  return list(root, 'incident', 'incidents').map((x, i) => {
    if (!isRecord(x)) fail(`incident ${i} is not an object.`);
    const severity = isRecord(x['severity']) ? text(x['severity']['name'], 50) : undefined;
    const status = isRecord(x['incident_status']) ? text(x['incident_status']['name'], 50) : undefined;
    const vendorSummary = text(x['summary'], 1500);
    const meta = [severity === undefined ? undefined : `severity ${severity}`, status === undefined ? undefined : `status ${status}`].filter((b): b is string => b !== undefined);
    const details: IncidentDetails = {
      summary: [`Imported from incident.io${meta.length > 0 ? ` (${meta.join(', ')})` : ''}.`, vendorSummary].filter((b): b is string => b !== undefined).join(' '),
      ...(text(x['reference'], 60) === undefined ? {} : { internalReference: `incident.io ${text(x['reference'], 60) ?? ''}` }),
    };
    return draft(text(x['name'], 200), `incident.io incident ${i + 1}`, serviceTypes, details, importTimestamp(x['created_at']));
  });
}

function misp(root: unknown, serviceTypes: readonly ServiceType[]): NewIncident[] {
  const events = Array.isArray(root) ? (root as unknown[]) : [root];
  return events.map((wrapper, i) => {
    const e = isRecord(wrapper) && isRecord(wrapper['Event']) ? wrapper['Event'] : fail(`item ${i} has no "Event" object.`);
    const attrs = Array.isArray(e['Attribute']) ? (e['Attribute'] as unknown[]) : [];
    const iocs: string[] = [];
    for (const a of attrs) {
      if (!isRecord(a) || a['to_ids'] !== true || a['deleted'] === true) continue;
      const type = text(a['type'], 60);
      const value = text(a['value'], 440);
      if (type !== undefined && value !== undefined && iocs.length < 500) iocs.push(`${type}: ${value}`);
    }
    const date = typeof e['date'] === 'string' && /^\d{4}-\d{2}-\d{2}$/u.test(e['date']) ? e['date'] : undefined;
    const uuid = text(e['uuid'], 40);
    const details: IncidentDetails = {
      summary: `Imported from a MISP event${date === undefined ? '' : ` dated ${date}`}.`,
      ...(uuid === undefined ? {} : { internalReference: `MISP ${uuid}` }),
      ...(iocs.length > 0 ? { indicatorsOfCompromise: [...new Set(iocs)] } : {}),
    };
    return draft(text(e['info'], 200), `MISP event ${i + 1}`, serviceTypes, details, undefined);
  });
}

/**
 * Parses an export into draft incidents.
 * @param serviceTypes the service types to give the drafts (the exports do not carry NIS2 service types).
 */
export function parseImport(format: ImportFormat, json: string, serviceTypes: readonly ServiceType[]): NewIncident[] {
  if (Buffer.byteLength(json) > MAX_IMPORT_BYTES) fail('The import file is too large.');
  let root: unknown;
  try {
    root = JSON.parse(json);
  } catch {
    fail('The import file is not valid JSON.');
  }
  const out = format === 'pagerduty' ? pagerDuty(root, serviceTypes) : format === 'incident-io' ? incidentIo(root, serviceTypes) : misp(root, serviceTypes);
  if (out.length === 0) fail('No incidents found.');
  if (out.length > MAX_IMPORT_INCIDENTS) fail(`Too many incidents in one import (max ${MAX_IMPORT_INCIDENTS}).`);
  return out;
}
