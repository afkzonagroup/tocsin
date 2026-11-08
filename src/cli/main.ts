// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { parseArgs, type ParseArgsConfig } from 'node:util';
import { answerText, applyAnswerText } from '../assess/answers.js';
import { questionsFor } from '../assess/questions.js';
import { findRecurringIncidents } from '../assess/recurring.js';
import { verifyAudit } from '../audit/chain.js';
import { IMPORT_FORMATS, MAX_IMPORT_BYTES, parseImport, type ImportFormat } from '../connectors/importers.js';
import { planNotifications } from '../connectors/notify.js';
import { deliverWebhook } from '../connectors/webhook.js';
import { formatRef } from '../legal/refs.js';
import { validateConfig, type TocsinConfig } from '../model/config.js';
import { SERVICE_TYPES, SERVICE_TYPE_LABELS, STAGES, STAGE_LABELS, type Incident, type ServiceType, type Stage } from '../model/types.js';
import { DETAIL_FIELDS, type DetailKey } from '../model/validate.js';
import {
  addIntermediateRequest,
  addRecipientCommunication,
  assessIncident,
  createIncident,
  findIncident,
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
  type OpContext,
} from '../registry/ops.js';
import { buildReport, type ReportContent } from '../reports/content.js';
import { REPORT_FORMATS, renderReport, validateReportContent, type ReportFormat } from '../reports/render.js';
import { computeDeadlines, pendingDeadlines, submissionOf, type Deadline } from '../stages/deadlines.js';
import { nextStages } from '../stages/machine.js';
import { createExportBundle, EncryptedStore, emptyData, readExportBundle, type StoreData } from '../store/store.js';
import { exists, isGroupOrWorldAccessible, readFileCapped, safePath, writeNewFile } from '../store/fsutil.js';
import { migrateStore } from '../store/migrate.js';
import { rekeyStore, restoreStore } from '../store/recovery.js';
import { formatInZone, parseInstant, toIso, toMs } from '../time/zone.js';
import { TocsinError, invalid, publicMessage } from '../util/errors.js';
import { oneOf, TRI_VALUES } from '../util/validate.js';
import { actorFrom, configPath, loadConfig, resolveKey, storePath } from './context.js';
import { colourEnabled, pad, paint, term, type CliIo } from './io.js';

export const VERSION = '0.1.0';

const COMMON = {
  store: { type: 'string' },
  config: { type: 'string' },
  'key-file': { type: 'string' },
  'no-color': { type: 'boolean' },
  json: { type: 'boolean' },
  help: { type: 'boolean', short: 'h' },
} as const satisfies NonNullable<ParseArgsConfig['options']>;

type Opts = NonNullable<ParseArgsConfig['options']>;

const HELP = `tocsin ${VERSION} — NIS2 significant-incident register (offline, encrypted)

Usage: tocsin <command> [options]

Setup
  init [--timezone Europe/Brussels]           Create the encrypted store and a config template
  config check                               Validate the configuration file

Incidents
  create --title T --service cloud[,cdn] [--occurred T] [--detected T] [--link ID ...]
  list                                       All incidents with next deadline
  show <id>                                  One incident in full
  set <id> <field> <value|->  [--clear]      Change a field ("-" reads standard input)
  aware <id> --at <time|now> [--reason R]    Became aware of the significant incident (starts the clocks)
  conclude <id> --at <time|now> | --reopen   Handling concluded (incident no longer ongoing)

Significance (Implementing Regulation (EU) 2024/2690, Article 23(3) NIS2)
  questions <id> [--all]                     Open (or all) questions for the assessment
  assess <id> [--answer id=value ...]        Answer questions and assess
  recurring                                  Check recurring incidents (IR 2024/2690 Art 4)

Reporting (Article 23(4) NIS2)
  deadlines [--all] [--fail-on-overdue]      Deadlines, overdue in red
  request <id> --at T [--by X] [--due T]     CSIRT/authority asked for an intermediate report
  status-update <id> <request-id> <text|->   Content of an intermediate report
  report <id> <stage> [--format md|json|html] [--out FILE] [--request R]
  submit <id> <stage> --at T [--request R] [--ref X] [--allow-incomplete]
  recipients <id> --kind incident|threat --at T --audience A --summary S [--measures M]

Records and data
  audit [--verify]                           Hash-chained audit log
  export --out FILE                          Encrypted export = backup (key: TOCSIN_EXPORT_KEY / _PASSPHRASE / prompt)
  import --in FILE [--replace]               Restore an export; --replace keeps the current store as a .bak
  rekey [--new-key-file FILE]                Re-encrypt the store under a new key (TOCSIN_NEW_KEY / _PASSPHRASE / prompt)
  migrate                                    Upgrade the store file to the current format version
  import-incidents --format pagerduty|incident-io|misp --in FILE --service TYPE
  notify [--dry-run]                         Send due/overdue webhook messages (configured webhooks only)
  ui [--port 8080] [--host 127.0.0.1]        Local web interface

Stages: ${STAGES.join(', ')}
Service types: ${SERVICE_TYPES.join(', ')}
Times: "now", 2026-03-29T14:05 (configured time zone) or 2026-03-29T14:05+02:00

Global: --store FILE (TOCSIN_STORE), --config FILE (TOCSIN_CONFIG), --key-file FILE, --no-color, --json
Keys: TOCSIN_KEY (32-byte hex/base64) or TOCSIN_PASSPHRASE, else an interactive prompt.

Tocsin by AFKzona Group — https://afkzonagroup.lt. Not legal advice.
`;

interface Parsed {
  readonly values: Record<string, string | boolean | (string | boolean)[] | undefined>;
  readonly positionals: string[];
}

function parse(args: string[], options: Opts): Parsed {
  try {
    const r = parseArgs({ args, options: { ...COMMON, ...options }, allowPositionals: true, strict: true });
    return { values: r.values, positionals: r.positionals };
  } catch (err) {
    throw new TocsinError('VALIDATION', err instanceof Error ? err.message.replace(/\s+/gu, ' ').slice(0, 200) : 'Invalid arguments.');
  }
}

function s(p: Parsed, name: string): string | undefined {
  const v = p.values[name];
  return typeof v === 'string' ? v : undefined;
}

function b(p: Parsed, name: string): boolean {
  return p.values[name] === true;
}

function req(p: Parsed, name: string): string {
  const v = s(p, name);
  if (v === undefined || v === '') invalid(`--${name} is required.`);
  return v;
}

function pos(p: Parsed, i: number, what: string): string {
  const v = p.positionals[i];
  if (v === undefined || v === '') invalid(`Missing ${what}.`);
  return v;
}

function expectPositionals(p: Parsed, n: number): void {
  if (p.positionals.length > n) invalid(`Unexpected argument "${term(p.positionals[n] ?? '').slice(0, 40)}".`);
}

function instantArg(v: string, cfg: TocsinConfig, io: CliIo): string {
  return v.trim() === 'now' ? toIso(io.now()) : parseInstant(v, cfg.timeZone);
}

function serviceList(v: string): ServiceType[] {
  const list = v.split(',').map((x) => oneOf(x.trim(), SERVICE_TYPES, 'service type'));
  if (list.length === 0) invalid('At least one service type is required.');
  return list;
}

class Session {
  constructor(
    readonly io: CliIo,
    readonly p: Parsed,
  ) {}

  get colour(): boolean {
    return colourEnabled(this.io, b(this.p, 'no-color'));
  }

  ctx(): OpContext {
    return { now: this.io.now(), actor: actorFrom(this.io) };
  }

  async config(): Promise<TocsinConfig> {
    return loadConfig(configPath(s(this.p, 'config'), this.io));
  }

  async store(): Promise<EncryptedStore> {
    const key = await resolveKey(this.io, { keyFile: s(this.p, 'key-file') });
    const path = storePath(s(this.p, 'store'), this.io);
    const store = await EncryptedStore.open(path, key);
    if (await isGroupOrWorldAccessible(path)) this.io.stderr('Warning: the store file is readable by other users. Run: chmod 600 <store>\n');
    return store;
  }

  out(text: string): void {
    this.io.stdout(text.endsWith('\n') ? text : `${text}\n`);
  }

  json(v: unknown): void {
    this.out(JSON.stringify(v, null, 2));
  }
}

async function textOrStdin(io: CliIo, v: string): Promise<string> {
  if (v !== '-') return v;
  if (io.readStdin === undefined) invalid('Standard input is not available.');
  return (await io.readStdin()).replace(/\r?\n$/u, '');
}

// ---------- rendering helpers ----------

function deadlineLine(sess: Session, cfg: TocsinConfig, inc: Incident, d: Deadline, now: number): string {
  const c = sess.colour;
  const label = d.kind === 'recipients' ? 'Recipients of services' : STAGE_LABELS[d.kind];
  const due = d.dueAt === undefined ? 'no fixed date' : formatInZone(d.dueAt, cfg.timeZone);
  let state: string;
  switch (d.state) {
    case 'overdue':
      state = paint(c, 'red', paint(c, 'bold', 'OVERDUE'));
      break;
    case 'late':
      state = paint(c, 'red', 'submitted late');
      break;
    case 'missed':
      state = paint(c, 'red', 'MISSED');
      break;
    case 'met':
      state = paint(c, 'green', 'submitted');
      break;
    case 'open': {
      if (d.dueAt === undefined) state = 'open';
      else {
        const left = toMs(d.dueAt) - now;
        const h = Math.floor(left / 3_600_000);
        const m = Math.floor((left % 3_600_000) / 60_000);
        const txt = `${h}h ${m}m left`;
        state = left <= 6 * 3_600_000 ? paint(c, 'yellow', txt) : txt;
      }
    }
  }
  const prov = d.provisional ? ' (estimate)' : '';
  return `${pad(term(inc.id), 15)} ${pad(label + (d.requestId === undefined ? '' : ` ${d.requestId}`), 26)} ${pad(due + prov, 40)} ${state}`;
}

function showIncident(sess: Session, cfg: TocsinConfig, inc: Incident): void {
  const z = cfg.timeZone;
  const t = (v: string | undefined): string => (v === undefined ? '—' : `${formatInZone(v, z)}  [${v}]`);
  const lines = [
    paint(sess.colour, 'bold', `${term(inc.id)}  ${term(inc.title)}`),
    `Service types:      ${inc.serviceTypes.map((x) => SERVICE_TYPE_LABELS[x]).join('; ')}`,
    `Occurred:           ${t(inc.occurredAt)}`,
    `Detected:           ${t(inc.detectedAt)}`,
    `Aware (significant): ${t(inc.awareAt)}`,
    `Handling concluded: ${t(inc.handlingConcludedAt)}`,
    `Assessment:         ${inc.assessment === undefined ? 'not assessed' : `${inc.assessment.outcome} (${inc.assessment.metCriteria.join(', ') || 'no criterion met'})`}`,
    '',
    'Details:',
  ];
  for (const k of DETAIL_FIELDS) {
    const v = inc.details[k];
    if (v === undefined) continue;
    lines.push(`  ${pad(k, 34)} ${term(Array.isArray(v) ? v.join(' | ') : v).replace(/\n/gu, '\n' + ' '.repeat(37))}`);
  }
  lines.push('', 'Submissions:');
  for (const st of inc.submissions) lines.push(`  ${pad(STAGE_LABELS[st.stage], 24)} ${t(st.submittedAt)}${st.authorityReference === undefined ? '' : `  ref ${term(st.authorityReference)}`}`);
  for (const r of inc.intermediateRequests) {
    lines.push(`  Request ${r.id}: requested ${t(r.requestedAt)}${r.dueAt === undefined ? '' : `, due ${t(r.dueAt)}`}${r.submission === undefined ? ', not answered' : `, answered ${t(r.submission.submittedAt)}`}`);
  }
  for (const c of inc.recipientCommunications) lines.push(`  Recipients ${c.id} (${c.kind}): ${t(c.communicatedAt)} to ${term(c.audience)}`);
  const next = nextStages(inc);
  lines.push('', `Next: ${next.length === 0 ? (inc.awareAt === undefined ? 'record awareness with "tocsin aware"' : 'nothing (closed)') : next.join(', ')}`);
  sess.out(lines.join('\n'));
}

// ---------- commands ----------

type Handler = (args: string[], io: CliIo) => Promise<number>;

const commands: Readonly<Record<string, Handler>> = {
  async init(args, io) {
    const p = parse(args, { timezone: { type: 'string' } });
    expectPositionals(p, 0);
    const sess = new Session(io, p);
    const cfgPath = configPath(s(p, 'config'), io);
    const stPath = storePath(s(p, 'store'), io);
    if (await exists(stPath)) throw new TocsinError('CONFLICT', `A store already exists at ${stPath}.`);
    if (!(await exists(cfgPath))) {
      const zone = s(p, 'timezone') ?? Intl.DateTimeFormat().resolvedOptions().timeZone;
      const template = {
        version: 1,
        timeZone: zone,
        entity: { name: 'Your entity name', category: 'important' },
        authority: { role: 'csirt', name: 'Your national CSIRT or competent authority', channel: 'How you submit reports (portal, e-mail, form)' },
      };
      validateConfig(template);
      await writeNewFile(cfgPath, `${JSON.stringify(template, null, 2)}\n`);
      sess.out(`Wrote configuration template ${cfgPath} — edit the entity and authority.`);
    }
    const key = await resolveKey(io, { keyFile: s(p, 'key-file'), confirm: true });
    const ctx = sess.ctx();
    const store = await EncryptedStore.create(stPath, key, initStore(emptyData(toIso(ctx.now)), ctx));
    store.close();
    sess.out(`Created encrypted store ${stPath} (mode 0600).`);
    return 0;
  },

  async config(args, io) {
    const p = parse(args, {});
    if (p.positionals[0] !== 'check') invalid('Usage: tocsin config check');
    expectPositionals(p, 1);
    const sess = new Session(io, p);
    const cfg = await sess.config();
    sess.out(`Configuration OK. Time zone ${cfg.timeZone}; reports go to ${term(cfg.authority.name)} (${cfg.authority.role}).`);
    if (cfg.turnover === undefined) sess.out('Note: no turnover configured; IR 2024/2690 Art 3(1)(a) will use only the EUR 500 000 limit.');
    return 0;
  },

  async create(args, io) {
    const p = parse(args, { title: { type: 'string' }, service: { type: 'string' }, occurred: { type: 'string' }, detected: { type: 'string' }, link: { type: 'string', multiple: true } });
    expectPositionals(p, 0);
    const sess = new Session(io, p);
    const cfg = await sess.config();
    const title = req(p, 'title');
    const services = serviceList(req(p, 'service'));
    const occurred = s(p, 'occurred');
    const detected = s(p, 'detected');
    const links = (p.values['link'] as string[] | undefined) ?? [];
    const input = {
      title,
      serviceTypes: services,
      ...(links.length === 0 ? {} : { linkedIncidentIds: links }),
      ...(occurred === undefined ? {} : { occurredAt: instantArg(occurred, cfg, io) }),
      ...(detected === undefined ? {} : { detectedAt: instantArg(detected, cfg, io) }),
    };
    const store = await sess.store();
    try {
      const inc = await store.transact((d) => createIncident(d, input, sess.ctx()));
      if (b(p, 'json')) sess.json(inc);
      else sess.out(`Created ${inc.id}. Next: assess significance ("tocsin questions ${inc.id}") and record awareness ("tocsin aware ${inc.id} --at now").`);
    } finally {
      store.close();
    }
    return 0;
  },

  async list(args, io) {
    const p = parse(args, {});
    expectPositionals(p, 0);
    const sess = new Session(io, p);
    const cfg = await sess.config();
    const store = await sess.store();
    try {
      const data = store.snapshot();
      if (b(p, 'json')) {
        sess.json(data.incidents.map((i) => ({ id: i.id, title: i.title, serviceTypes: i.serviceTypes, awareAt: i.awareAt, assessment: i.assessment?.outcome, next: pendingDeadlines(computeDeadlines(i, cfg.timeZone, io.now()))[0] })));
        return 0;
      }
      if (data.incidents.length === 0) {
        sess.out('No incidents.');
        return 0;
      }
      for (const i of data.incidents) {
        const next = pendingDeadlines(computeDeadlines(i, cfg.timeZone, io.now()))[0];
        const nextText = next === undefined ? (i.awareAt === undefined ? 'awareness not recorded' : 'no pending deadline') : deadlineLine(sess, cfg, i, next, io.now()).slice(16);
        sess.out(`${pad(term(i.id), 15)} ${pad(term(i.title).slice(0, 40), 41)} ${pad(i.assessment?.outcome ?? 'not assessed', 16)} ${nextText}`);
      }
    } finally {
      store.close();
    }
    return 0;
  },

  async show(args, io) {
    const p = parse(args, {});
    const id = pos(p, 0, 'incident id');
    expectPositionals(p, 1);
    const sess = new Session(io, p);
    const cfg = await sess.config();
    const store = await sess.store();
    try {
      const inc = findIncident(store.snapshot(), id);
      if (b(p, 'json')) sess.json(inc);
      else showIncident(sess, cfg, inc);
    } finally {
      store.close();
    }
    return 0;
  },

  async set(args, io) {
    const p = parse(args, { clear: { type: 'boolean' } });
    const id = pos(p, 0, 'incident id');
    const field = pos(p, 1, 'field name');
    const clear = b(p, 'clear');
    const raw = clear ? undefined : pos(p, 2, 'value');
    expectPositionals(p, clear ? 2 : 3);
    const sess = new Session(io, p);
    const cfg = await sess.config();
    const value = raw === undefined ? undefined : await textOrStdin(io, raw);
    const store = await sess.store();
    try {
      await store.transact((d) => {
        if (field === 'title') {
          if (value === undefined) invalid('The title cannot be cleared.');
          return updateCore(d, id, { title: value }, sess.ctx());
        }
        if (field === 'services') {
          if (value === undefined) invalid('Service types cannot be cleared.');
          return updateCore(d, id, { serviceTypes: serviceList(value) }, sess.ctx());
        }
        if (field === 'occurred' || field === 'detected') {
          const key = field === 'occurred' ? 'occurredAt' : 'detectedAt';
          return updateCore(d, id, { [key]: value === undefined ? null : instantArg(value, cfg, io) }, sess.ctx());
        }
        if (!(DETAIL_FIELDS as readonly string[]).includes(field)) {
          invalid(`Unknown field "${term(field).slice(0, 40)}". Fields: title, services, occurred, detected, ${DETAIL_FIELDS.join(', ')}.`);
        }
        const key = field as DetailKey;
        const patch: Record<string, unknown> = {};
        if (value === undefined) patch[key] = null;
        else if (key === 'suspectedUnlawfulOrMalicious' || key === 'crossBorderImpact' || key === 'recipientsLikelyAffected' || key === 'trustServicesImpacted') {
          if (!(TRI_VALUES as readonly string[]).includes(value)) invalid(`${key} must be yes, no or unknown.`);
          patch[key] = value;
        } else if (key === 'indicatorsOfCompromise') {
          patch[key] = value.split(/\r?\n/u).map((x) => x.trim()).filter((x) => x !== '');
        } else if (key === 'affectedMemberStates') {
          patch[key] = value.split(/[,\s]+/u).map((x) => x.trim().toUpperCase()).filter((x) => x !== '');
        } else patch[key] = value;
        return updateDetails(d, id, patch, sess.ctx());
      });
    } finally {
      store.close();
    }
    sess.out(`Updated ${term(id)}: ${field}.`);
    return 0;
  },

  async aware(args, io) {
    const p = parse(args, { at: { type: 'string' }, reason: { type: 'string' } });
    const id = pos(p, 0, 'incident id');
    expectPositionals(p, 1);
    const sess = new Session(io, p);
    const cfg = await sess.config();
    const at = instantArg(req(p, 'at'), cfg, io);
    const store = await sess.store();
    try {
      const inc = await store.transact((d) => recordAwareness(d, id, at, sess.ctx(), s(p, 'reason')));
      sess.out(`Recorded awareness for ${inc.id} at ${formatInZone(at, cfg.timeZone)}. Deadlines:`);
      for (const dl of computeDeadlines(inc, cfg.timeZone, io.now())) sess.out(deadlineLine(sess, cfg, inc, dl, io.now()));
    } finally {
      store.close();
    }
    return 0;
  },

  async conclude(args, io) {
    const p = parse(args, { at: { type: 'string' }, reopen: { type: 'boolean' } });
    const id = pos(p, 0, 'incident id');
    expectPositionals(p, 1);
    const sess = new Session(io, p);
    const cfg = await sess.config();
    const reopen = b(p, 'reopen');
    if (reopen && s(p, 'at') !== undefined) invalid('Use either --at or --reopen.');
    const at = reopen ? null : instantArg(req(p, 'at'), cfg, io);
    const store = await sess.store();
    try {
      await store.transact((d) => recordHandlingConcluded(d, id, at, sess.ctx()));
    } finally {
      store.close();
    }
    sess.out(at === null ? `${term(id)} is ongoing again.` : `Handling of ${term(id)} concluded at ${formatInZone(at, cfg.timeZone)}.`);
    return 0;
  },

  async questions(args, io) {
    const p = parse(args, { all: { type: 'boolean' } });
    const id = pos(p, 0, 'incident id');
    expectPositionals(p, 1);
    const sess = new Session(io, p);
    const cfg = await sess.config();
    const store = await sess.store();
    try {
      const inc = findIncident(store.snapshot(), id);
      const r = assessIncident(store.snapshot().incidents, inc, cfg);
      const list = b(p, 'all') ? questionsFor(inc.serviceTypes) : r.openQuestions;
      if (b(p, 'json')) {
        sess.json(list.map((q) => ({ ...q, open: r.openQuestions.some((o) => o.id === q.id), answer: answerText(inc.assessment?.answers ?? {}, q.id) })));
        return 0;
      }
      if (list.length === 0) sess.out('No open questions.');
      for (const q of list) {
        const current = answerText(inc.assessment?.answers ?? {}, q.id);
        if (current !== '') sess.out(paint(sess.colour, 'dim', `(answered: ${term(current)})`));
        sess.out(`${paint(sess.colour, 'bold', q.id)}  [${q.kind}]  ${formatRef(q.ref)}\n  ${q.text}${q.help === undefined ? '' : `\n  ${paint(sess.colour, 'dim', q.help)}`}`);
      }
      sess.out(`\nAnswer with: tocsin assess ${term(id)} --answer <id>=<value>  (tri: yes|no|unknown; duration: 45m, 1h30m; cents: euro amount)`);
    } finally {
      store.close();
    }
    return 0;
  },

  async assess(args, io) {
    const p = parse(args, { answer: { type: 'string', multiple: true } });
    const id = pos(p, 0, 'incident id');
    expectPositionals(p, 1);
    const sess = new Session(io, p);
    const cfg = await sess.config();
    const raw = (p.values['answer'] as string[] | undefined) ?? [];
    if (raw.length > 200) invalid('Too many answers.');
    const assignments = raw.map((a): [string, string] => {
      const i = a.indexOf('=');
      if (i <= 0) invalid(`Answers look like id=value; got "${term(a).slice(0, 60)}".`);
      return [a.slice(0, i).trim(), a.slice(i + 1)];
    });
    const store = await sess.store();
    try {
      const { assessment } = await store.transact((d) => {
        const inc = findIncident(d, id);
        const answers = applyAnswerText(inc.assessment?.answers ?? {}, assignments);
        return saveAssessment(d, id, answers, cfg, sess.ctx());
      });
      if (b(p, 'json')) {
        sess.json(assessment);
        return 0;
      }
      const colour = assessment.outcome === 'significant' ? 'red' : assessment.outcome === 'undetermined' ? 'yellow' : 'green';
      sess.out(`Outcome: ${paint(sess.colour, colour, paint(sess.colour, 'bold', assessment.outcome.toUpperCase()))}`);
      for (const r of assessment.reasons) sess.out(`  met  ${r.id}${r.serviceType === undefined ? '' : ` (${r.serviceType})`}  ${formatRef(r.ref)}\n       ${r.criterion}\n       ${r.reason}`);
      for (const n of assessment.notes) sess.out(`  note ${n}`);
      if (assessment.openQuestions.length > 0) sess.out(`  ${assessment.openQuestions.length} open question(s): tocsin questions ${term(id)}`);
      if (assessment.outcome === 'significant') sess.out(`  The assessment is advisory. If you conclude it is significant, record awareness: tocsin aware ${term(id)} --at <time>`);
    } finally {
      store.close();
    }
    return 0;
  },

  async recurring(args, io) {
    const p = parse(args, {});
    expectPositionals(p, 0);
    const sess = new Session(io, p);
    const cfg = await sess.config();
    const store = await sess.store();
    try {
      const findings = findRecurringIncidents(store.snapshot().incidents, cfg.turnover?.amountCents, cfg.timeZone);
      if (b(p, 'json')) {
        sess.json(findings);
        return 0;
      }
      if (findings.length === 0) sess.out('No candidate groups (needs incidents assessed as not significant with the same rootCauseKey).');
      for (const f of findings) {
        const st = f.status === 'met' ? paint(sess.colour, 'red', 'SIGNIFICANT (collectively)') : f.status === 'unknown' ? paint(sess.colour, 'yellow', 'undetermined') : 'not met';
        sess.out(`${term(f.rootCauseKey)}: ${st}\n  ${f.incidentIds.join(', ')}\n  ${term(f.reason)}\n  ${formatRef(f.ref)}`);
      }
      if (findings.some((f) => f.status === 'met')) {
        sess.out('To report a group: tocsin create --title "Recurring: …" --service <type> --link <id> --link <id>, then assess and record awareness.');
      }
    } finally {
      store.close();
    }
    return 0;
  },

  async deadlines(args, io) {
    const p = parse(args, { all: { type: 'boolean' }, 'fail-on-overdue': { type: 'boolean' } });
    expectPositionals(p, 0);
    const sess = new Session(io, p);
    const cfg = await sess.config();
    const store = await sess.store();
    let overdue: number;
    try {
      const now = io.now();
      const rows: { inc: Incident; d: Deadline }[] = [];
      for (const inc of store.snapshot().incidents) {
        const ds = computeDeadlines(inc, cfg.timeZone, now);
        for (const d of b(p, 'all') ? ds : pendingDeadlines(ds)) rows.push({ inc, d });
      }
      overdue = rows.filter((r) => r.d.state === 'overdue').length;
      rows.sort((a, c) => (a.d.dueAt === undefined ? 1 : 0) - (c.d.dueAt === undefined ? 1 : 0) || (a.d.dueAt !== undefined && c.d.dueAt !== undefined ? toMs(a.d.dueAt) - toMs(c.d.dueAt) : 0));
      if (b(p, 'json')) sess.json(rows.map((r) => ({ incidentId: r.inc.id, ...r.d })));
      else if (rows.length === 0) sess.out('No pending deadlines.');
      else {
        sess.out(paint(sess.colour, 'bold', `${pad('Incident', 15)} ${pad('Stage', 26)} ${pad(`Due (${cfg.timeZone})`, 40)} State`));
        for (const r of rows) sess.out(deadlineLine(sess, cfg, r.inc, r.d, now));
      }
    } finally {
      store.close();
    }
    return b(p, 'fail-on-overdue') && overdue > 0 ? 3 : 0;
  },

  async request(args, io) {
    const p = parse(args, { at: { type: 'string' }, by: { type: 'string' }, due: { type: 'string' } });
    const id = pos(p, 0, 'incident id');
    expectPositionals(p, 1);
    const sess = new Session(io, p);
    const cfg = await sess.config();
    const due = s(p, 'due');
    const by = s(p, 'by');
    const input = { requestedAt: instantArg(req(p, 'at'), cfg, io), ...(by === undefined ? {} : { requestedBy: by }), ...(due === undefined ? {} : { dueAt: instantArg(due, cfg, io) }) };
    const store = await sess.store();
    try {
      const r = await store.transact((d) => addIntermediateRequest(d, id, input, sess.ctx()));
      sess.out(`Recorded request ${r.id}. Write the update: tocsin status-update ${term(id)} ${r.id} "<text>"`);
    } finally {
      store.close();
    }
    return 0;
  },

  async 'status-update'(args, io) {
    const p = parse(args, {});
    const id = pos(p, 0, 'incident id');
    const rid = pos(p, 1, 'request id');
    const text = await textOrStdin(io, pos(p, 2, 'text'));
    expectPositionals(p, 3);
    const sess = new Session(io, p);
    const store = await sess.store();
    try {
      await store.transact((d) => setStatusUpdate(d, id, rid, text, sess.ctx()));
    } finally {
      store.close();
    }
    sess.out(`Saved status update for ${term(id)} ${term(rid)}.`);
    return 0;
  },

  async report(args, io) {
    const p = parse(args, { format: { type: 'string' }, out: { type: 'string' }, request: { type: 'string' } });
    const id = pos(p, 0, 'incident id');
    const stage = oneOf(pos(p, 1, 'stage'), STAGES, 'stage');
    expectPositionals(p, 2);
    const format: ReportFormat = oneOf(s(p, 'format') ?? 'md', REPORT_FORMATS, 'format');
    const sess = new Session(io, p);
    const cfg = await sess.config();
    const store = await sess.store();
    try {
      const inc = findIncident(store.snapshot(), id);
      const requestId = s(p, 'request');
      let content: ReportContent;
      const submitted =
        stage === 'intermediate-report' ? inc.intermediateRequests.find((r) => r.id === requestId)?.submission : submissionOf(inc, stage);
      if (submitted !== undefined) content = validateReportContent(submitted.snapshot);
      else content = buildReport(inc, stage, cfg, io.now(), requestId);
      const text = renderReport(content, format);
      const out = s(p, 'out');
      // On a terminal, carriage returns in stored text could overwrite what was printed before them.
      if (out === undefined) io.stdout(io.isTty ? term(text) : text);
      else {
        await writeNewFile(safePath(out, 'output'), text);
        await store.transact((d) => ({ data: logEvent(d, 'report.exported', sess.ctx(), id, `${stage} as ${format}`), result: undefined }));
        sess.out(`Wrote ${out} (plaintext, mode 0600)${submitted === undefined ? '' : ' — content as submitted'}.`);
      }
      if (submitted === undefined && content.missing.length > 0) io.stderr(`Draft: prescribed elements still empty: ${content.missing.join(', ')}\n`);
    } finally {
      store.close();
    }
    return 0;
  },

  async submit(args, io) {
    const p = parse(args, { at: { type: 'string' }, request: { type: 'string' }, ref: { type: 'string' }, 'allow-incomplete': { type: 'boolean' } });
    const id = pos(p, 0, 'incident id');
    const stage: Stage = oneOf(pos(p, 1, 'stage'), STAGES, 'stage');
    expectPositionals(p, 2);
    const sess = new Session(io, p);
    const cfg = await sess.config();
    const at = instantArg(req(p, 'at'), cfg, io);
    const requestId = s(p, 'request');
    const ref = s(p, 'ref');
    const store = await sess.store();
    try {
      const inc = await store.transact((d) =>
        recordSubmission(
          d,
          id,
          { stage, submittedAt: at, ...(requestId === undefined ? {} : { requestId }), ...(ref === undefined ? {} : { authorityReference: ref }), allowIncomplete: b(p, 'allow-incomplete') },
          cfg,
          sess.ctx(),
        ),
      );
      const d = computeDeadlines(inc, cfg.timeZone, io.now()).find((x) => x.kind === stage && (x.requestId ?? undefined) === requestId);
      sess.out(`Recorded ${STAGE_LABELS[stage]} for ${inc.id} at ${formatInZone(at, cfg.timeZone)}${d?.state === 'late' ? paint(sess.colour, 'red', ' — after the deadline') : ''}.`);
    } finally {
      store.close();
    }
    return 0;
  },

  async recipients(args, io) {
    const p = parse(args, { kind: { type: 'string' }, at: { type: 'string' }, audience: { type: 'string' }, summary: { type: 'string' }, measures: { type: 'string' } });
    const id = pos(p, 0, 'incident id');
    expectPositionals(p, 1);
    const sess = new Session(io, p);
    const cfg = await sess.config();
    const kind = oneOf(req(p, 'kind'), ['incident', 'threat'] as const, 'kind') === 'incident' ? 'incident-23-1' : 'cyber-threat-23-2';
    const measures = s(p, 'measures');
    const input = { kind, communicatedAt: instantArg(req(p, 'at'), cfg, io), audience: req(p, 'audience'), summary: req(p, 'summary'), ...(measures === undefined ? {} : { measuresOrRemedies: measures }) } as const;
    const store = await sess.store();
    try {
      const c = await store.transact((d) => addRecipientCommunication(d, id, input, sess.ctx()));
      sess.out(`Recorded communication ${c.id}.`);
    } finally {
      store.close();
    }
    return 0;
  },

  async audit(args, io) {
    const p = parse(args, { verify: { type: 'boolean' } });
    expectPositionals(p, 0);
    const sess = new Session(io, p);
    const store = await sess.store();
    try {
      const log = store.snapshot().audit;
      const check = verifyAudit(log);
      if (b(p, 'json')) {
        sess.json(b(p, 'verify') ? check : log);
        return check.ok ? 0 : 1;
      }
      if (!b(p, 'verify')) {
        for (const e of log) sess.out(`${String(e.seq).padStart(5)}  ${e.at}  ${pad(term(e.actor), 14)} ${pad(e.action, 20)} ${term(e.target ?? '')} ${e.fields.join(',')}${e.note === undefined ? '' : `  (${term(e.note)})`}`);
      }
      sess.out(check.ok ? paint(sess.colour, 'green', `Audit chain intact: ${check.entries} entries, head ${check.head}`) : paint(sess.colour, 'red', `Audit chain BROKEN at ${check.brokenAt ?? '?'}: ${check.problem ?? ''}`));
      return check.ok ? 0 : 1;
    } finally {
      store.close();
    }
  },

  async export(args, io) {
    const p = parse(args, { out: { type: 'string' } });
    expectPositionals(p, 0);
    const sess = new Session(io, p);
    const out = safePath(req(p, 'out'), 'output');
    if (await exists(out)) throw new TocsinError('CONFLICT', 'The output file already exists.');
    const store = await sess.store();
    try {
      const exportKey = await resolveKey(io, { prefix: 'TOCSIN_EXPORT', confirm: true, label: 'Export passphrase' });
      const data = await store.transact((d) => {
        const next = logEvent(d, 'export.created', sess.ctx());
        return { data: next, result: next };
      });
      await writeNewFile(out, await createExportBundle(data, exportKey));
      sess.out(`Wrote encrypted export ${out}: ${data.incidents.length} incident(s), ${data.audit.length} audit entries.`);
    } finally {
      store.close();
    }
    return 0;
  },

  async import(args, io) {
    const p = parse(args, { in: { type: 'string' }, replace: { type: 'boolean' } });
    expectPositionals(p, 0);
    const sess = new Session(io, p);
    const input = safePath(req(p, 'in'), 'input');
    const stPath = storePath(s(p, 'store'), io);
    const replace = b(p, 'replace');
    if (!replace && (await exists(stPath))) {
      throw new TocsinError('CONFLICT', 'The target store already exists. To replace it, pass --replace; the current file is then kept as a .bak copy.');
    }
    const bundle = await readFileCapped(input, 64 * 1024 * 1024);
    const exportKey = await resolveKey(io, { prefix: 'TOCSIN_EXPORT', label: 'Export passphrase' });
    // Every record and the audit chain are verified here, before the store is touched.
    const data: StoreData = await readExportBundle(bundle, exportKey);
    const key = await resolveKey(io, { keyFile: s(p, 'key-file'), confirm: true, label: 'New store passphrase' });
    const r = await restoreStore(stPath, key, data, sess.ctx(), { replace });
    sess.out(`Restored ${r.incidents} incident(s) into ${stPath}; audit chain verified (${r.auditEntries} entries, head ${r.auditHead}).`);
    if (r.replacedBackup !== undefined) sess.out(`The replaced store was kept as ${r.replacedBackup} (mode 0600).`);
    return 0;
  },

  async rekey(args, io) {
    const p = parse(args, { 'new-key-file': { type: 'string' } });
    expectPositionals(p, 0);
    const sess = new Session(io, p);
    const stPath = storePath(s(p, 'store'), io);
    const current = await resolveKey(io, { keyFile: s(p, 'key-file'), label: 'Current store passphrase' });
    const next = await resolveKey(io, { prefix: 'TOCSIN_NEW', keyFile: s(p, 'new-key-file'), confirm: true, label: 'New store passphrase' });
    const r = await rekeyStore(stPath, current, next, sess.ctx());
    sess.out(`Re-encrypted ${stPath}: ${r.from} replaced by a new ${r.to}. Audit chain verified (${r.auditEntries} entries, head ${r.auditHead}).`);
    sess.out('Use the new key from now on (TOCSIN_KEY, TOCSIN_PASSPHRASE or --key-file). Backups and exports made before now still open with their old keys.');
    return 0;
  },

  async migrate(args, io) {
    const p = parse(args, {});
    expectPositionals(p, 0);
    const sess = new Session(io, p);
    const stPath = storePath(s(p, 'store'), io);
    const key = await resolveKey(io, { keyFile: s(p, 'key-file') });
    const r = await migrateStore(stPath, key, sess.ctx());
    if (r.applied.length === 0) sess.out(`The store is already at format version ${r.to}; nothing to do. Audit chain verified (${r.auditEntries} entries).`);
    else sess.out(`Migrated ${stPath} from format version ${r.from} to ${r.to}. Audit chain verified (${r.auditEntries} entries, head ${r.auditHead}). The original is kept as ${r.backup ?? '?'}.`);
    return 0;
  },

  async 'import-incidents'(args, io) {
    const p = parse(args, { format: { type: 'string' }, in: { type: 'string' }, service: { type: 'string' } });
    expectPositionals(p, 0);
    const sess = new Session(io, p);
    const format: ImportFormat = oneOf(req(p, 'format'), IMPORT_FORMATS, 'format');
    const services = serviceList(req(p, 'service'));
    const json = (await readFileCapped(safePath(req(p, 'in'), 'input'), MAX_IMPORT_BYTES)).toString('utf8');
    const drafts = parseImport(format, json, services);
    const store = await sess.store();
    try {
      const ids = await store.transact((d) => {
        let data = d;
        const created: string[] = [];
        for (const draft of drafts) {
          const r = createIncident(data, draft, sess.ctx());
          data = r.data;
          created.push(r.result.id);
        }
        return { data: logEvent(data, 'incidents.imported', sess.ctx(), undefined, `${format}: ${created.length}`), result: created };
      });
      sess.out(`Imported ${ids.length} draft incident(s): ${ids.join(', ')}. Assess each one; nothing was marked significant.`);
    } finally {
      store.close();
    }
    return 0;
  },

  async notify(args, io) {
    const p = parse(args, { 'dry-run': { type: 'boolean' } });
    expectPositionals(p, 0);
    const sess = new Session(io, p);
    const cfg = await sess.config();
    if ((cfg.webhooks ?? []).length === 0) {
      sess.out('No webhooks configured; nothing sent.');
      return 0;
    }
    const store = await sess.store();
    let failed = 0;
    try {
      const plan = planNotifications(store.snapshot(), cfg, io.now());
      if (b(p, 'dry-run')) {
        for (const n of plan) sess.out(`[dry-run] ${n.webhookId}: ${term(n.message.text)}`);
        if (plan.length === 0) sess.out('Nothing to send.');
        return 0;
      }
      const delivered: string[] = [];
      for (const n of plan) {
        const hook = (cfg.webhooks ?? []).find((h) => h.id === n.webhookId);
        if (hook === undefined) continue;
        try {
          await deliverWebhook(hook, n.message, io.env);
          delivered.push(n.key);
        } catch (err) {
          failed++;
          io.stderr(`Webhook ${hook.id}: ${publicMessage(err)}\n`);
        }
      }
      if (delivered.length > 0) await store.transact((d) => ({ data: markNotified(d, delivered, sess.ctx()), result: undefined }));
      sess.out(`Sent ${delivered.length} of ${plan.length} message(s).`);
    } finally {
      store.close();
    }
    return failed > 0 ? 1 : 0;
  },

  async ui(args, io) {
    const p = parse(args, { port: { type: 'string' }, host: { type: 'string' }, 'allow-non-loopback': { type: 'boolean' }, 'allowed-host': { type: 'string', multiple: true } });
    expectPositionals(p, 0);
    const sess = new Session(io, p);
    const cfg = await sess.config();
    const cfgPath = configPath(s(p, 'config'), io);
    const store = await sess.store();
    const { startUi } = await import('../ui/server.js');
    const portText = s(p, 'port') ?? '8080';
    if (!/^\d{1,5}$/u.test(portText) || Number(portText) > 65535) invalid('--port must be 0-65535.');
    const allowed = (p.values['allowed-host'] as string[] | undefined) ?? [];
    const ui = await startUi({
      store,
      config: cfg,
      configPath: cfgPath,
      host: s(p, 'host') ?? '127.0.0.1',
      port: Number(portText),
      allowNonLoopback: b(p, 'allow-non-loopback'),
      allowedHosts: allowed,
      actor: actorFrom(io),
      now: io.now,
    });
    io.stderr(`Tocsin UI on ${ui.origin}\nOpen this link (it carries the session token; do not share it):\n${ui.loginUrl}\nPress Ctrl+C to stop.\n`);
    await ui.closed;
    store.close();
    return 0;
  },
};

/**
 * CLI entry point. Returns the exit code: 0 success, 1 error, 2 usage error, 3 overdue (--fail-on-overdue).
 */
export async function run(argv: readonly string[], io: CliIo): Promise<number> {
  const [cmd, ...rest] = argv;
  if (cmd === undefined || cmd === 'help' || cmd === '--help' || cmd === '-h') {
    io.stdout(HELP);
    return cmd === undefined ? 2 : 0;
  }
  if (cmd === '--version' || cmd === 'version') {
    io.stdout(`${VERSION}\n`);
    return 0;
  }
  const handler = Object.hasOwn(commands, cmd) ? commands[cmd] : undefined;
  if (handler === undefined) {
    io.stderr(`Unknown command "${term(cmd).slice(0, 40)}". Run "tocsin help".\n`);
    return 2;
  }
  if (rest.includes('--help') || rest.includes('-h')) {
    io.stdout(HELP);
    return 0;
  }
  try {
    return await handler([...rest], io);
  } catch (err) {
    const msg = publicMessage(err);
    io.stderr(`Error: ${term(msg)}\n`);
    if (err instanceof TocsinError) return err.code === 'VALIDATION' ? 2 : 1;
    if (io.env['TOCSIN_DEBUG'] === '1' && err instanceof Error) io.stderr(`${err.stack ?? ''}\n`);
    return 1;
  }
}

