// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { answerText } from '../assess/answers.js';
import { questionsFor } from '../assess/questions.js';
import type { AssessmentResult } from '../assess/assess.js';
import type { RecurringFinding } from '../assess/recurring.js';
import type { ChainCheck, AuditEntry } from '../audit/chain.js';
import { formatRef, SOURCES } from '../legal/refs.js';
import type { TocsinConfig } from '../model/config.js';
import { SERVICE_TYPES, SERVICE_TYPE_LABELS, STAGES, STAGE_LABELS, type Incident } from '../model/types.js';
import { ATTRIBUTION } from '../reports/content.js';
import type { Deadline } from '../stages/deadlines.js';
import { nextStages } from '../stages/machine.js';
import { formatInZone, toMs } from '../time/zone.js';
import { html, raw, type SafeHtml } from '../util/html.js';
import type { Tri } from '../util/validate.js';

/** Server-rendered pages. Every dynamic value goes through the escaping `html` template. No scripts. */

export const SOURCE_URL = 'https://github.com/afkzonagroup/tocsin';

export interface PageCtx {
  readonly csrf: string;
  readonly cfg: TocsinConfig;
  readonly now: number;
}

export function layout(title: string, body: SafeHtml, ctx: PageCtx | undefined, flash?: { kind: 'ok' | 'bad'; text: string }): string {
  return html`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="same-origin">
<title>${title} — Tocsin</title>
<link rel="stylesheet" href="/static/app.css">
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header class="top"><div class="in"><a class="brand" href="/">Tocsin</a>${
    ctx === undefined
      ? raw('')
      : html`<nav aria-label="Main"><ul><li><a href="/">Incidents</a></li><li><a href="/new">New incident</a></li><li><a href="/recurring">Recurring</a></li><li><a href="/audit">Audit log</a></li><li><a href="/about">About</a></li></ul></nav>
<form method="post" action="/logout" class="row lock"><input type="hidden" name="_csrf" value="${ctx.csrf}"><button class="secondary" type="submit">Lock</button></form>`
  }</div></header>
<main id="main">
${flash === undefined ? raw('') : html`<p class="flash ${flash.kind}" role="${flash.kind === 'bad' ? 'alert' : 'status'}">${flash.text}</p>`}
${body}
</main>
<footer><div class="in"><a href="${ATTRIBUTION.url}" rel="noopener noreferrer">${ATTRIBUTION.text}</a> · <a href="/about">About and legal notices</a> · <a href="${SOURCE_URL}" rel="noopener noreferrer">Source code</a> · Not legal advice.</div></footer>
</body>
</html>
`.value;
}

function csrfField(ctx: PageCtx): SafeHtml {
  return html`<input type="hidden" name="_csrf" value="${ctx.csrf}">`;
}

function when(ctx: PageCtx, iso: string | undefined): string {
  return iso === undefined ? '—' : formatInZone(iso, ctx.cfg.timeZone);
}

function stateBadge(d: Deadline, now: number): SafeHtml {
  switch (d.state) {
    case 'overdue':
      return raw('<span class="badge bad">Overdue</span>');
    case 'late':
      return raw('<span class="badge bad">Submitted late</span>');
    case 'missed':
      return raw('<span class="badge bad">Missed</span>');
    case 'met':
      return raw('<span class="badge ok">Submitted</span>');
    case 'open':
      if (d.dueAt !== undefined && toMs(d.dueAt) - now <= 6 * 3_600_000) return raw('<span class="badge warn">Due soon</span>');
      return raw('<span class="badge">Open</span>');
  }
}

function deadlineLabel(d: Deadline): string {
  return (d.kind === 'recipients' ? 'Recipients of services' : STAGE_LABELS[d.kind]) + (d.requestId === undefined ? '' : ` (${d.requestId})`);
}

export function deadlineTable(ctx: PageCtx, rows: readonly { inc: Incident; d: Deadline }[], showIncident: boolean): SafeHtml {
  if (rows.length === 0) return raw('<p class="muted">No deadlines.</p>');
  return html`<div class="table-wrap"><table>
<thead><tr>${showIncident ? raw('<th scope="col">Incident</th>') : raw('')}<th scope="col">Stage</th><th scope="col">Due (${ctx.cfg.timeZone})</th><th scope="col">State</th><th scope="col">Basis</th></tr></thead>
<tbody>${rows.map(
    ({ inc, d }) =>
      html`<tr>${showIncident ? html`<td class="nowrap" data-label="Incident"><a href="/incidents/${inc.id}">${inc.id}</a></td>` : raw('')}<td data-label="Stage">${deadlineLabel(d)}</td><td data-label="Due">${d.dueAt === undefined ? 'no fixed date' : when(ctx, d.dueAt)}${
        d.provisional ? ' (estimate)' : ''
      }</td><td data-label="State">${stateBadge(d, ctx.now)}</td><td data-label="Basis"><span class="ref">${d.basis}. <a href="${d.ref.url}" rel="noopener noreferrer">${formatRef(d.ref)}</a></span></td></tr>`,
  )}</tbody></table></div>`;
}

export function homePage(ctx: PageCtx, incidents: readonly Incident[], pending: readonly { inc: Incident; d: Deadline }[]): SafeHtml {
  return html`<h1>Incidents</h1>
<h2>Pending deadlines</h2>
${deadlineTable(ctx, pending, true)}
<h2>Register</h2>
${
  incidents.length === 0
    ? html`<p>No incidents yet. <a href="/new">Record the first one</a>.</p>`
    : html`<div class="table-wrap"><table><thead><tr><th scope="col">Id</th><th scope="col">Title</th><th scope="col">Assessment</th><th scope="col">Aware</th><th scope="col">Next</th></tr></thead><tbody>${incidents.map(
        (i) =>
          html`<tr><td class="nowrap" data-label="Id"><a href="/incidents/${i.id}">${i.id}</a></td><td data-label="Title">${i.title}</td><td data-label="Assessment">${i.assessment?.outcome ?? 'not assessed'}</td><td data-label="Aware">${when(ctx, i.awareAt)}</td><td data-label="Next">${
            nextStages(i)
              .map((s) => STAGE_LABELS[s])
              .join(', ') || (i.awareAt === undefined ? 'record awareness' : '—')
          }</td></tr>`,
      )}</tbody></table></div>`
}`;
}

function timeField(name: string, label: string, hint: string, value = ''): SafeHtml {
  return html`<div><label for="${name}">${label}<span class="hint">${hint}</span></label><input type="text" id="${name}" name="${name}" value="${value}" autocomplete="off" spellcheck="false" placeholder="2026-03-29T14:05 or now"></div>`;
}

export function newIncidentPage(ctx: PageCtx): SafeHtml {
  return html`<h1>New incident</h1>
<form class="stack" method="post" action="/incidents">${csrfField(ctx)}
<div><label for="title">Title</label><input type="text" id="title" name="title" required maxlength="200"></div>
<fieldset><legend>Affected service types</legend><div class="choices">${SERVICE_TYPES.map(
    (t) => html`<label><input type="checkbox" name="serviceTypes" value="${t}"> ${SERVICE_TYPE_LABELS[t]}</label>`,
  )}</div></fieldset>
${timeField('occurredAt', 'Occurred', `Optional. Time zone ${ctx.cfg.timeZone} unless you add an offset such as +02:00.`)}
${timeField('detectedAt', 'Detected', 'Optional.')}
<div><button type="submit">Create</button></div>
</form>`;
}

const TRI_LABEL: Readonly<Record<Tri, string>> = { yes: 'Yes', no: 'No', unknown: 'Not yet determined' };

function triRadios(name: string, current: Tri | undefined): SafeHtml {
  return html`<div class="choices">${(['yes', 'no', 'unknown'] as const).map(
    (v) => html`<label><input type="radio" name="${name}" value="${v}"${current === v ? raw(' checked') : raw('')}> ${TRI_LABEL[v]}</label>`,
  )}<label><input type="radio" name="${name}" value=""${current === undefined ? raw(' checked') : raw('')}> Not answered</label></div>`;
}

function textArea(name: string, label: string, value: string | undefined, hint?: string): SafeHtml {
  return html`<div><label for="${name}">${label}${hint === undefined ? raw('') : html`<span class="hint">${hint}</span>`}</label><textarea id="${name}" name="${name}">${value ?? ''}</textarea></div>`;
}

function stageOptions(name: string, stages: readonly string[]): SafeHtml {
  return html`<fieldset><legend>Stage</legend><div class="choices">${stages.map(
    (s, i) => html`<label><input type="radio" name="${name}" value="${s}"${i === 0 ? raw(' checked') : raw('')}> ${STAGE_LABELS[s as keyof typeof STAGE_LABELS]}</label>`,
  )}</div></fieldset>`;
}

export function incidentPage(ctx: PageCtx, inc: Incident, deadlines: readonly Deadline[], assessment: AssessmentResult): SafeHtml {
  const d = inc.details;
  const closed = inc.submissions.some((s) => s.stage === 'final-report');
  const next = nextStages(inc);
  return html`<h1>${inc.id}: ${inc.title}</h1>
<div class="panel"><dl class="facts">
<dt>Service types</dt><dd>${inc.serviceTypes.map((t) => SERVICE_TYPE_LABELS[t]).join('; ')}</dd>
<dt>Occurred</dt><dd>${when(ctx, inc.occurredAt)}</dd>
<dt>Detected</dt><dd>${when(ctx, inc.detectedAt)}</dd>
<dt>Became aware</dt><dd>${when(ctx, inc.awareAt)}</dd>
<dt>Handling concluded</dt><dd>${when(ctx, inc.handlingConcludedAt)}</dd>
<dt>Assessment</dt><dd>${assessment.outcome}${inc.assessment === undefined ? ' (not saved yet)' : ''}</dd>
</dl></div>

<h2>Deadlines</h2>
${inc.awareAt === undefined ? raw('<p class="muted">Deadlines start when you record that the entity became aware of the significant incident.</p>') : deadlineTable(ctx, deadlines.map((x) => ({ inc, d: x })), false)}

${
  closed
    ? raw('<p class="muted">The final report was submitted. The record is closed.</p>')
    : html`<h2>Awareness and handling</h2>
<form class="stack" method="post" action="/incidents/${inc.id}/aware">${csrfField(ctx)}
${timeField('at', 'Became aware of the significant incident', 'Starts the 24-hour and 72-hour clocks (Art 23(4) NIS2). Aware means a reasonable degree of certainty after initial assessment (recital 31 IR 2024/2690).')}
<div><label for="reason">Reason for a change<span class="hint">Required when changing the time after a report was submitted.</span></label><input type="text" id="reason" name="reason" maxlength="500"></div>
<div><button type="submit">Record awareness</button></div></form>
<form class="stack" method="post" action="/incidents/${inc.id}/conclude">${csrfField(ctx)}
${timeField('at', 'Handling concluded', 'When the incident is no longer ongoing. Leave empty and submit to mark it ongoing again.')}
<div><button type="submit">Save</button></div></form>`
}

<h2>Significance assessment</h2>
<p class="muted">${assessment.outcome === 'significant' ? 'At least one criterion is met.' : assessment.outcome === 'undetermined' ? 'Some answers are missing.' : 'No criterion is met.'} The assessment is advisory; the decision is yours.</p>
${
  assessment.reasons.length === 0
    ? raw('')
    : html`<ul>${assessment.reasons.map((r) => html`<li><strong>${r.criterion}</strong> — ${r.reason} <span class="ref"><a href="${r.ref.url}" rel="noopener noreferrer">${formatRef(r.ref)}</a></span></li>`)}</ul>`
}
${assessment.notes.length === 0 ? raw('') : html`<ul>${assessment.notes.map((n) => html`<li class="muted">${n}</li>`)}</ul>`}
${
  closed
    ? raw('')
    : html`<form class="stack" method="post" action="/incidents/${inc.id}/assess">${csrfField(ctx)}
<p class="muted">${assessment.openQuestions.length} question(s) still open. Answers you leave empty stay unknown.</p>
${questionsFor(inc.serviceTypes).map((q) => {
  const id = `q-${q.id.replace(/[^A-Za-z0-9-]/gu, '-')}`;
  const current = answerText(inc.assessment?.answers ?? {}, q.id);
  const open = assessment.openQuestions.some((o) => o.id === q.id);
  return html`<div class="q${open ? ' open' : ''}">${open ? raw('<p><span class="badge warn">Open</span></p>') : raw('')}${
    q.kind === 'tri'
      ? html`<fieldset><legend>${q.text}</legend>${q.help === undefined ? raw('') : html`<p class="hint">${q.help}</p>`}${triRadios(`a:${q.id}`, current === '' ? undefined : (current as Tri))}<p class="ref"><a href="${q.ref.url}" rel="noopener noreferrer">${formatRef(q.ref)}</a></p></fieldset>`
      : html`<label for="${id}">${q.text}<span class="hint">${q.help ?? ''} ${q.kind === 'duration' ? 'Format: 45m, 1h30m.' : q.kind === 'cents' ? 'Amount in euro.' : 'Whole number.'}</span></label><input type="text" id="${id}" name="a:${q.id}" value="${current}" inputmode="${q.kind === 'duration' ? 'text' : 'decimal'}"><p class="ref"><a href="${q.ref.url}" rel="noopener noreferrer">${formatRef(q.ref)}</a></p>`
  }</div>`;
})}
<div><button type="submit">Save answers</button></div></form>`
}

${
  closed
    ? raw('')
    : html`<h2>Report content</h2>
<form class="stack" method="post" action="/incidents/${inc.id}/details">${csrfField(ctx)}
<fieldset><legend>Suspected of being caused by unlawful or malicious acts (Art 23(4)(a))</legend>${triRadios('suspectedUnlawfulOrMalicious', d.suspectedUnlawfulOrMalicious)}</fieldset>
${textArea('suspectedUnlawfulOrMaliciousNote', 'Note on suspected unlawful or malicious acts', d.suspectedUnlawfulOrMaliciousNote)}
<fieldset><legend>Could have / has a cross-border impact (Art 23(4)(a), (d)(iv))</legend>${triRadios('crossBorderImpact', d.crossBorderImpact)}</fieldset>
${textArea('crossBorderImpactDetails', 'Cross-border impact details', d.crossBorderImpactDetails, 'Information enabling the authority to determine any cross-border impact (Art 23(1)).')}
<div><label for="affectedMemberStates">Member States concerned<span class="hint">Two-letter codes separated by commas (EL for Greece).</span></label><input type="text" id="affectedMemberStates" name="affectedMemberStates" value="${(d.affectedMemberStates ?? []).join(', ')}"></div>
${textArea('severity', 'Severity', d.severity, 'Initial assessment in the notification (Art 23(4)(b)); final in the final report (Art 23(4)(d)(i)).')}
${textArea('impact', 'Impact', d.impact)}
${textArea('indicatorsOfCompromise', 'Indicators of compromise', (d.indicatorsOfCompromise ?? []).join('\n'), 'One per line. Where available (Art 23(4)(b)).')}
${textArea('description', 'Detailed description', d.description, 'Final report (Art 23(4)(d)(i)).')}
${textArea('threatTypeOrRootCause', 'Type of threat or root cause', d.threatTypeOrRootCause, 'Final report (Art 23(4)(d)(ii)).')}
${textArea('mitigationApplied', 'Applied mitigation measures', d.mitigationApplied, 'Final report (Art 23(4)(d)(iii)).')}
${textArea('mitigationOngoing', 'Ongoing mitigation measures', d.mitigationOngoing, 'Write "None" if none are ongoing.')}
${textArea('progressStatus', 'Progress of the ongoing incident', d.progressStatus, 'Progress report (Art 23(4)(e)).')}
${textArea('summary', 'Summary (optional)', d.summary)}
<div><label for="rootCauseKey">Root-cause label<span class="hint">Optional. Same label = same apparent root cause, for the recurring-incident check (IR 2024/2690 Art 4). Lower-case letters, digits, dots and dashes.</span></label><input type="text" id="rootCauseKey" name="rootCauseKey" value="${d.rootCauseKey ?? ''}"></div>
<fieldset><legend>Likely to adversely affect the provision of services to recipients (Art 23(1))</legend>${triRadios('recipientsLikelyAffected', d.recipientsLikelyAffected)}</fieldset>
${inc.serviceTypes.includes('trust-service') ? html`<fieldset><legend>Impact on the provision of trust services (24-hour notification)</legend>${triRadios('trustServicesImpacted', d.trustServicesImpacted)}</fieldset>` : raw('')}
<div><label for="internalReference">Internal reference (optional)</label><input type="text" id="internalReference" name="internalReference" value="${d.internalReference ?? ''}"></div>
<div><button type="submit">Save content</button></div></form>`
}

<h2>Reports</h2>
<ul>${STAGES.filter((s) => s !== 'intermediate-report').map(
    (s) =>
      html`<li>${STAGE_LABELS[s]}: <a href="/incidents/${inc.id}/report/${s}?format=html">view</a> · <a href="/incidents/${inc.id}/report/${s}?format=md">Markdown</a> · <a href="/incidents/${inc.id}/report/${s}?format=json">JSON</a>${
        inc.submissions.some((x) => x.stage === s) ? raw(' <span class="badge ok">submitted</span>') : raw('')
      }</li>`,
  )}${inc.intermediateRequests.map(
    (r) =>
      html`<li>Intermediate report ${r.id}: <a href="/incidents/${inc.id}/report/intermediate-report?format=html&amp;request=${r.id}">view</a> · <a href="/incidents/${inc.id}/report/intermediate-report?format=md&amp;request=${r.id}">Markdown</a>${
        r.submission === undefined ? raw('') : raw(' <span class="badge ok">submitted</span>')
      }</li>`,
  )}</ul>

${
  closed || inc.awareAt === undefined
    ? raw('')
    : html`<h3>Record a submission</h3>
<form class="stack" method="post" action="/incidents/${inc.id}/submit">${csrfField(ctx)}
${stageOptions('stage', next.length > 0 ? next : ['early-warning'])}
${
  inc.intermediateRequests.some((r) => r.submission === undefined)
    ? html`<div><label for="requestId">Request id (intermediate report only)</label><input type="text" id="requestId" name="requestId" value="${inc.intermediateRequests.find((r) => r.submission === undefined)?.id ?? ''}"></div>`
    : raw('')
}
${timeField('at', 'Submitted at', 'When the report was sent to the CSIRT or competent authority.')}
<div><label for="authorityReference">Authority reference (optional)</label><input type="text" id="authorityReference" name="authorityReference" maxlength="200"></div>
<div class="choices"><label><input type="checkbox" name="allowIncomplete" value="1"> Record even if prescribed elements are empty</label></div>
<div><button type="submit">Record submission</button></div></form>

<h3>Request for an intermediate report</h3>
<form class="stack" method="post" action="/incidents/${inc.id}/request">${csrfField(ctx)}
${timeField('at', 'Request received', 'Art 23(4)(c): on request of the CSIRT or competent authority.')}
<div><label for="requestedBy">Requested by (optional)</label><input type="text" id="requestedBy" name="requestedBy" maxlength="200"></div>
${timeField('dueAt', 'Due (optional)', 'Only if the request sets a date; the Directive sets none.')}
<div><button type="submit">Record request</button></div></form>
${inc.intermediateRequests
  .filter((r) => r.submission === undefined)
  .map(
    (r) => html`<form class="stack" method="post" action="/incidents/${inc.id}/status-update">${csrfField(ctx)}<input type="hidden" name="requestId" value="${r.id}">
${textArea('statusUpdate', `Status update for request ${r.id}`, r.statusUpdate, 'Relevant status updates (Art 23(4)(c)).')}
<div><button type="submit">Save status update</button></div></form>`,
  )}

<h3>Communication to recipients of services</h3>
<form class="stack" method="post" action="/incidents/${inc.id}/recipients">${csrfField(ctx)}
<fieldset><legend>Kind</legend><div class="choices"><label><input type="radio" name="kind" value="incident-23-1" checked> Significant incident (Art 23(1))</label><label><input type="radio" name="kind" value="cyber-threat-23-2"> Significant cyber threat (Art 23(2))</label></div></fieldset>
${timeField('at', 'Communicated at', '')}
<div><label for="audience">Audience</label><input type="text" id="audience" name="audience" maxlength="200"></div>
${textArea('summary', 'What was communicated', undefined)}
${textArea('measuresOrRemedies', 'Measures or remedies recipients can take', undefined, 'Art 23(2).')}
<div><button type="submit">Record communication</button></div></form>`
}
${
  inc.recipientCommunications.length === 0
    ? raw('')
    : html`<h3>Communications recorded</h3><ul>${inc.recipientCommunications.map((c) => html`<li>${c.id} · ${when(ctx, c.communicatedAt)} · ${c.audience}: ${c.summary}</li>`)}</ul>`
}`;
}

export function recurringPage(findings: readonly RecurringFinding[]): SafeHtml {
  return html`<h1>Recurring incidents</h1>
<p>Implementing Regulation (EU) 2024/2690, Article 4: incidents that individually are not significant count as one significant incident when they occurred at least twice within 6 months, have the same apparent root cause, and together meet Article 3(1)(a). Incidents are grouped by their root-cause label.</p>
${
  findings.length === 0
    ? raw('<p class="muted">No candidate groups.</p>')
    : html`<div class="table-wrap"><table><thead><tr><th scope="col">Root cause</th><th scope="col">Result</th><th scope="col">Incidents</th><th scope="col">Reason</th></tr></thead><tbody>${findings.map(
        (f) =>
          html`<tr><td data-label="Root cause">${f.rootCauseKey}</td><td data-label="Result">${
            f.status === 'met' ? raw('<span class="badge bad">Significant (collectively)</span>') : f.status === 'unknown' ? raw('<span class="badge warn">Undetermined</span>') : raw('<span class="badge">Not met</span>')
          }</td><td data-label="Incidents">${f.incidentIds.map((id, i) => html`${i === 0 ? '' : ', '}<a href="/incidents/${id}">${id}</a>`)}</td><td data-label="Reason">${f.reason}</td></tr>`,
      )}</tbody></table></div>`
}`;
}

export function auditPage(log: readonly AuditEntry[], check: ChainCheck): SafeHtml {
  return html`<h1>Audit log</h1>
<p>${check.ok ? html`<span class="badge ok">Chain intact</span> ${check.entries} entries. Head hash: <code>${check.head}</code>` : html`<span class="badge bad">Chain broken</span> at entry ${check.brokenAt ?? 0}: ${check.problem ?? ''}`}</p>
<div class="table-wrap"><table><thead><tr><th scope="col">#</th><th scope="col">Time (UTC)</th><th scope="col">Actor</th><th scope="col">Action</th><th scope="col">Target</th><th scope="col">Fields</th></tr></thead><tbody>${[...log]
    .reverse()
    .slice(0, 500)
    .map(
      (e) =>
        html`<tr><td data-label="#">${e.seq}</td><td data-label="Time (UTC)">${e.at}</td><td data-label="Actor">${e.actor}</td><td data-label="Action">${e.action}</td><td data-label="Target">${e.target ?? ''}</td><td data-label="Fields">${e.fields.join(', ')}${e.note === undefined ? '' : ` (${e.note})`}</td></tr>`,
    )}</tbody></table></div>`;
}

export function aboutPage(ctx: PageCtx): SafeHtml {
  return html`<h1>About Tocsin</h1>
<p><a href="${ATTRIBUTION.url}" rel="noopener noreferrer">${ATTRIBUTION.text}</a>. Copyright 2026 MB AFKzona Group. Licensed under the GNU Affero General Public License v3.0 only, with an additional attribution term under section 7(b) (LICENSE-ADDITIONAL-TERMS.md). The <a href="${SOURCE_URL}" rel="noopener noreferrer">source code</a> is available to every user of this interface.</p>
<p>Tocsin helps run significant-incident reporting under Article 23 of <a href="${SOURCES.NIS2.url}" rel="noopener noreferrer">Directive (EU) 2022/2555 (NIS2)</a> and the significance criteria of <a href="${SOURCES.IR2024_2690.url}" rel="noopener noreferrer">Implementing Regulation (EU) 2024/2690</a>. It does not make anyone compliant and is not legal advice. National rules, forms and portals differ; reports go to the recipient you configured: ${ctx.cfg.authority.name}.</p>
<p>Everything stays on this machine. The store is encrypted with AES-256-GCM. Nothing is sent anywhere unless you configure webhooks and run <code>tocsin notify</code>.</p>`;
}

export function loginPage(): SafeHtml {
  return html`<h1>Locked</h1><p>Open the link printed in the terminal where <code>tocsin ui</code> runs. The link works once; restart the UI to get a new one.</p>`;
}

export function errorPage(message: string): SafeHtml {
  return html`<h1>Something went wrong</h1><p>${message}</p><p><a href="/">Back to incidents</a></p>`;
}
