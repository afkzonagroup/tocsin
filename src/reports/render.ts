// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { SOURCES, formatRef, type LegalRef, type SourceId } from '../legal/refs.js';
import { STAGES } from '../model/types.js';
import { canonicalJson } from '../util/canonical-json.js';
import { cspHash, escapeHtml, html, raw, type SafeHtml } from '../util/html.js';
import { arr, asRecord, oneOf, str } from '../util/validate.js';
import type { ReportContent, ReportElement, Requirement } from './content.js';

export const REPORT_FORMATS = ['md', 'json', 'html'] as const;
export type ReportFormat = (typeof REPORT_FORMATS)[number];

const REQUIREMENT_LABEL: Readonly<Record<Requirement, string>> = {
  required: 'Required',
  'where-applicable': 'Required where applicable',
  'where-available': 'Where available',
  optional: 'Optional',
};

// ---------- Markdown ----------

/**
 * Escapes user text for Markdown. HTML-significant characters become entities (so a Markdown viewer
 * that renders inline HTML shows them as text) and Markdown syntax characters are backslash-escaped.
 */
export function escapeMarkdown(text: string): string {
  return text
    .replace(/&/gu, '&amp;')
    .replace(/</gu, '&lt;')
    .replace(/>/gu, '&gt;')
    .replace(/[\\`*_{}[\]()#+!|~]/gu, (c) => `\\${c}`)
    .replace(/^(\s*)([-=])/gmu, '$1\\$2')
    .replace(/^(\s*\d+)\./gmu, '$1\\.');
}

function mdValue(v: string | readonly string[] | undefined): string {
  if (v === undefined) return '_Not provided._';
  if (typeof v === 'string') return v.split(/\r?\n/u).map(escapeMarkdown).join('  \n');
  return v.map((x) => `- ${escapeMarkdown(x)}`).join('\n');
}

function mdRef(r: LegalRef | undefined): string {
  return r === undefined ? '' : ` ([${escapeMarkdown(formatRef(r))}](${r.url}))`;
}

function mdElement(e: ReportElement): string {
  const lines = [`### ${escapeMarkdown(e.label)}`, '', `*${REQUIREMENT_LABEL[e.requirement]}*${mdRef(e.ref)}`, '', mdValue(e.value)];
  if (e.note !== undefined) lines.push('', `> ${escapeMarkdown(e.note)}`);
  return lines.join('\n');
}

/** Renders a report as Markdown. */
export function renderMarkdown(c: ReportContent): string {
  const parts = [
    `# ${escapeMarkdown(c.stageLabel)}: ${escapeMarkdown(c.title)}`,
    '',
    `Legal basis: [${escapeMarkdown(formatRef(c.legalBasis))}](${c.legalBasis.url}). Incident ${escapeMarkdown(c.incidentId)}. Generated ${escapeMarkdown(c.generatedAt)}; local times in ${escapeMarkdown(c.timeZone)}.`,
  ];
  if (c.missing.length > 0) parts.push('', `> **Draft.** Prescribed elements still empty: ${c.missing.map(escapeMarkdown).join(', ')}.`);
  parts.push('', '## Content prescribed by Article 23(4) NIS2', '', c.elements.map(mdElement).join('\n\n'));
  const optional = c.optional.filter((e) => e.value !== undefined);
  if (optional.length > 0) {
    parts.push('', '## Optional information', '', 'Not prescribed by Article 23(4). National forms usually ask for it.', '', optional.map(mdElement).join('\n\n'));
  }
  parts.push('', '---', '', `${escapeMarkdown(c.attribution.text)} — ${c.attribution.url}. Not legal advice; check the form your CSIRT or competent authority requires.`, '');
  return parts.join('\n');
}

// ---------- JSON ----------

/** Renders a report as pretty-printed JSON (stable key order). */
export function renderJson(c: ReportContent): string {
  return `${JSON.stringify(JSON.parse(canonicalJson(c)), null, 2)}\n`;
}

// ---------- HTML ----------

const REPORT_CSS = `
:root{color-scheme:light dark;--bg:#fff;--fg:#1a1a1a;--muted:#555;--line:#d0d0d0;--warn-bg:#fff4d6;--warn-fg:#5a4100}
@media (prefers-color-scheme:dark){:root{--bg:#141414;--fg:#ececec;--muted:#b0b0b0;--line:#3a3a3a;--warn-bg:#3a2f0b;--warn-fg:#ffe7a3}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:46rem;margin:0 auto;padding:2rem 1rem 3rem}
h1{font-size:1.6rem;line-height:1.25;margin:0 0 .5rem}
h2{font-size:1.15rem;margin:2rem 0 .75rem;padding-bottom:.25rem;border-bottom:1px solid var(--line)}
h3{font-size:1rem;margin:1.25rem 0 .25rem}
.meta,.req{color:var(--muted);font-size:.9rem}
.req{margin:0 0 .35rem}
.value{white-space:pre-wrap;overflow-wrap:anywhere;margin:0}
.empty{color:var(--muted);font-style:italic}
.draft{background:var(--warn-bg);color:var(--warn-fg);padding:.75rem 1rem;border-radius:6px}
.note{color:var(--muted);font-size:.9rem;margin:.35rem 0 0}
ul{margin:0;padding-left:1.25rem}
a{color:inherit}
footer{margin-top:3rem;padding-top:1rem;border-top:1px solid var(--line);color:var(--muted);font-size:.85rem}
@media print{body{background:#fff;color:#000}.draft{border:1px solid #000}}
`.trim();

/** The Content-Security-Policy embedded in HTML reports: nothing but the one hashed inline stylesheet. */
export const REPORT_CSP = `default-src 'none'; style-src ${cspHash(REPORT_CSS)}; img-src 'none'; base-uri 'none'; form-action 'none'`;

function htmlRef(r: LegalRef | undefined): SafeHtml {
  return r === undefined ? raw('') : html` — <a href="${r.url}" rel="noopener noreferrer">${formatRef(r)}</a>`;
}

function htmlValue(v: string | readonly string[] | undefined): SafeHtml {
  if (v === undefined) return raw('<p class="value empty">Not provided.</p>');
  if (typeof v === 'string') return html`<p class="value">${v}</p>`;
  return html`<ul>${v.map((x) => html`<li>${x}</li>`)}</ul>`;
}

function htmlElement(e: ReportElement): SafeHtml {
  return html`<section><h3>${e.label}</h3><p class="req">${REQUIREMENT_LABEL[e.requirement]}${htmlRef(e.ref)}</p>${htmlValue(e.value)}${
    e.note === undefined ? raw('') : html`<p class="note">${e.note}</p>`
  }</section>`;
}

/** Renders a self-contained HTML page. All user text is escaped; a CSP meta tag blocks scripts and remote loads. */
export function renderHtml(c: ReportContent): string {
  const optional = c.optional.filter((e) => e.value !== undefined);
  const page = html`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="${REPORT_CSP}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>${c.stageLabel}: ${c.title}</title>
<style>${raw(REPORT_CSS)}</style>
</head>
<body>
<main>
<h1>${c.stageLabel}: ${c.title}</h1>
<p class="meta">Legal basis: <a href="${c.legalBasis.url}" rel="noopener noreferrer">${formatRef(c.legalBasis)}</a>. Incident ${c.incidentId}. Generated ${c.generatedAt}; local times in ${c.timeZone}.</p>
${c.missing.length > 0 ? html`<p class="draft"><strong>Draft.</strong> Prescribed elements still empty: ${c.missing.join(', ')}.</p>` : raw('')}
<h2>Content prescribed by Article 23(4) NIS2</h2>
${c.elements.map(htmlElement)}
${
  optional.length > 0
    ? html`<h2>Optional information</h2><p class="meta">Not prescribed by Article 23(4). National forms usually ask for it.</p>${optional.map(htmlElement)}`
    : raw('')
}
<footer><a href="${c.attribution.url}" rel="noopener noreferrer">${c.attribution.text}</a>. Not legal advice; check the form your CSIRT or competent authority requires.</footer>
</main>
</body>
</html>
`;
  return page.value;
}

/** Renders in the requested format. */
export function renderReport(c: ReportContent, format: ReportFormat): string {
  switch (format) {
    case 'md':
      return renderMarkdown(c);
    case 'json':
      return renderJson(c);
    case 'html':
      return renderHtml(c);
  }
}

// ---------- snapshot validation ----------

const HTTPS_EURLEX = /^https:\/\/eur-lex\.europa\.eu\/[A-Za-z0-9/?=:._-]{1,200}$/u;

function validateRef(v: unknown): LegalRef {
  const o = asRecord(v, 'ref');
  const source = oneOf(o['source'], Object.keys(SOURCES) as SourceId[], 'ref.source');
  return { source, provision: str(o['provision'], 'ref.provision', { max: 200 }), url: str(o['url'], 'ref.url', { max: 260, pattern: HTTPS_EURLEX }) };
}

function validateElement(v: unknown): ReportElement {
  const o = asRecord(v, 'element');
  const value = o['value'];
  let parsed: string | readonly string[] | undefined;
  if (typeof value === 'string') parsed = str(value, 'element.value', { max: 20_000, multiline: true });
  else if (value !== undefined) parsed = arr(value, 'element.value', 500).map((x) => str(x, 'element.value[]', { max: 2000, multiline: true }));
  return {
    key: str(o['key'], 'element.key', { max: 64, pattern: /^[A-Za-z]+$/u }),
    label: str(o['label'], 'element.label', { max: 200 }),
    requirement: oneOf(o['requirement'], ['required', 'where-applicable', 'where-available', 'optional'] as const, 'element.requirement'),
    ...(o['ref'] === undefined ? {} : { ref: validateRef(o['ref']) }),
    ...(parsed === undefined ? {} : { value: parsed }),
    ...(o['note'] === undefined ? {} : { note: str(o['note'], 'element.note', { max: 1000 }) }),
  };
}

/** Validates a stored report snapshot before it is rendered again. */
export function validateReportContent(v: unknown): ReportContent {
  const o = asRecord(v, 'report');
  if (o['format'] !== 'tocsin-report' || o['formatVersion'] !== 1) throw new TypeError('Not a Tocsin report (format/version).');
  const a = asRecord(o['attribution'], 'attribution');
  return {
    format: 'tocsin-report',
    formatVersion: 1,
    stage: oneOf(o['stage'], STAGES, 'stage'),
    stageLabel: str(o['stageLabel'], 'stageLabel', { max: 60 }),
    legalBasis: validateRef(o['legalBasis']),
    incidentId: str(o['incidentId'], 'incidentId', { max: 16 }),
    title: str(o['title'], 'title', { max: 200 }),
    generatedAt: str(o['generatedAt'], 'generatedAt', { max: 30 }),
    timeZone: str(o['timeZone'], 'timeZone', { max: 64 }),
    ...(o['requestId'] === undefined ? {} : { requestId: str(o['requestId'], 'requestId', { max: 8 }) }),
    elements: arr(o['elements'], 'elements', 50).map(validateElement),
    optional: arr(o['optional'], 'optional', 50).map(validateElement),
    missing: arr(o['missing'], 'missing', 50).map((x) => str(x, 'missing', { max: 64 })),
    attribution: { text: str(a['text'], 'attribution.text', { max: 100 }), url: str(a['url'], 'attribution.url', { max: 200, pattern: /^https:\/\/[a-z0-9.-]+(\/[A-Za-z0-9/._-]*)?$/u }) },
  };
}

export { escapeHtml };
