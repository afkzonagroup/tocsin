// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { buildReport } from '../src/reports/content.js';
import { escapeMarkdown, REPORT_CSP, renderHtml, renderJson, renderMarkdown, validateReportContent } from '../src/reports/render.js';
import { escapeHtml, html, raw } from '../src/util/html.js';
import { CFG, incident } from './helpers.js';

const NOW = Date.UTC(2026, 0, 12);
const XSS = `<script>alert(1)</script><img src=x onerror="alert(2)"> ' " \` = & </textarea>`;

const full = incident({
  awareAt: '2026-01-10T08:00:00.000Z',
  title: `Title ${XSS}`,
  details: {
    suspectedUnlawfulOrMalicious: 'yes',
    suspectedUnlawfulOrMaliciousNote: XSS,
    crossBorderImpact: 'yes',
    crossBorderImpactDetails: 'Customers in LV',
    affectedMemberStates: ['LV', 'EE'],
    severity: 'High',
    impact: 'Service down for 2 hours',
    indicatorsOfCompromise: ['ip-dst: 203.0.113.9', `domain: evil.example ${XSS}`],
    description: 'Detailed',
    threatTypeOrRootCause: 'Ransomware',
    mitigationApplied: 'Restored from backup',
    mitigationOngoing: 'None',
    progressStatus: 'Recovery 80 %',
  },
  intermediateRequests: [{ id: 'R-1', requestedAt: '2026-01-11T08:00:00.000Z', statusUpdate: 'Containment done' }],
});

const keys = (stage: Parameters<typeof buildReport>[1], requestId?: string): string[] => buildReport(full, stage, CFG, NOW, requestId).elements.map((e) => e.key);

describe('report content per Article 23(4)', () => {
  it('early warning: suspected unlawful/malicious acts and cross-border impact (point (a))', () => {
    expect(keys('early-warning')).toEqual(['suspectedUnlawfulOrMalicious', 'crossBorderImpact']);
    const r = buildReport(full, 'early-warning', CFG, NOW);
    expect(r.elements.every((e) => e.requirement === 'where-applicable')).toBe(true);
    expect(r.legalBasis.provision).toBe('Article 23(4), point (a)');
  });

  it('incident notification: initial assessment (severity, impact), IoCs where available, update of (a) (point (b))', () => {
    expect(keys('incident-notification')).toEqual(['severity', 'impact', 'indicatorsOfCompromise', 'suspectedUnlawfulOrMalicious', 'crossBorderImpact']);
    const r = buildReport(full, 'incident-notification', CFG, NOW);
    expect(r.elements.find((e) => e.key === 'indicatorsOfCompromise')?.requirement).toBe('where-available');
  });

  it('intermediate report: relevant status updates (point (c))', () => {
    expect(keys('intermediate-report', 'R-1')).toEqual(['statusUpdate']);
    expect(() => buildReport(full, 'intermediate-report', CFG, NOW, 'R-9')).toThrow();
  });

  it('final report: (i) description, severity, impact; (ii) threat/root cause; (iii) applied and ongoing mitigation; (iv) cross-border impact', () => {
    const r = buildReport(full, 'final-report', CFG, NOW);
    expect(r.elements.map((e) => [e.key, e.ref?.provision])).toEqual([
      ['description', 'Article 23(4), point (d)(i)'],
      ['severity', 'Article 23(4), point (d)(i)'],
      ['impact', 'Article 23(4), point (d)(i)'],
      ['threatTypeOrRootCause', 'Article 23(4), point (d)(ii)'],
      ['mitigationApplied', 'Article 23(4), point (d)(iii)'],
      ['mitigationOngoing', 'Article 23(4), point (d)(iii)'],
      ['crossBorderImpact', 'Article 23(4), point (d)(iv)'],
    ]);
    expect(r.missing).toEqual([]);
  });

  it('progress report: content not prescribed; the tool asks for progress status and says so', () => {
    const r = buildReport(full, 'progress-report', CFG, NOW);
    expect(r.elements.map((e) => e.key)).toEqual(['progressStatus']);
    expect(r.elements[0]?.note).toMatch(/does not list its content/u);
    expect(r.optional.map((e) => e.key)).toContain('description');
  });

  it('every optional element is labelled optional and kept apart from the prescribed ones', () => {
    for (const stage of ['early-warning', 'incident-notification', 'progress-report', 'final-report'] as const) {
      const r = buildReport(full, stage, CFG, NOW);
      expect(r.optional.every((e) => e.requirement === 'optional')).toBe(true);
      expect(r.elements.some((e) => e.requirement === 'optional')).toBe(false);
    }
  });

  it('lists missing prescribed elements; "where available" may be empty', () => {
    const r = buildReport(incident({ awareAt: '2026-01-10T08:00:00.000Z' }), 'incident-notification', CFG, NOW);
    expect(r.missing).toEqual(['severity', 'impact', 'suspectedUnlawfulOrMalicious', 'crossBorderImpact']);
  });

  it('a stated "not yet determined" counts as a position for "where applicable" elements', () => {
    const r = buildReport(incident({ details: { suspectedUnlawfulOrMalicious: 'unknown', crossBorderImpact: 'no' } }), 'early-warning', CFG, NOW);
    expect(r.missing).toEqual([]);
    expect(r.elements[0]?.value).toBe('Not yet determined');
  });

  it('carries the attribution required by LICENSE-ADDITIONAL-TERMS.md', () => {
    const r = buildReport(full, 'early-warning', CFG, NOW);
    expect(r.attribution.text).toBe('Tocsin by AFKzona Group');
    expect(renderMarkdown(r)).toContain('Tocsin by AFKzona Group');
    expect(renderHtml(r)).toContain('Tocsin by AFKzona Group</a>');
  });
});

describe('HTML escaping', () => {
  it('escapes all special characters', () => {
    expect(escapeHtml(`<a href="x" onclick='y'>&\`=`)).toBe('&lt;a href&#61;&quot;x&quot; onclick&#61;&#39;y&#39;&gt;&amp;&#96;&#61;');
  });

  it('the html template escapes values and only passes SafeHtml through', () => {
    expect(html`<p title="${XSS}">${XSS}</p>`.value).not.toMatch(/<script|<img|onerror="/u);
    expect(html`<p>${raw('<b>ok</b>')}</p>`.value).toBe('<p><b>ok</b></p>');
  });

  it('rendered HTML reports contain no active content from user data', () => {
    for (const stage of ['early-warning', 'incident-notification', 'final-report'] as const) {
      const page = renderHtml(buildReport(full, stage, CFG, NOW));
      expect(page).not.toMatch(/<script/iu);
      expect(page).not.toMatch(/<img/iu);
      expect(page).not.toMatch(/onerror="/iu);
      expect(page).not.toContain('</textarea>');
      expect(page).toContain('&lt;script&gt;');
    }
  });

  it('the report CSP allows exactly the one inline stylesheet (hash matches)', () => {
    const page = renderHtml(buildReport(full, 'early-warning', CFG, NOW));
    const style = /<style>([\s\S]*?)<\/style>/u.exec(page)?.[1] ?? '';
    const hash = createHash('sha256').update(style, 'utf8').digest('base64');
    expect(REPORT_CSP).toContain(`'sha256-${hash}'`);
    expect(REPORT_CSP).toContain("default-src 'none'");
    expect(page).toContain('http-equiv="Content-Security-Policy"');
    expect(page.match(/<style>/gu)).toHaveLength(1);
  });
});

describe('Markdown and JSON', () => {
  it('escapes HTML and Markdown syntax in user text', () => {
    expect(escapeMarkdown('<b>x</b> [l](javascript:1) *e* # h')).toBe('&lt;b&gt;x&lt;/b&gt; \\[l\\]\\(javascript:1\\) \\*e\\* \\# h');
    expect(escapeMarkdown('- item\n1. one')).toBe('\\- item\n1\\. one');
    const md = renderMarkdown(buildReport(full, 'early-warning', CFG, NOW));
    expect(md).not.toMatch(/<script|<img/iu);
  });

  it('JSON is stable and round-trips through snapshot validation', () => {
    const r = buildReport(full, 'final-report', CFG, NOW);
    const text = renderJson(r);
    expect(validateReportContent(JSON.parse(text))).toEqual(JSON.parse(text));
  });

  it('snapshot validation rejects foreign or manipulated content', () => {
    const r = JSON.parse(renderJson(buildReport(full, 'final-report', CFG, NOW))) as Record<string, unknown>;
    expect(() => validateReportContent({ ...r, format: 'x' })).toThrow();
    expect(() => validateReportContent({ ...r, legalBasis: { source: 'NIS2', provision: 'x', url: 'javascript:alert(1)' } })).toThrow();
    expect(() => validateReportContent({ ...r, attribution: { text: 'x', url: 'http://evil' } })).toThrow();
  });
});
