// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { createHash } from 'node:crypto';

const HTML_ESCAPES: Readonly<Record<string, string>> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
  '`': '&#96;',
  '=': '&#61;',
};

/**
 * Escapes text for use in HTML element content and in double- or single-quoted attribute values.
 * Never use the result in unquoted attributes, URLs, `<script>` or `<style>`.
 */
export function escapeHtml(text: string): string {
  return text.replace(/[&<>"'`=]/gu, (c) => HTML_ESCAPES[c] ?? c);
}

/** Tagged template that escapes every interpolated value. Use {@link raw} to pass trusted markup. */
export function html(strings: TemplateStringsArray, ...values: readonly (string | number | SafeHtml | readonly SafeHtml[])[]): SafeHtml {
  let out = strings[0] ?? '';
  values.forEach((v, i) => {
    out += render(v) + (strings[i + 1] ?? '');
  });
  return new SafeHtml(out);
}

function render(v: string | number | SafeHtml | readonly SafeHtml[]): string {
  if (v instanceof SafeHtml) return v.value;
  if (typeof v === 'number') return escapeHtml(String(v));
  if (typeof v === 'string') return escapeHtml(v);
  return v.map((x) => x.value).join('');
}

/** Markup that is already safe. Only produced by {@link html} or {@link raw}. */
export class SafeHtml {
  readonly value: string;
  constructor(value: string) {
    this.value = value;
  }
  toString(): string {
    return this.value;
  }
}

/** Marks a compile-time constant string as markup. Never pass user data. */
export function raw(constant: string): SafeHtml {
  return new SafeHtml(constant);
}

/** CSP source expression ('sha256-…') for an inline style or script block. */
export function cspHash(content: string): string {
  return `'sha256-${createHash('sha256').update(content, 'utf8').digest('base64')}'`;
}
