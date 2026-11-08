// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Official sources. Every rule in this package points to one of these.
 * Texts were read on EUR-Lex on 8 November 2026 (see LEGAL.md).
 */
export const SOURCES = {
  NIS2: {
    title: 'Directive (EU) 2022/2555 (NIS 2 Directive)',
    celex: '32022L2555',
    url: 'https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32022L2555',
  },
  IR2024_2690: {
    title: 'Commission Implementing Regulation (EU) 2024/2690',
    celex: '32024R2690',
    url: 'https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R2690',
  },
  REG1182_71: {
    title: 'Regulation (EEC, Euratom) No 1182/71 (periods, dates and time limits)',
    celex: '31971R1182',
    url: 'https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:31971R1182',
  },
} as const;

export type SourceId = keyof typeof SOURCES;

/** A pointer to a provision of an official text. */
export interface LegalRef {
  readonly source: SourceId;
  /** Human-readable provision, e.g. "Article 23(4), point (a)". */
  readonly provision: string;
  readonly url: string;
}

/** Builds a {@link LegalRef}. */
export function ref(source: SourceId, provision: string): LegalRef {
  return { source, provision, url: SOURCES[source].url };
}

/** Formats a reference as "Directive (EU) 2022/2555, Article 23(4)". */
export function formatRef(r: LegalRef): string {
  const short = r.source === 'NIS2' ? 'NIS2' : r.source === 'IR2024_2690' ? 'IR 2024/2690' : 'Reg. 1182/71';
  return `${short} ${r.provision}`;
}
