// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

// Doctest for README.md: every ```ts block of the README is executed here with the same lines, and each
// `console.log(x); // expected` comment is checked against the logged value.

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { addCalendarMonths, assessSignificance, buildReport, computeDeadlines, parseInstant, renderReport, type Incident, type TocsinConfig } from '../src/index.js';

const README = readFileSync(new URL('../README.md', import.meta.url), 'utf8');
const SELF = readFileSync(new URL(import.meta.url), 'utf8');

function readmeBlocks(): string[] {
  return [...README.matchAll(/```ts\n([\s\S]*?)```/gu)].map((m) => m[1] ?? '');
}

/** Expected values from the `// …` comment after each console.log, in order. */
function expectations(block: string): unknown[] {
  return [...block.matchAll(/console\.log\(.*\);\s*\/\/\s*(.+)$/gmu)].map((m) => JSON.parse((m[1] ?? '').replace(/'/gu, '"')) as unknown);
}

function example1(): unknown[] {
  const logged: unknown[] = [];
  const console = { log: (v: unknown): void => void logged.push(v) };
  // --- README block 1 (imports are at the top of this file) ---
  const awareAt = parseInstant('2027-01-31T09:30', 'Europe/Brussels');
  console.log(addCalendarMonths(awareAt, 1, 'Europe/Brussels')); // '2027-02-28T08:30:00.000Z'

  const result = assessSignificance({
    serviceTypes: ['cloud'],
    answers: { services: { cloud: { completeUnavailabilitySeconds: 31 * 60 } } },
  });
  console.log(result.outcome); // 'significant'
  console.log(result.reasons[0]?.ref.provision); // 'Article 7, point (a)'
  // --- end ---
  return logged;
}

function example2(): unknown[] {
  const logged: unknown[] = [];
  const console = { log: (v: unknown): void => void logged.push(v) };
  // --- README block 2 ---
  const config: TocsinConfig = {
    version: 1,
    timeZone: 'Europe/Brussels',
    entity: { name: 'Example UAB' },
    authority: { role: 'csirt', name: 'National CSIRT' },
  };
  const incident: Incident = {
    id: 'INC-2026-0001',
    title: 'Storage cluster outage',
    createdAt: '2026-03-28T09:00:00.000Z',
    updatedAt: '2026-03-28T09:00:00.000Z',
    serviceTypes: ['cloud'],
    awareAt: '2026-03-28T10:00:00.000Z',
    details: { suspectedUnlawfulOrMalicious: 'no', crossBorderImpact: 'unknown' },
    submissions: [],
    intermediateRequests: [],
    recipientCommunications: [],
    linkedIncidentIds: [],
  };
  const due = computeDeadlines(incident, config.timeZone, Date.parse('2026-03-28T10:00:00.000Z'));
  console.log(due.map((d) => [d.kind, d.dueAt])[0]); // ['early-warning', '2026-03-29T10:00:00.000Z']
  const markdown = renderReport(buildReport(incident, 'early-warning', config, Date.now()), 'md');
  console.log(markdown.startsWith('# Early warning: Storage cluster outage')); // true
  // --- end ---
  return logged;
}

describe('README examples', () => {
  const blocks = readmeBlocks();

  it('has the two library examples', () => {
    expect(blocks).toHaveLength(2);
  });

  it('every README code line is executed here verbatim', () => {
    for (const block of blocks) {
      for (const line of block.split('\n').map((l) => l.trim())) {
        if (line === '' || line.startsWith('import ')) continue;
        expect(SELF, `README line not in examples.test.ts: ${line}`).toContain(line);
      }
    }
  });

  it('block 1 prints what the README says', () => {
    expect(example1()).toEqual(expectations(blocks[0] ?? ''));
  });

  it('block 2 prints what the README says', () => {
    expect(example2()).toEqual(expectations(blocks[1] ?? ''));
  });

  it('README imports only names the package exports', async () => {
    const api = (await import('../src/index.js')) as Record<string, unknown>;
    for (const block of blocks) {
      const names = /import \{([^}]+)\} from '@afkzona\/tocsin';/u.exec(block)?.[1] ?? '';
      for (const raw of names.split(',')) {
        const name = raw.trim();
        if (name === '' || name.startsWith('type ')) continue;
        expect(api[name], name).toBeDefined();
      }
    }
  });
});

describe('source hygiene', () => {
  function files(dir: string): string[] {
    return readdirSync(dir).flatMap((f) => {
      const p = join(dir, f);
      return statSync(p).isDirectory() ? files(p) : p.endsWith('.ts') || p.endsWith('.js') || p.endsWith('.md') ? [p] : [];
    });
  }
  const root = new URL('..', import.meta.url).pathname;
  const all = [...files(join(root, 'src')), ...files(join(root, 'test')), ...files(join(root, 'bin')), join(root, 'README.md')];

  it('no raw bidirectional-control or invisible characters (Trojan Source)', () => {
    for (const f of all) {
      const text = readFileSync(f, 'utf8');
      expect(/[\u202A-\u202E\u2066-\u2069\u200B-\u200F\u2028\u2029\uFEFF]/u.test(text), f).toBe(false);
    }
  });

  it('no eval, Function constructor, child processes or innerHTML in src', () => {
    for (const f of files(join(root, 'src'))) {
      const text = readFileSync(f, 'utf8');
      expect(/\beval\(|new Function\(|child_process|innerHTML|insertAdjacentHTML|document\.write/u.test(text), f).toBe(false);
    }
  });

  it('every source file carries the copyright and SPDX header', () => {
    for (const f of [...files(join(root, 'src')), ...files(join(root, 'test'))]) {
      const head = readFileSync(f, 'utf8').slice(0, 200);
      expect(head, f).toContain('Copyright 2026 MB AFKzona Group');
      expect(head, f).toContain('SPDX-License-Identifier: AGPL-3.0-only');
    }
  });
});
