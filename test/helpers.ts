// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { TocsinConfig } from '../src/model/config.js';
import type { Incident } from '../src/model/types.js';
import type { KeySource } from '../src/store/crypto.js';

export const CFG: TocsinConfig = {
  version: 1,
  timeZone: 'Europe/Vilnius',
  entity: { name: 'Example UAB', category: 'important', memberState: 'LT' },
  authority: { role: 'csirt', name: 'Example CSIRT' },
};

export function incident(over: Partial<Incident> = {}): Incident {
  return {
    id: 'INC-2026-0001',
    title: 'Test incident',
    createdAt: '2026-01-01T00:00:00.000Z',
    updatedAt: '2026-01-01T00:00:00.000Z',
    serviceTypes: ['cloud'],
    details: {},
    submissions: [],
    intermediateRequests: [],
    recipientCommunications: [],
    linkedIncidentIds: [],
    ...over,
  };
}

/** A fake submission entry (content not relevant for deadline tests). */
export function sub(stage: 'early-warning' | 'incident-notification' | 'progress-report' | 'final-report', submittedAt: string): Incident['submissions'][number] {
  return { stage, submittedAt, recordedAt: submittedAt, contentSha256: '0'.repeat(64), snapshot: {} };
}

export const RAW_KEY: KeySource = { kind: 'raw', key: Buffer.alloc(32, 7) };
export const OTHER_KEY: KeySource = { kind: 'raw', key: Buffer.alloc(32, 8) };
export const FAST_SCRYPT = { N: 2 ** 14, r: 8, p: 1 } as const;

export async function tempDir(): Promise<{ dir: string; cleanup: () => Promise<void> }> {
  const dir = await mkdtemp(join(tmpdir(), 'tocsin-test-'));
  return { dir, cleanup: () => rm(dir, { recursive: true, force: true }) };
}

export const MS = (iso: string): number => Date.parse(iso);
