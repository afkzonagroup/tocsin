// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { appendAudit } from '../audit/chain.js';
import { toIso } from '../time/zone.js';
import { TocsinError } from '../util/errors.js';
import { isRecord } from '../util/validate.js';
import type { KeySource } from './crypto.js';
import { readFileCapped, safePath, withLock } from './fsutil.js';
import { maintenance, type MaintenanceContext } from './recovery.js';
import {
  FORMAT_VERSION,
  MAX_STORE_BYTES,
  STORE_FORMAT,
  keyFor,
  parseKdf,
  readHeader,
  serialise,
  verifyStoreBuffer,
  type Kdf,
  type StoreData,
} from './store.js';

/**
 * Store format migrations.
 *
 * Every store file carries `"version"`. A release that changes the format raises {@link FORMAT_VERSION}
 * and adds one step to {@link STORE_MIGRATIONS} that turns a file of the previous version into the next.
 * `tocsin migrate` runs the steps in order under the store lock, verifies the result completely (every
 * record, the index and the audit chain), appends a `store.migrated` audit entry, keeps the original file
 * as `<store>.v<old>-<time>.bak`, and replaces the store atomically. A file newer than this release is
 * refused; it is never rewritten.
 */

/** Helpers a migration step may use to read the old file and to write the next version. */
export interface MigrationTools {
  /** Validates a key-derivation header (bounded scrypt cost). */
  readonly parseKdf: (raw: unknown) => Kdf;
  /** Derives the data key for that header. The caller must zero it after use. */
  readonly deriveKey: (source: KeySource, kdf: Kdf) => Promise<Buffer>;
  /** Builds a current-version file object from data the step has authenticated. */
  readonly encodeCurrent: (kdf: Kdf, key: Buffer, data: StoreData, revision: number) => Record<string, unknown>;
}

/** One migration step: authenticates a parsed file of version `from` and returns the file as version `to`. */
export interface MigrationStep {
  readonly from: number;
  readonly to: number;
  /** Short description for the audit entry (no data, no secrets). */
  readonly description: string;
  /**
   * Must authenticate the input with `source` before using it (a step that cannot verify its input must
   * throw). The runner verifies the final result completely before anything is written.
   */
  readonly run: (file: Readonly<Record<string, unknown>>, source: KeySource, tools: MigrationTools) => Promise<Record<string, unknown>>;
}

/**
 * Real migration steps, in order. Format version 1 is the first released format, so there are none yet.
 * The runner and its checks are exercised by tests with a test-only version 0.
 */
export const STORE_MIGRATIONS: readonly MigrationStep[] = [];

const TOOLS: MigrationTools = {
  parseKdf,
  deriveKey: (source, kdf) => keyFor(source, kdf, STORE_FORMAT),
  encodeCurrent: (kdf, key, data, revision) => JSON.parse(serialise(STORE_FORMAT, kdf, key, data, revision).text) as Record<string, unknown>,
};

/** Orders the steps from `from` to the current version. Throws when the path has a gap or is ambiguous. */
export function planMigration(from: number, steps: readonly MigrationStep[]): MigrationStep[] {
  for (const s of steps) {
    if (!Number.isSafeInteger(s.from) || !Number.isSafeInteger(s.to) || s.from < 0 || s.to <= s.from || s.to > FORMAT_VERSION) {
      throw new TocsinError('STORE_FORMAT', `Invalid migration step ${s.from} to ${s.to}.`);
    }
  }
  const plan: MigrationStep[] = [];
  let v = from;
  while (v < FORMAT_VERSION) {
    const candidates = steps.filter((s) => s.from === v);
    if (candidates.length !== 1) {
      throw new TocsinError('STORE_FORMAT', candidates.length === 0 ? `This Tocsin cannot upgrade a store from format version ${v}.` : `More than one migration from format version ${v}.`);
    }
    const step = candidates[0] as MigrationStep;
    plan.push(step);
    v = step.to;
  }
  return plan;
}

export interface MigrationResult {
  readonly from: number;
  readonly to: number;
  /** Descriptions of the steps that ran; empty when the store was already current. */
  readonly applied: readonly string[];
  /** The `.bak` copy of the original file, when a migration ran. */
  readonly backup?: string;
  readonly auditEntries: number;
  readonly auditHead: string;
}

/**
 * Upgrades the store at `path` to the current format version. A store that is already current is fully
 * verified and left untouched (not even rewritten).
 */
export async function migrateStore(path: string, source: KeySource, ctx: MaintenanceContext, steps: readonly MigrationStep[] = STORE_MIGRATIONS): Promise<MigrationResult> {
  const p = safePath(path, 'store');
  const actor = maintenance.auditActor(ctx.actor);
  return withLock(p, async () => {
    const original = await readFileCapped(p, MAX_STORE_BYTES);
    const header = readHeader(original, STORE_FORMAT);
    if (header.version === FORMAT_VERSION) {
      const current = await verifyStoreBuffer(original, source);
      return { from: header.version, to: header.version, applied: [], auditEntries: current.data.audit.length, auditHead: current.data.audit.at(-1)?.hash ?? '' };
    }
    const plan = planMigration(header.version, steps);
    let file: Record<string, unknown> = structuredClone(header.raw);
    for (const step of plan) {
      const out = await step.run(file, source, TOOLS);
      if (!isRecord(out) || out['format'] !== STORE_FORMAT || out['version'] !== step.to) {
        throw new TocsinError('STORE_FORMAT', `Migration ${step.from} to ${step.to} did not produce a version ${step.to} store.`);
      }
      file = out;
    }
    // The result must verify completely as a current store before anything is written.
    const migrated = await verifyStoreBuffer(Buffer.from(JSON.stringify(file), 'utf8'), source);
    const note = `format version ${header.version} to ${FORMAT_VERSION}: ${plan.map((s) => s.description).join('; ')}`.slice(0, 500);
    const data: StoreData = { ...migrated.data, audit: appendAudit(migrated.data.audit, { at: toIso(ctx.now), actor, action: 'store.migrated', fields: [], note }) };
    const key = await keyFor(source, migrated.file.kdf, STORE_FORMAT);
    let text: string;
    try {
      text = serialise(STORE_FORMAT, migrated.file.kdf, key, data, migrated.revision + 1, { plain: migrated.plain, boxes: migrated.file.records }).text;
    } finally {
      key.fill(0);
    }
    await maintenance.verifyBeforeWrite(text, source, data);
    const backup = await maintenance.keepBackup(maintenance.backupPath(p, ctx.now, `v${header.version}-`), original);
    await maintenance.replaceAndVerify(p, text, source, data);
    return { from: header.version, to: FORMAT_VERSION, applied: plan.map((s) => s.description), backup, auditEntries: data.audit.length, auditHead: data.audit.at(-1)?.hash ?? '' };
  });
}
