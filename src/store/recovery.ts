// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { timingSafeEqual } from 'node:crypto';
import { basename, dirname } from 'node:path';
import { appendAudit, assertAuditIntact } from '../audit/chain.js';
import { toIso } from '../time/zone.js';
import { TocsinError } from '../util/errors.js';
import { str } from '../util/validate.js';
import { DEFAULT_SCRYPT, assertPassphrase, type KeySource, type ScryptParams } from './crypto.js';
import { exists, fsyncDir, readFileCapped, safePath, withLock, writeFileAtomic, writeNewFile } from './fsutil.js';
import { MAX_STORE_BYTES, STORE_FORMAT, assertSameData, keyFor, newKdf, serialise, verifyStoreBuffer, type Kdf, type StoreData } from './store.js';

/**
 * Store maintenance: key rotation (`rekeyStore`) and restore from a verified export (`restoreStore`).
 *
 * Both follow the same pattern under the store lock: verify what is there or what comes in, build the new
 * file in memory, verify that text again with a key derived afresh from the secret, replace the store with
 * one atomic rename (temp file, fsync, rename, directory fsync), then read the file back and verify it.
 * The store path therefore always holds either the complete old file or the complete new file.
 */

/** Who and when, for the audit entry. */
export interface MaintenanceContext {
  readonly now: number;
  readonly actor: string;
}

function auditActor(actor: string): string {
  return str(actor, 'actor', { max: 100, min: 1 });
}

type SecretKind = 'raw key' | 'passphrase';

function describeKdf(kdf: Kdf): SecretKind {
  return kdf.name === 'raw' ? 'raw key' : 'passphrase';
}

function describeSource(s: KeySource): SecretKind {
  return s.kind === 'raw' ? 'raw key' : 'passphrase';
}

/** Compact UTC timestamp for backup file names: 20261108T193000123Z. */
export function backupStamp(now: number): string {
  return toIso(now).replace(/[-:.]/gu, '');
}

/** `<store>.<tag><stamp>.bak`, next to the store. */
function backupPath(storePath: string, now: number, tag = ''): string {
  return `${storePath}.${tag}${backupStamp(now)}.bak`;
}

/**
 * Copies `bytes` (the store as read under the lock) to `backup`: created exclusively (never overwrites,
 * never follows a planted link), mode 0600, fsynced, then the directory fsynced.
 */
async function keepBackup(backup: string, bytes: Uint8Array): Promise<string> {
  await writeNewFile(backup, bytes);
  await fsyncDir(dirname(backup));
  return backup;
}

/** Writes `text` atomically, then reads the file back and verifies it against `expected` with `source`. */
async function replaceAndVerify(p: string, text: string, source: KeySource, expected: StoreData): Promise<void> {
  await writeFileAtomic(p, text);
  const after = await verifyStoreBuffer(await readFileCapped(p, MAX_STORE_BYTES), source);
  assertSameData(after.data, expected, 'after writing');
}

/** Verifies `text` in memory before anything on disk changes. */
async function verifyBeforeWrite(text: string, source: KeySource, expected: StoreData): Promise<void> {
  const check = await verifyStoreBuffer(Buffer.from(text, 'utf8'), source);
  assertSameData(check.data, expected, 'before writing');
}

function sameBytes(x: Uint8Array, y: Uint8Array): boolean {
  return x.length === y.length && timingSafeEqual(x, y);
}

/** True when both sources are the same secret. Both are the operator's own input; the length check leaks nothing new. */
function sameSecret(a: KeySource, b: KeySource): boolean {
  if (a.kind === 'raw' && b.kind === 'raw') return sameBytes(a.key, b.key);
  if (a.kind === 'passphrase' && b.kind === 'passphrase') return sameBytes(Buffer.from(a.passphrase.normalize('NFC'), 'utf8'), Buffer.from(b.passphrase.normalize('NFC'), 'utf8'));
  return false;
}

// ---------- key rotation ----------

export interface RekeyOptions {
  /** scrypt parameters when the new secret is a passphrase. Defaults to {@link DEFAULT_SCRYPT}. */
  readonly scrypt?: ScryptParams;
}

export interface RekeyResult {
  readonly from: SecretKind;
  readonly to: SecretKind;
  readonly auditEntries: number;
  readonly auditHead: string;
}

/**
 * Re-encrypts the whole store under a new key or passphrase (raw to raw, passphrase to passphrase, or
 * mixed). The audit chain is kept and extended by one `store.rekeyed` entry that names only the kinds of
 * secret, never the secrets. A new passphrase must meet the usual rules; the new secret must differ from
 * the current one.
 *
 * Interrupted at any point, the store opens with exactly one of the two secrets: the old one until the
 * atomic rename, the new one after it. Backups and exports made earlier stay readable with their old keys.
 *
 * @example
 * ```ts
 * await rekeyStore('tocsin-store.tocsin', { kind: 'passphrase', passphrase: old }, { kind: 'raw', key }, { now: Date.now(), actor: 'ops' });
 * ```
 */
export async function rekeyStore(path: string, current: KeySource, next: KeySource, ctx: MaintenanceContext, opts: RekeyOptions = {}): Promise<RekeyResult> {
  const p = safePath(path, 'store');
  if (next.kind === 'passphrase') assertPassphrase(next.passphrase);
  if (sameSecret(current, next)) throw new TocsinError('VALIDATION', 'The new key or passphrase is the same as the current one.');
  const actor = auditActor(ctx.actor);
  return withLock(p, async () => {
    // 1. The whole store must verify with the current secret before anything changes.
    const before = await verifyStoreBuffer(await readFileCapped(p, MAX_STORE_BYTES), current);
    const note = `${describeKdf(before.file.kdf)} replaced by a new ${describeSource(next)}`;
    const data: StoreData = { ...before.data, audit: appendAudit(before.data.audit, { at: toIso(ctx.now), actor, action: 'store.rekeyed', fields: [], note }) };
    // 2. Every record sealed afresh under a key from a new salt.
    const kdf = newKdf(next, opts.scrypt ?? DEFAULT_SCRYPT);
    const key = await keyFor(next, kdf, STORE_FORMAT);
    let text: string;
    try {
      text = serialise(STORE_FORMAT, kdf, key, data, before.revision + 1).text;
    } finally {
      key.fill(0);
    }
    // 3. Verify in memory, 4. replace atomically, 5. verify on disk.
    await verifyBeforeWrite(text, next, data);
    await replaceAndVerify(p, text, next, data);
    const head = data.audit.at(-1);
    return { from: describeKdf(before.file.kdf), to: describeSource(next), auditEntries: data.audit.length, auditHead: head?.hash ?? '' };
  });
}

// ---------- restore ----------

export interface RestoreOptions {
  /** Replace an existing store. Without it, restoring onto an existing store is refused. */
  readonly replace?: boolean;
  /** scrypt parameters when the store secret is a passphrase. Defaults to {@link DEFAULT_SCRYPT}. */
  readonly scrypt?: ScryptParams;
}

export interface RestoreResult {
  readonly incidents: number;
  readonly auditEntries: number;
  readonly auditHead: string;
  /** Path of the `.bak` copy of the store that was replaced, if any. */
  readonly replacedBackup?: string;
}

/**
 * Writes verified data (from {@link readExportBundle}) as the store at `path`, encrypted under `source`.
 * The audit chain of the data is checked before anything on disk changes. An existing store is replaced
 * only with `replace: true`; it is then kept byte for byte as `<store>.<UTC time>.bak` (mode 0600), even
 * when it is damaged or encrypted under another key. One audit entry records the restore.
 */
export async function restoreStore(path: string, source: KeySource, data: StoreData, ctx: MaintenanceContext, opts: RestoreOptions = {}): Promise<RestoreResult> {
  const p = safePath(path, 'store');
  // Checked again on the sealed text before the rename; this first check fails fast, before the lock.
  assertAuditIntact(data.audit);
  const actor = auditActor(ctx.actor);
  return withLock(p, async () => {
    const present = await exists(p);
    if (present && opts.replace !== true) {
      throw new TocsinError('CONFLICT', 'A store already exists at that path. To replace it, pass --replace; the current file is then kept as a .bak copy.');
    }
    // Read the file being replaced first: a symlink, directory or oversized file is refused here.
    const old = present ? await readFileCapped(p, MAX_STORE_BYTES) : undefined;
    const n = data.incidents.length;
    const backupName = old === undefined ? undefined : backupPath(p, ctx.now);
    const note = backupName === undefined ? `${n} incident(s)` : `${n} incident(s); the replaced store was kept as ${basename(backupName)}`;
    const restored: StoreData = {
      ...data,
      audit: appendAudit(data.audit, { at: toIso(ctx.now), actor, action: old === undefined ? 'store.imported' : 'store.restored', fields: [], note: note.slice(0, 500) }),
    };
    const kdf = newKdf(source, opts.scrypt ?? DEFAULT_SCRYPT);
    const key = await keyFor(source, kdf, STORE_FORMAT);
    let text: string;
    try {
      text = serialise(STORE_FORMAT, kdf, key, restored, 1).text;
    } finally {
      key.fill(0);
    }
    await verifyBeforeWrite(text, source, restored);
    const replacedBackup = old === undefined || backupName === undefined ? undefined : await keepBackup(backupName, old);
    await replaceAndVerify(p, text, source, restored);
    const head = restored.audit.at(-1);
    return { incidents: n, auditEntries: restored.audit.length, auditHead: head?.hash ?? '', ...(replacedBackup === undefined ? {} : { replacedBackup }) };
  });
}

/** @internal Shared with the migration runner. */
export const maintenance = { backupPath, keepBackup, replaceAndVerify, verifyBeforeWrite, auditActor };
