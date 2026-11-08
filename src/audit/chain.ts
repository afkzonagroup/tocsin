// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { sha256Canonical } from '../util/canonical-json.js';
import { TocsinError } from '../util/errors.js';
import { arr, asRecord, nonNegInt, onlyKeys, str } from '../util/validate.js';

/**
 * Hash-chained audit log. Each entry commits to the previous entry's hash, so changing, removing or
 * reordering any entry breaks every later link. The log lives inside the encrypted store, so an attacker
 * without the key cannot rewrite it either. A party holding the key can rewrite the whole chain: write
 * down the head hash (`tocsin audit --verify`) if you need evidence against that.
 */

export const GENESIS_HASH = '0'.repeat(64);

export interface AuditEntry {
  readonly seq: number;
  readonly at: string;
  readonly actor: string;
  readonly action: string;
  readonly target?: string;
  /** Names of the fields that changed. Values are not repeated here; the state hash pins them. */
  readonly fields: readonly string[];
  /** SHA-256 of the canonical JSON of the target record after the change. */
  readonly stateSha256?: string;
  readonly note?: string;
  readonly prev: string;
  readonly hash: string;
}

export type AuditInput = Omit<AuditEntry, 'seq' | 'prev' | 'hash'>;

/** Hash of an entry: SHA-256 over the canonical JSON of every field except `hash`. */
export function entryHash(e: Omit<AuditEntry, 'hash'>): string {
  return sha256Canonical(e);
}

/** Appends an entry and returns the new log (input is not mutated). */
export function appendAudit(log: readonly AuditEntry[], input: AuditInput): AuditEntry[] {
  const last = log.at(-1);
  const body: Omit<AuditEntry, 'hash'> = { ...input, seq: (last?.seq ?? 0) + 1, prev: last?.hash ?? GENESIS_HASH };
  return [...log, { ...body, hash: entryHash(body) }];
}

export interface ChainCheck {
  readonly ok: boolean;
  readonly entries: number;
  readonly head: string;
  /** First broken sequence number, when not ok. */
  readonly brokenAt?: number;
  readonly problem?: string;
}

/** Verifies sequence numbers, links and hashes of the whole log. */
export function verifyAudit(log: readonly AuditEntry[]): ChainCheck {
  let prev = GENESIS_HASH;
  for (let i = 0; i < log.length; i++) {
    const e = log[i] as AuditEntry;
    const { hash, ...body } = e;
    if (e.seq !== i + 1) return { ok: false, entries: log.length, head: prev, brokenAt: i + 1, problem: 'sequence number out of order' };
    if (e.prev !== prev) return { ok: false, entries: log.length, head: prev, brokenAt: e.seq, problem: 'link to previous entry broken' };
    if (entryHash(body) !== hash) return { ok: false, entries: log.length, head: prev, brokenAt: e.seq, problem: 'entry content does not match its hash' };
    prev = hash;
  }
  return { ok: true, entries: log.length, head: prev };
}

const HEX64 = /^[0-9a-f]{64}$/u;

/** Structural validation of one stored entry. */
export function validateAuditEntry(v: unknown): AuditEntry {
  const o = asRecord(v, 'audit entry');
  onlyKeys(o, ['seq', 'at', 'actor', 'action', 'target', 'fields', 'stateSha256', 'note', 'prev', 'hash'], 'audit entry');
  const e: AuditEntry = {
    seq: nonNegInt(o['seq'], 'audit.seq'),
    at: str(o['at'], 'audit.at', { max: 24 }),
    actor: str(o['actor'], 'audit.actor', { max: 100 }),
    action: str(o['action'], 'audit.action', { max: 40, pattern: /^[a-z][a-z.-]*$/u }),
    fields: arr(o['fields'], 'audit.fields', 100).map((f) => str(f, 'audit.field', { max: 80 })),
    prev: str(o['prev'], 'audit.prev', { max: 64, pattern: HEX64 }),
    hash: str(o['hash'], 'audit.hash', { max: 64, pattern: HEX64 }),
    ...(o['target'] === undefined ? {} : { target: str(o['target'], 'audit.target', { max: 40 }) }),
    ...(o['stateSha256'] === undefined ? {} : { stateSha256: str(o['stateSha256'], 'audit.stateSha256', { max: 64, pattern: HEX64 }) }),
    ...(o['note'] === undefined ? {} : { note: str(o['note'], 'audit.note', { max: 500, multiline: true }) }),
  };
  return e;
}

/** Throws when the chain is broken. */
export function assertAuditIntact(log: readonly AuditEntry[]): void {
  const r = verifyAudit(log);
  if (!r.ok) throw new TocsinError('WRONG_KEY_OR_TAMPERED', `Audit log broken at entry ${r.brokenAt ?? '?'}: ${r.problem ?? 'unknown problem'}.`);
}
