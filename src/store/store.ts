// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { assertAuditIntact, validateAuditEntry, type AuditEntry } from '../audit/chain.js';
import { validateIncident } from '../model/validate.js';
import type { Incident } from '../model/types.js';
import { canonicalJson, sha256Hex } from '../util/canonical-json.js';
import { TocsinError } from '../util/errors.js';
import { arr, asRecord, isRecord, nonNegInt, onlyKeys, str } from '../util/validate.js';
import {
  DEFAULT_SCRYPT,
  assertScryptParams,
  dataKey,
  masterKey,
  open,
  randomSalt,
  seal,
  type Box,
  type KeySource,
  type ScryptParams,
} from './crypto.js';
import { exists, readFileCapped, safePath, withLock, writeFileAtomic } from './fsutil.js';

/**
 * Encrypted JSON store.
 *
 * File layout (version 1):
 * ```json
 * { "format": "tocsin-store", "version": 1, "cipher": "aes-256-gcm",
 *   "kdf": { "name": "scrypt", "salt": "…", "N": 131072, "r": 8, "p": 1 },
 *   "index": { "n": "…", "c": "…", "t": "…" },
 *   "records": { "incident:INC-2026-0001": { "n": "…", "c": "…", "t": "…" }, … } }
 * ```
 * Each record is sealed separately with its own random nonce; its id is bound as associated data, so
 * records cannot be swapped. The sealed index lists every record id with the SHA-256 of its box, so a
 * record cannot be removed, added, or replaced by an older copy of itself without detection. The index
 * also binds the KDF header. Rolling back the whole file to an older complete version cannot be detected
 * offline; see SECURITY.md.
 */

export const STORE_FORMAT = 'tocsin-store';
export const EXPORT_FORMAT = 'tocsin-export';
export const FORMAT_VERSION = 1;
/** Hard cap on file size read from disk. */
export const MAX_STORE_BYTES = 64 * 1024 * 1024;

export type FileFormat = typeof STORE_FORMAT | typeof EXPORT_FORMAT;

export interface StoreMeta {
  readonly createdAt: string;
  /** Next incident sequence number per year ("2026": 4). */
  readonly counters: Readonly<Record<string, number>>;
  /** Keys of webhook notifications already sent (dedupe), newest last, capped. */
  readonly notified: readonly string[];
}

export interface StoreData {
  readonly meta: StoreMeta;
  readonly incidents: readonly Incident[];
  readonly audit: readonly AuditEntry[];
}

/** @internal Key-derivation header of a file. */
export type Kdf = { readonly name: 'scrypt'; readonly salt: string; readonly N: number; readonly r: number; readonly p: number } | { readonly name: 'raw'; readonly salt: string };

/** @internal A parsed file of format version 1. */
export interface FileV1 {
  readonly format: FileFormat;
  readonly version: 1;
  readonly cipher: 'aes-256-gcm';
  readonly kdf: Kdf;
  readonly index: Box;
  readonly records: Readonly<Record<string, Box>>;
}

interface IndexV1 {
  readonly revision: number;
  readonly records: Readonly<Record<string, string>>; // id -> sha256(box)
}

const RECORD_ID = /^(?:incident:INC-\d{4}-\d{4,6}|audit:\d{1,9}|meta:main)$/u;
const MAX_NOTIFIED = 5000;

function boxHash(b: Box): string {
  return sha256Hex(`${b.n}.${b.c}.${b.t}`);
}

function recordAad(format: FileFormat, id: string): string {
  return `${format}/v${FORMAT_VERSION}/record/${id}`;
}

function indexAad(format: FileFormat, kdf: Kdf): string {
  return `${format}/v${FORMAT_VERSION}/index/${canonicalJson(kdf)}`;
}

function parseBox(v: unknown, what: string): Box {
  const o = asRecord(v, what);
  onlyKeys(o, ['n', 'c', 't'], what);
  return { n: str(o['n'], `${what}.n`, { max: 32 }), c: str(o['c'], `${what}.c`, { max: MAX_STORE_BYTES }), t: str(o['t'], `${what}.t`, { max: 32 }) };
}

/** Highest format version number accepted as a number at all (anything above is refused as corrupt). */
const MAX_VERSION_NUMBER = 10_000;

function formatLabel(format: FileFormat): string {
  return format === STORE_FORMAT ? 'store' : 'export';
}

/** @internal The top-level object of a file and its format version, before the version-specific checks. */
export interface FileHeader {
  readonly raw: Readonly<Record<string, unknown>>;
  readonly version: number;
}

/**
 * @internal Parses the JSON of a store or export file and reads its format version. Versions newer than
 * this release are refused with a message that says so; the caller decides what to do with older ones.
 */
export function readHeader(buf: Buffer, expected: FileFormat): FileHeader {
  let raw: unknown;
  try {
    raw = JSON.parse(buf.toString('utf8'));
  } catch {
    throw new TocsinError('STORE_FORMAT', 'The file is not valid JSON. It may be truncated or damaged; restore it from a backup (see "Backup and restore" in the README).');
  }
  if (!isRecord(raw)) throw new TocsinError('STORE_FORMAT', 'The file structure is invalid.');
  if (raw['format'] !== expected) throw new TocsinError('STORE_FORMAT', `Not a ${expected} file.`);
  const v = raw['version'];
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 0 || v > MAX_VERSION_NUMBER) throw new TocsinError('STORE_FORMAT', 'The file structure is invalid.');
  if (v > FORMAT_VERSION) {
    throw new TocsinError(
      'STORE_FORMAT',
      `This ${formatLabel(expected)} file uses format version ${v}, written by a newer Tocsin. This Tocsin reads format version ${FORMAT_VERSION} only. Upgrade Tocsin; do not edit the file.`,
    );
  }
  return { raw, version: v };
}

/** @internal Validates a key-derivation header (also bounds the scrypt cost before any work). */
export function parseKdf(v: unknown): Kdf {
  const k = asRecord(v, 'kdf');
  if (k['name'] === 'scrypt') {
    onlyKeys(k, ['name', 'salt', 'N', 'r', 'p'], 'kdf');
    const kdf: Kdf = { name: 'scrypt', salt: str(k['salt'], 'kdf.salt', { max: 64 }), N: nonNegInt(k['N'], 'kdf.N'), r: nonNegInt(k['r'], 'kdf.r'), p: nonNegInt(k['p'], 'kdf.p') };
    assertScryptParams(kdf);
    return kdf;
  }
  if (k['name'] === 'raw') {
    onlyKeys(k, ['name', 'salt'], 'kdf');
    return { name: 'raw', salt: str(k['salt'], 'kdf.salt', { max: 64 }) };
  }
  throw new TocsinError('STORE_FORMAT', 'Unsupported key derivation.');
}

/** @internal Parses a file of the current format version. Older versions are refused with a pointer to `tocsin migrate`. */
export function parseFile(buf: Buffer, expected: FileFormat): FileV1 {
  const { raw: o, version } = readHeader(buf, expected);
  if (version < FORMAT_VERSION) {
    throw new TocsinError(
      'STORE_FORMAT',
      expected === STORE_FORMAT
        ? `This store uses format version ${version}. Run "tocsin migrate" to upgrade it to version ${FORMAT_VERSION}; the original file is kept as a .bak copy.`
        : `This export uses format version ${version}. Import it with the Tocsin release that wrote it, migrate that store, and export again.`,
    );
  }
  try {
    onlyKeys(o, ['format', 'version', 'cipher', 'kdf', 'index', 'records'], 'file');
    if (o['cipher'] !== 'aes-256-gcm') throw new TocsinError('STORE_FORMAT', 'Unsupported cipher.');
    const kdf = parseKdf(o['kdf']);
    const recs = asRecord(o['records'], 'records');
    const records: Record<string, Box> = {};
    for (const [id, b] of Object.entries(recs)) {
      if (!RECORD_ID.test(id)) throw new TocsinError('WRONG_KEY_OR_TAMPERED', 'Unexpected record id in file.');
      records[id] = parseBox(b, 'record');
    }
    return { format: expected, version: 1, cipher: 'aes-256-gcm', kdf, index: parseBox(o['index'], 'index'), records };
  } catch (err) {
    if (err instanceof TocsinError && err.code !== 'VALIDATION') throw err;
    throw new TocsinError('STORE_FORMAT', 'The file structure is invalid.', { cause: err });
  }
}

function saltOf(kdf: Kdf): Buffer {
  const s = Buffer.from(kdf.salt, 'base64');
  if (s.length < 16) throw new TocsinError('STORE_FORMAT', 'Invalid salt.');
  return s;
}

function scryptOf(kdf: Kdf): ScryptParams | undefined {
  return kdf.name === 'scrypt' ? { N: kdf.N, r: kdf.r, p: kdf.p } : undefined;
}

function decodeJson(buf: Buffer): unknown {
  try {
    return JSON.parse(buf.toString('utf8'));
  } catch {
    throw new TocsinError('WRONG_KEY_OR_TAMPERED', 'A record does not decode.');
  }
}

function validateMeta(v: unknown): StoreMeta {
  const o = asRecord(v, 'meta');
  onlyKeys(o, ['createdAt', 'counters', 'notified'], 'meta');
  const c = asRecord(o['counters'], 'meta.counters');
  const counters: Record<string, number> = {};
  for (const [y, n] of Object.entries(c)) {
    if (!/^\d{4}$/u.test(y)) throw new TocsinError('STORE_FORMAT', 'Invalid counter.');
    counters[y] = nonNegInt(n, 'counter', 999_999);
  }
  return {
    createdAt: str(o['createdAt'], 'meta.createdAt', { max: 24 }),
    counters,
    notified: arr(o['notified'], 'meta.notified', MAX_NOTIFIED).map((x) => str(x, 'notified', { max: 200 })),
  };
}

/** @internal Decrypts and validates every record of a parsed file, and verifies the audit chain. */
export function decryptAll(file: FileV1, key: Buffer): { data: StoreData; revision: number; plain: Map<string, string> } {
  const idx = decodeJson(open(key, file.index, indexAad(file.format, file.kdf)));
  if (!isRecord(idx) || typeof idx['revision'] !== 'number' || !isRecord(idx['records'])) throw new TocsinError('WRONG_KEY_OR_TAMPERED', 'Index is malformed.');
  const index: IndexV1 = { revision: idx['revision'], records: idx['records'] as Record<string, string> };
  const listed = Object.keys(index.records).sort();
  const present = Object.keys(file.records).sort();
  if (listed.length !== present.length || listed.some((id, i) => id !== present[i])) {
    throw new TocsinError('WRONG_KEY_OR_TAMPERED', 'Records were added to or removed from the file.');
  }
  const plain = new Map<string, string>();
  let meta: StoreMeta | undefined;
  const incidents: Incident[] = [];
  const audit: AuditEntry[] = [];
  for (const id of present) {
    const box = file.records[id] as Box;
    if (index.records[id] !== boxHash(box)) throw new TocsinError('WRONG_KEY_OR_TAMPERED', 'A record was replaced.');
    const text = open(key, box, recordAad(file.format, id)).toString('utf8');
    plain.set(id, text);
    const value = decodeJson(Buffer.from(text, 'utf8'));
    try {
      if (id === 'meta:main') meta = validateMeta(value);
      else if (id.startsWith('incident:')) {
        const inc = validateIncident(value);
        if (`incident:${inc.id}` !== id) throw new TocsinError('WRONG_KEY_OR_TAMPERED', 'Record id mismatch.');
        incidents.push(inc);
      } else {
        const e = validateAuditEntry(value);
        if (`audit:${e.seq}` !== id) throw new TocsinError('WRONG_KEY_OR_TAMPERED', 'Record id mismatch.');
        audit.push(e);
      }
    } catch (err) {
      if (err instanceof TocsinError && err.code === 'WRONG_KEY_OR_TAMPERED') throw err;
      throw new TocsinError('STORE_FORMAT', `Record ${id} is invalid.`, { cause: err });
    }
  }
  if (meta === undefined) throw new TocsinError('WRONG_KEY_OR_TAMPERED', 'The store metadata record is missing.');
  audit.sort((a, b) => a.seq - b.seq);
  incidents.sort((a, b) => a.id.localeCompare(b.id));
  assertAuditIntact(audit);
  return { data: { meta, incidents, audit }, revision: index.revision, plain };
}

/** @internal Canonical plaintext of every record, by record id. */
export function recordsOf(data: StoreData): Map<string, string> {
  const m = new Map<string, string>();
  m.set('meta:main', canonicalJson({ ...data.meta, notified: data.meta.notified.slice(-MAX_NOTIFIED) }));
  for (const i of data.incidents) m.set(`incident:${i.id}`, canonicalJson(i));
  for (const e of data.audit) m.set(`audit:${e.seq}`, canonicalJson(e));
  for (const id of m.keys()) if (!RECORD_ID.test(id)) throw new TocsinError('VALIDATION', `Invalid record id ${id}.`);
  return m;
}

/** @internal Seals data into the text of a current-version file. */
export function serialise(format: FileFormat, kdf: Kdf, key: Buffer, data: StoreData, revision: number, previous?: { plain: Map<string, string>; boxes: Readonly<Record<string, Box>> }): { text: string; plain: Map<string, string>; boxes: Record<string, Box> } {
  const plain = recordsOf(data);
  const boxes: Record<string, Box> = {};
  const hashes: Record<string, string> = {};
  for (const [id, text] of plain) {
    const prevBox = previous?.boxes[id];
    // Unchanged records keep their ciphertext; changed ones get a fresh nonce.
    const box = prevBox !== undefined && previous?.plain.get(id) === text ? prevBox : seal(key, Buffer.from(text, 'utf8'), recordAad(format, id));
    boxes[id] = box;
    hashes[id] = boxHash(box);
  }
  const index: IndexV1 = { revision, records: hashes };
  const file: FileV1 = { format, version: 1, cipher: 'aes-256-gcm', kdf, index: seal(key, Buffer.from(canonicalJson(index), 'utf8'), indexAad(format, kdf)), records: boxes };
  return { text: `${JSON.stringify(file)}\n`, plain, boxes };
}

/** @internal Derives the data key of a file for a key source; refuses a source of the wrong kind. */
export async function keyFor(source: KeySource, kdf: Kdf, format: FileFormat): Promise<Buffer> {
  if (source.kind === 'raw' && kdf.name !== 'raw') throw new TocsinError('WRONG_KEY_OR_TAMPERED', 'This file is protected by a passphrase, not a raw key.');
  if (source.kind === 'passphrase' && kdf.name !== 'scrypt') throw new TocsinError('WRONG_KEY_OR_TAMPERED', 'This file is protected by a raw key, not a passphrase.');
  const salt = saltOf(kdf);
  const master = await masterKey(source, salt, scryptOf(kdf));
  try {
    return dataKey(master, salt, format);
  } finally {
    master.fill(0);
  }
}

/** @internal A fresh key-derivation header (new random salt) for a key source. */
export function newKdf(source: KeySource, scryptParams: ScryptParams): Kdf {
  const salt = randomSalt().toString('base64');
  return source.kind === 'raw' ? { name: 'raw', salt } : { name: 'scrypt', salt, ...scryptParams };
}

/** @internal A store file, read and fully verified. */
export interface VerifiedFile {
  readonly file: FileV1;
  readonly data: StoreData;
  readonly revision: number;
  readonly plain: Map<string, string>;
}

/**
 * @internal Parses, decrypts and verifies the text of a store file with a key derived afresh from `source`
 * (every record authenticated, the index complete, the audit chain intact).
 */
export async function verifyStoreBuffer(buf: Buffer, source: KeySource): Promise<VerifiedFile> {
  const file = parseFile(buf, STORE_FORMAT);
  const key = await keyFor(source, file.kdf, STORE_FORMAT);
  try {
    return { file, ...decryptAll(file, key) };
  } finally {
    key.fill(0);
  }
}

/** @internal Throws unless two data sets hold exactly the same records. */
export function assertSameData(actual: StoreData, expected: StoreData, when: string): void {
  const a = recordsOf(actual);
  const e = recordsOf(expected);
  if (a.size !== e.size || [...e].some(([id, text]) => a.get(id) !== text)) {
    throw new TocsinError('WRONG_KEY_OR_TAMPERED', `Verification ${when} failed: the store content differs from what was written.`);
  }
}

export function emptyData(now: string): StoreData {
  return { meta: { createdAt: now, counters: {}, notified: [] }, incidents: [], audit: [] };
}

export interface CreateOptions {
  /** scrypt parameters for passphrase stores. Defaults to {@link DEFAULT_SCRYPT}. */
  readonly scrypt?: ScryptParams;
}

/**
 * A handle on an encrypted store file. Every change runs as a transaction: take the lock, re-read and
 * verify the file, apply a pure update, write atomically, release the lock.
 */
export class EncryptedStore {
  readonly path: string;
  private readonly kdf: Kdf;
  private readonly key: Buffer;
  private data: StoreData;
  private revision: number;
  private plain: Map<string, string>;
  private boxes: Readonly<Record<string, Box>>;

  private constructor(path: string, kdf: Kdf, key: Buffer, loaded: { data: StoreData; revision: number; plain: Map<string, string>; boxes: Readonly<Record<string, Box>> }) {
    this.path = path;
    this.kdf = kdf;
    this.key = key;
    this.data = loaded.data;
    this.revision = loaded.revision;
    this.plain = loaded.plain;
    this.boxes = loaded.boxes;
  }

  /** Creates a new store. Fails if the file exists. */
  static async create(path: string, source: KeySource, initial: StoreData, opts: CreateOptions = {}): Promise<EncryptedStore> {
    const p = safePath(path, 'store');
    return withLock(p, async () => {
      if (await exists(p)) throw new TocsinError('CONFLICT', 'A store already exists at that path.');
      const kdf = newKdf(source, opts.scrypt ?? DEFAULT_SCRYPT);
      const key = await keyFor(source, kdf, STORE_FORMAT);
      assertAuditIntact(initial.audit);
      const out = serialise(STORE_FORMAT, kdf, key, initial, 1);
      await writeFileAtomic(p, out.text);
      return new EncryptedStore(p, kdf, key, { data: initial, revision: 1, plain: out.plain, boxes: out.boxes });
    });
  }

  /** Opens and fully verifies an existing store. */
  static async open(path: string, source: KeySource): Promise<EncryptedStore> {
    const p = safePath(path, 'store');
    const file = parseFile(await readFileCapped(p, MAX_STORE_BYTES), STORE_FORMAT);
    const key = await keyFor(source, file.kdf, STORE_FORMAT);
    const loaded = decryptAll(file, key);
    return new EncryptedStore(p, file.kdf, key, { ...loaded, boxes: file.records });
  }

  /** Current in-memory data (deep-frozen copy semantics: treat as read-only). */
  snapshot(): StoreData {
    return structuredClone(this.data);
  }

  /** Re-reads the file (to see changes made by another process). */
  async refresh(): Promise<StoreData> {
    const file = parseFile(await readFileCapped(this.path, MAX_STORE_BYTES), STORE_FORMAT);
    if (canonicalJson(file.kdf) !== canonicalJson(this.kdf)) throw new TocsinError('WRONG_KEY_OR_TAMPERED', 'The key header of the store changed.');
    const loaded = decryptAll(file, this.key);
    if (loaded.revision < this.revision) throw new TocsinError('WRONG_KEY_OR_TAMPERED', 'The store revision went backwards (possible rollback).');
    this.data = loaded.data;
    this.revision = loaded.revision;
    this.plain = loaded.plain;
    this.boxes = file.records;
    return this.snapshot();
  }

  /**
   * Runs `update` on the latest data under the lock and saves the result atomically.
   * `update` must be pure: it receives a copy and returns the new data plus a result value.
   */
  async transact<T>(update: (data: StoreData) => { data: StoreData; result: T }): Promise<T> {
    return withLock(this.path, async () => {
      const current = await this.refresh();
      const { data, result } = update(current);
      assertAuditIntact(data.audit);
      const rev = this.revision + 1;
      const out = serialise(STORE_FORMAT, this.kdf, this.key, data, rev, { plain: this.plain, boxes: this.boxes });
      await writeFileAtomic(this.path, out.text);
      this.data = data;
      this.revision = rev;
      this.plain = out.plain;
      this.boxes = out.boxes;
      return result;
    });
  }

  /** Clears the data key from memory. The handle cannot be used afterwards. */
  close(): void {
    this.key.fill(0);
  }
}

// ---------- export / import ----------

/**
 * Serialises all data into an encrypted export bundle, sealed under `exportKey` (a separate key or
 * passphrase you hand over with the file). Same format and checks as the store.
 */
export async function createExportBundle(data: StoreData, exportKey: KeySource, opts: CreateOptions = {}): Promise<string> {
  assertAuditIntact(data.audit);
  const kdf = newKdf(exportKey, opts.scrypt ?? DEFAULT_SCRYPT);
  const key = await keyFor(exportKey, kdf, EXPORT_FORMAT);
  try {
    return serialise(EXPORT_FORMAT, kdf, key, data, 1).text;
  } finally {
    key.fill(0);
  }
}

/** Decrypts and fully verifies an export bundle (every record authenticated, audit chain intact). */
export async function readExportBundle(content: Buffer, exportKey: KeySource): Promise<StoreData> {
  if (content.length > MAX_STORE_BYTES) throw new TocsinError('IO', 'Export file too large.');
  const file = parseFile(content, EXPORT_FORMAT);
  const key = await keyFor(exportKey, file.kdf, EXPORT_FORMAT);
  try {
    return decryptAll(file, key).data;
  } finally {
    key.fill(0);
  }
}
