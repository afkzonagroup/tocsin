// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { chmod, mkdir, readdir, readFile, stat, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { verifyAudit, type AuditEntry } from '../src/audit/chain.js';
import { run } from '../src/cli/main.js';
import type { CliIo } from '../src/cli/io.js';
import { createIncident, initStore, logEvent } from '../src/registry/ops.js';
import type { KeySource } from '../src/store/crypto.js';
import { withLock } from '../src/store/fsutil.js';
import { migrateStore, planMigration, STORE_MIGRATIONS, type MigrationStep } from '../src/store/migrate.js';
import { rekeyStore, restoreStore } from '../src/store/recovery.js';
import { createExportBundle, EncryptedStore, emptyData, FORMAT_VERSION, keyFor, newKdf, readExportBundle, serialise, STORE_FORMAT, type StoreData } from '../src/store/store.js';
import { TocsinError } from '../src/util/errors.js';
import { FAST_SCRYPT, OTHER_KEY, RAW_KEY, tempDir } from './helpers.js';
import { V0_TO_V1, writeV0Store } from './migration-fixtures.js';

const ctx = { now: Date.UTC(2026, 0, 10, 8), actor: 'tester' };
const PASS_A_TEXT = 'first long passphrase';
const PASS_A: KeySource = { kind: 'passphrase', passphrase: PASS_A_TEXT };
const PASS_B: KeySource = { kind: 'passphrase', passphrase: 'second long passphrase' };
const RAW_HEX = 'ab'.repeat(32);

function seeded(n = 2): StoreData {
  let data = initStore(emptyData('2026-01-10T08:00:00.000Z'), ctx);
  for (let i = 0; i < n; i++) data = createIncident(data, { title: `Incident ${i + 1}`, serviceTypes: ['cloud'] }, ctx).data;
  return data;
}

let dir: string;
let cleanup: () => Promise<void>;
let store: string;
beforeEach(async () => {
  ({ dir, cleanup } = await tempDir());
  store = join(dir, 's.tocsin');
});
afterEach(async () => {
  await cleanup();
});

async function expectCode(p: Promise<unknown>, code: string, message?: RegExp): Promise<void> {
  const err = await p.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(err, `expected ${code}`).toBeInstanceOf(TocsinError);
  expect((err as TocsinError).code).toBe(code);
  if (message !== undefined) expect((err as TocsinError).message).toMatch(message);
}

async function create(source: KeySource, data: StoreData = seeded()): Promise<void> {
  (await EncryptedStore.create(store, source, data, { scrypt: FAST_SCRYPT })).close();
}

async function load(source: KeySource, path = store): Promise<StoreData> {
  const s = await EncryptedStore.open(path, source);
  try {
    return s.snapshot();
  } finally {
    s.close();
  }
}

async function bakFiles(): Promise<string[]> {
  return (await readdir(dir)).filter((n) => n.endsWith('.bak')).sort();
}

function lastEntry(d: StoreData): AuditEntry {
  const e = d.audit.at(-1);
  if (e === undefined) throw new Error('empty audit log');
  return e;
}

describe('rekey', () => {
  const combos: [string, KeySource, KeySource][] = [
    ['raw to raw', RAW_KEY, OTHER_KEY],
    ['passphrase to passphrase', PASS_A, PASS_B],
    ['raw to passphrase', RAW_KEY, PASS_A],
    ['passphrase to raw', PASS_A, RAW_KEY],
  ];

  for (const [name, from, to] of combos) {
    it(`${name}: the new secret opens the store, the old one does not, and the audit chain is kept`, async () => {
      await create(from);
      const before = await load(from);
      const r = await rekeyStore(store, from, to, { ...ctx, actor: 'rotator' }, { scrypt: FAST_SCRYPT });
      expect(r.from).toBe(from.kind === 'raw' ? 'raw key' : 'passphrase');
      expect(r.to).toBe(to.kind === 'raw' ? 'raw key' : 'passphrase');
      await expectCode(EncryptedStore.open(store, from), 'WRONG_KEY_OR_TAMPERED');
      const after = await load(to);
      expect(after.incidents).toEqual(before.incidents);
      expect(after.meta).toEqual(before.meta);
      expect(after.audit.slice(0, before.audit.length)).toEqual(before.audit); // every earlier entry unchanged
      expect(verifyAudit(after.audit)).toMatchObject({ ok: true, entries: before.audit.length + 1, head: r.auditHead });
      expect(lastEntry(after)).toMatchObject({ action: 'store.rekeyed', actor: 'rotator', fields: [] });
      if (process.platform !== 'win32') expect((await stat(store)).mode & 0o777).toBe(0o600);
      expect((await readdir(dir)).filter((n) => n !== 's.tocsin')).toEqual([]); // no temp, lock or backup left
    });
  }

  it('the audit entry names the kinds of secret only, never key material', async () => {
    await create(PASS_A);
    await rekeyStore(store, PASS_A, RAW_KEY, ctx);
    const e = lastEntry(await load(RAW_KEY));
    expect(e.note).toBe('passphrase replaced by a new raw key');
    const text = JSON.stringify(e);
    const raw = Buffer.from((RAW_KEY as { key: Uint8Array }).key);
    for (const secret of [PASS_A_TEXT, raw.toString('hex'), raw.toString('base64')]) expect(text).not.toContain(secret);
  });

  it('every record is sealed afresh: no ciphertext, nonce or salt survives', async () => {
    await create(RAW_KEY);
    const before = JSON.parse(await readFile(store, 'utf8')) as { kdf: { salt: string }; records: Record<string, { n: string }> };
    await rekeyStore(store, RAW_KEY, OTHER_KEY, ctx);
    const after = JSON.parse(await readFile(store, 'utf8')) as { kdf: { salt: string }; records: Record<string, { n: string }> };
    expect(after.kdf.salt).not.toBe(before.kdf.salt);
    for (const [id, box] of Object.entries(before.records)) expect(after.records[id]?.n).not.toBe(box.n);
  });

  it('refuses a weak new passphrase and the same secret again, before touching the file', async () => {
    await create(RAW_KEY);
    const bytes = await readFile(store);
    await expectCode(rekeyStore(store, RAW_KEY, { kind: 'passphrase', passphrase: 'too short' }, ctx), 'VALIDATION', /at least 12/u);
    await expectCode(rekeyStore(store, RAW_KEY, { kind: 'raw', key: Buffer.alloc(32, 7) }, ctx), 'VALIDATION', /same as the current/u);
    expect(await readFile(store)).toEqual(bytes);
    const p2 = join(dir, 'p.tocsin');
    (await EncryptedStore.create(p2, PASS_A, seeded(), { scrypt: FAST_SCRYPT })).close();
    // Same passphrase, also when typed in another Unicode normalisation form, is refused.
    await expectCode(rekeyStore(p2, PASS_A, { kind: 'passphrase', passphrase: 'first long passphrase' }, ctx), 'VALIDATION', /same as the current/u);
    const nfd = { kind: 'passphrase', passphrase: 'café long passphrase' } as const;
    const nfc = { kind: 'passphrase', passphrase: 'café long passphrase' } as const;
    const p3 = join(dir, 'u.tocsin');
    (await EncryptedStore.create(p3, nfc, seeded(), { scrypt: FAST_SCRYPT })).close();
    await expectCode(rekeyStore(p3, nfc, nfd, ctx), 'VALIDATION', /same as the current/u);
  });

  it('a wrong current secret changes nothing', async () => {
    await create(RAW_KEY);
    const bytes = await readFile(store);
    await expectCode(rekeyStore(store, OTHER_KEY, PASS_B, ctx), 'WRONG_KEY_OR_TAMPERED');
    expect(await readFile(store)).toEqual(bytes);
  });

  it('refuses a store whose audit chain is broken (verified before anything changes)', async () => {
    await create(RAW_KEY);
    // A legitimate transaction cannot break the chain, so rewrite the file through the internals with a broken log.
    const data = seeded();
    const broken: StoreData = { ...data, audit: data.audit.map((e, i) => (i === 1 ? { ...e, actor: 'mallory' } : e)) };
    const kdf = newKdf(RAW_KEY, FAST_SCRYPT);
    const key = await keyFor(RAW_KEY, kdf, STORE_FORMAT);
    await writeFile(store, serialise(STORE_FORMAT, kdf, key, broken, 5).text);
    const bytes = await readFile(store);
    await expectCode(rekeyStore(store, RAW_KEY, OTHER_KEY, ctx), 'WRONG_KEY_OR_TAMPERED', /Audit log broken/u);
    expect(await readFile(store)).toEqual(bytes);
  });

  it('runs under the store lock', async () => {
    await create(RAW_KEY);
    const bytes = await readFile(store);
    await withLock(store, async () => {
      await expectCode(rekeyStore(store, RAW_KEY, OTHER_KEY, ctx), 'STORE_LOCKED');
    });
    expect(await readFile(store)).toEqual(bytes);
  });

  it('an open handle on the old key fails closed after a rekey', async () => {
    await create(RAW_KEY);
    const s = await EncryptedStore.open(store, RAW_KEY);
    await rekeyStore(store, RAW_KEY, OTHER_KEY, ctx);
    await expectCode(s.transact((d) => ({ data: d, result: undefined })), 'WRONG_KEY_OR_TAMPERED', /key header/u);
    s.close();
  });

  it('can rotate repeatedly; each rotation adds one entry and the chain stays intact', async () => {
    await create(RAW_KEY);
    await rekeyStore(store, RAW_KEY, PASS_A, ctx, { scrypt: FAST_SCRYPT });
    await rekeyStore(store, PASS_A, PASS_B, ctx, { scrypt: FAST_SCRYPT });
    await rekeyStore(store, PASS_B, RAW_KEY, ctx);
    const d = await load(RAW_KEY);
    expect(d.audit.filter((e) => e.action === 'store.rekeyed')).toHaveLength(3);
    expect(verifyAudit(d.audit).ok).toBe(true);
  });
});

describe('backup and restore', () => {
  async function backupOf(source: KeySource): Promise<Buffer> {
    const s = await EncryptedStore.open(store, source);
    const data = await s.transact((d) => {
      const next = logEvent(d, 'export.created', ctx);
      return { data: next, result: next };
    });
    s.close();
    return Buffer.from(await createExportBundle(data, OTHER_KEY));
  }

  it('restore drill: back up, damage the store, restore with --replace, verify everything', async () => {
    await create(RAW_KEY, seeded(3));
    const bundle = await backupOf(RAW_KEY);
    const backedUp = await load(RAW_KEY);
    // Damage: the store file is truncated (for example by a full disk outside Tocsin's atomic writes).
    const full = await readFile(store);
    const damaged = full.subarray(0, Math.floor(full.length / 2));
    await writeFile(store, damaged);
    await expectCode(EncryptedStore.open(store, RAW_KEY), 'STORE_FORMAT', /truncated or damaged/u);

    const data = await readExportBundle(bundle, OTHER_KEY);
    const r = await restoreStore(store, RAW_KEY, data, { ...ctx, actor: 'restorer' }, { replace: true });
    const restored = await load(RAW_KEY);
    expect(restored.incidents).toEqual(backedUp.incidents);
    expect(restored.audit.slice(0, backedUp.audit.length)).toEqual(backedUp.audit);
    expect(verifyAudit(restored.audit)).toMatchObject({ ok: true, head: r.auditHead });
    expect(lastEntry(restored)).toMatchObject({ action: 'store.restored', actor: 'restorer' });
    expect(lastEntry(restored).note).toMatch(/3 incident\(s\); the replaced store was kept as s\.tocsin\.20260110T080000000Z\.bak/u);

    // The replaced (damaged) file is kept byte for byte, private.
    expect(await bakFiles()).toEqual(['s.tocsin.20260110T080000000Z.bak']);
    expect(r.replacedBackup).toBe(join(dir, 's.tocsin.20260110T080000000Z.bak'));
    const bak = join(dir, 's.tocsin.20260110T080000000Z.bak');
    expect(await readFile(bak)).toEqual(damaged);
    if (process.platform !== 'win32') expect((await stat(bak)).mode & 0o777).toBe(0o600);
  });

  it('restoring into a new path writes a store.imported entry and needs no flag', async () => {
    const data = await readExportBundle(Buffer.from(await createExportBundle(seeded(), OTHER_KEY)), OTHER_KEY);
    const r = await restoreStore(store, PASS_A, data, ctx, { scrypt: FAST_SCRYPT });
    expect(r.replacedBackup).toBeUndefined();
    expect(lastEntry(await load(PASS_A))).toMatchObject({ action: 'store.imported', note: '2 incident(s)' });
    expect(await bakFiles()).toEqual([]);
  });

  it('never overwrites an existing store without replace', async () => {
    await create(RAW_KEY);
    const bytes = await readFile(store);
    await expectCode(restoreStore(store, RAW_KEY, seeded(5), ctx), 'CONFLICT', /--replace/u);
    expect(await readFile(store)).toEqual(bytes);
    expect(await bakFiles()).toEqual([]);
  });

  it('verifies the audit chain of the data before replacing anything', async () => {
    await create(RAW_KEY);
    const bytes = await readFile(store);
    const data = seeded(3);
    const broken: StoreData = { ...data, audit: [data.audit[0] as AuditEntry, ...data.audit.slice(2)] };
    await expectCode(restoreStore(store, RAW_KEY, broken, ctx, { replace: true }), 'WRONG_KEY_OR_TAMPERED', /Audit log broken/u);
    // Checked first of all: even a locked store reports the broken data, not the lock.
    await withLock(store, async () => {
      await expectCode(restoreStore(store, RAW_KEY, broken, ctx, { replace: true }), 'WRONG_KEY_OR_TAMPERED', /Audit log broken/u);
    });
    expect(await readFile(store)).toEqual(bytes);
    expect(await bakFiles()).toEqual([]);
  });

  it('a tampered backup is rejected before the store is touched', async () => {
    await create(RAW_KEY);
    const bundle = JSON.parse((await backupOf(RAW_KEY)).toString('utf8')) as { records: Record<string, { c: string }> };
    const rec = bundle.records['incident:INC-2026-0001'];
    if (rec === undefined) throw new Error('missing');
    const c = Buffer.from(rec.c, 'base64');
    c[0] = (c[0] ?? 0) ^ 1;
    rec.c = c.toString('base64');
    await expectCode(readExportBundle(Buffer.from(JSON.stringify(bundle)), OTHER_KEY), 'WRONG_KEY_OR_TAMPERED');
  });

  it('runs under the store lock and refuses to replace a symlink or a directory', async () => {
    await create(RAW_KEY);
    const bytes = await readFile(store);
    await withLock(store, async () => {
      await expectCode(restoreStore(store, RAW_KEY, seeded(), ctx, { replace: true }), 'STORE_LOCKED');
    });
    expect(await readFile(store)).toEqual(bytes);

    const link = join(dir, 'link.tocsin');
    await symlink(store, link);
    await expectCode(restoreStore(link, OTHER_KEY, seeded(), ctx, { replace: true }), 'IO', /symbolic link/u);
    expect(await readFile(store)).toEqual(bytes);

    const d = join(dir, 'd.tocsin');
    await mkdir(d);
    await expectCode(restoreStore(d, OTHER_KEY, seeded(), ctx, { replace: true }), 'IO');
    expect(await bakFiles()).toEqual([]);
  });

  it('a second restore in the same millisecond does not overwrite the first .bak', async () => {
    await create(RAW_KEY);
    await restoreStore(store, RAW_KEY, seeded(1), ctx, { replace: true });
    await expectCode(restoreStore(store, RAW_KEY, seeded(2), ctx, { replace: true }), 'CONFLICT');
    expect(await bakFiles()).toHaveLength(1);
    expect((await load(RAW_KEY)).incidents).toHaveLength(1);
  });
});

describe('partial files', () => {
  it('a truncated store never opens with partial data, at any length', async () => {
    await create(RAW_KEY, seeded(3));
    const full = await readFile(store);
    const step = Math.max(1, Math.floor(full.length / 97));
    for (let len = 0; len < full.length - 1; len += step) {
      await writeFile(store, full.subarray(0, len));
      const err = await EncryptedStore.open(store, RAW_KEY).then(
        () => undefined,
        (e: unknown) => e,
      );
      expect(err, `length ${len}`).toBeInstanceOf(TocsinError);
      expect(['STORE_FORMAT', 'WRONG_KEY_OR_TAMPERED']).toContain((err as TocsinError).code);
    }
    // Only the trailing newline missing: the JSON is complete, and so is the store.
    await writeFile(store, full.subarray(0, full.length - 1));
    expect((await load(RAW_KEY)).incidents).toHaveLength(3);
  });

  it('a truncated temp file left by a crash is ignored, and later writes and a rekey succeed', async () => {
    await create(RAW_KEY);
    const full = await readFile(store);
    const tmp = join(dir, '.s.tocsin.0123456789abcdef.tmp');
    await writeFile(tmp, full.subarray(0, 100), { mode: 0o600 });
    const s = await EncryptedStore.open(store, RAW_KEY);
    await s.transact((d) => createIncident(d, { title: 'After crash', serviceTypes: ['dns'] }, ctx));
    s.close();
    await rekeyStore(store, RAW_KEY, OTHER_KEY, ctx);
    expect((await load(OTHER_KEY)).incidents.map((i) => i.title)).toContain('After crash');
    expect(await readFile(tmp)).toEqual(full.subarray(0, 100)); // never read, never replaced
  });
});

describe('format versions and migration', () => {
  it('refuses a newer format version with a clear message, for stores and exports', async () => {
    await create(RAW_KEY);
    const f = JSON.parse(await readFile(store, 'utf8')) as Record<string, unknown>;
    await writeFile(store, JSON.stringify({ ...f, version: FORMAT_VERSION + 1, somethingNew: true }));
    const bytes = await readFile(store);
    const newer = new RegExp(`format version ${FORMAT_VERSION + 1}, written by a newer Tocsin`, 'u');
    await expectCode(EncryptedStore.open(store, RAW_KEY), 'STORE_FORMAT', newer);
    await expectCode(migrateStore(store, RAW_KEY, ctx), 'STORE_FORMAT', newer);
    await expectCode(rekeyStore(store, RAW_KEY, OTHER_KEY, ctx), 'STORE_FORMAT', newer);
    expect(await readFile(store)).toEqual(bytes); // never rewritten
    const bundle = JSON.parse(await createExportBundle(seeded(), RAW_KEY)) as Record<string, unknown>;
    await expectCode(readExportBundle(Buffer.from(JSON.stringify({ ...bundle, version: 7 })), RAW_KEY), 'STORE_FORMAT', /format version 7, written by a newer Tocsin/u);
  });

  it('refuses malformed version fields as invalid structure', async () => {
    await create(RAW_KEY);
    const f = JSON.parse(await readFile(store, 'utf8')) as Record<string, unknown>;
    for (const version of ['1', 1.5, -1, 1e9, null]) {
      await writeFile(store, JSON.stringify({ ...f, version }));
      await expectCode(EncryptedStore.open(store, RAW_KEY), 'STORE_FORMAT', /structure is invalid/u);
    }
  });

  it('an older store is refused by normal commands with a pointer to "tocsin migrate"', async () => {
    await writeV0Store(store, RAW_KEY, seeded());
    await expectCode(EncryptedStore.open(store, RAW_KEY), 'STORE_FORMAT', /tocsin migrate/u);
    await expectCode(rekeyStore(store, RAW_KEY, OTHER_KEY, ctx), 'STORE_FORMAT', /tocsin migrate/u);
  });

  it('v1 to v1: migrating a current store verifies it and leaves the file untouched', async () => {
    await create(RAW_KEY);
    const bytes = await readFile(store);
    for (const steps of [STORE_MIGRATIONS, [V0_TO_V1]]) {
      const r = await migrateStore(store, RAW_KEY, ctx, steps);
      expect(r).toMatchObject({ from: FORMAT_VERSION, to: FORMAT_VERSION, applied: [] });
      expect(r.backup).toBeUndefined();
    }
    expect(await readFile(store)).toEqual(bytes);
    expect(await bakFiles()).toEqual([]);
    await expectCode(migrateStore(store, OTHER_KEY, ctx), 'WRONG_KEY_OR_TAMPERED'); // verification still runs
  });

  for (const source of [RAW_KEY, PASS_A]) {
    it(`v0 to v1 (${source.kind}): migrates, keeps the original as .bak, audits, and the chain verifies`, async () => {
      const data = seeded(3);
      await writeV0Store(store, source, data, 7);
      const original = await readFile(store);
      const r = await migrateStore(store, source, { ...ctx, actor: 'upgrader' }, [V0_TO_V1]);
      expect(r).toMatchObject({ from: 0, to: 1, applied: ['test-only: one sealed box to sealed records'] });
      const after = await load(source);
      expect(after.incidents).toEqual(data.incidents);
      expect(after.audit.slice(0, data.audit.length)).toEqual(data.audit);
      expect(verifyAudit(after.audit)).toMatchObject({ ok: true, entries: data.audit.length + 1, head: r.auditHead });
      expect(lastEntry(after)).toMatchObject({ action: 'store.migrated', actor: 'upgrader', note: 'format version 0 to 1: test-only: one sealed box to sealed records' });
      expect(JSON.parse(await readFile(store, 'utf8'))).toMatchObject({ version: 1 });
      expect(await bakFiles()).toEqual(['s.tocsin.v0-20260110T080000000Z.bak']);
      expect(r.backup).toBe(join(dir, 's.tocsin.v0-20260110T080000000Z.bak'));
      expect(await readFile(r.backup ?? '')).toEqual(original);
      if (process.platform !== 'win32') expect((await stat(r.backup ?? '')).mode & 0o777).toBe(0o600);
      // The revision continues from the old file (rollback detection keeps working).
      const s = await EncryptedStore.open(store, source);
      await s.transact((d) => ({ data: d, result: undefined }));
      s.close();
      // A second run is a no-op.
      expect((await migrateStore(store, source, ctx, [V0_TO_V1])).applied).toEqual([]);
    });
  }

  it('a tampered old file is refused by the step and nothing is written', async () => {
    await writeV0Store(store, RAW_KEY, seeded());
    const f = JSON.parse(await readFile(store, 'utf8')) as { data: { c: string } };
    const c = Buffer.from(f.data.c, 'base64');
    c[3] = (c[3] ?? 0) ^ 1;
    f.data.c = c.toString('base64');
    await writeFile(store, JSON.stringify(f));
    const bytes = await readFile(store);
    await expectCode(migrateStore(store, RAW_KEY, ctx, [V0_TO_V1]), 'WRONG_KEY_OR_TAMPERED');
    await expectCode(migrateStore(store, OTHER_KEY, ctx, [V0_TO_V1]), 'WRONG_KEY_OR_TAMPERED');
    expect(await readFile(store)).toEqual(bytes);
    expect(await bakFiles()).toEqual([]);
  });

  it('a step whose result does not verify (broken audit chain) is refused and nothing is written', async () => {
    const data = seeded(2);
    await writeV0Store(store, RAW_KEY, data);
    const bytes = await readFile(store);
    const lossy: MigrationStep = {
      ...V0_TO_V1,
      async run(file, source, tools) {
        const out = await V0_TO_V1.run(file, source, tools);
        const kdf = tools.parseKdf(out['kdf']);
        const key = await tools.deriveKey(source, kdf);
        // Drops the first audit entry: every record still decrypts, only the chain check can notice.
        const r = tools.encodeCurrent(kdf, key, { ...data, audit: data.audit.slice(1) }, 4);
        key.fill(0);
        return r;
      },
    };
    await expectCode(migrateStore(store, RAW_KEY, ctx, [lossy]), 'WRONG_KEY_OR_TAMPERED', /Audit log broken/u);
    expect(await readFile(store)).toEqual(bytes);
    expect(await bakFiles()).toEqual([]);
  });

  it('a step that returns the wrong version is refused', async () => {
    await writeV0Store(store, RAW_KEY, seeded());
    const wrong: MigrationStep = { ...V0_TO_V1, run: async (file) => Promise.resolve({ ...file, version: 0 }) };
    await expectCode(migrateStore(store, RAW_KEY, ctx, [wrong]), 'STORE_FORMAT', /did not produce a version 1 store/u);
  });

  it('plans steps in order and refuses gaps, duplicates and invalid steps', () => {
    const step = (from: number, to: number): MigrationStep => ({ ...V0_TO_V1, from, to, description: `${from}-${to}` });
    expect(planMigration(1, [])).toEqual([]);
    expect(planMigration(0, [step(0, 1)]).map((s) => s.description)).toEqual(['0-1']);
    expect(() => planMigration(0, [])).toThrow(/cannot upgrade a store from format version 0/u);
    expect(() => planMigration(0, [step(0, 1), step(0, 1)])).toThrow(/More than one/u);
    expect(() => planMigration(0, [step(1, 1)])).toThrow(/Invalid migration step/u);
    expect(() => planMigration(0, [step(0, FORMAT_VERSION + 1)])).toThrow(/Invalid migration step/u);
  });

  it('runs under the store lock', async () => {
    await writeV0Store(store, RAW_KEY, seeded());
    const bytes = await readFile(store);
    await withLock(store, async () => {
      await expectCode(migrateStore(store, RAW_KEY, ctx, [V0_TO_V1]), 'STORE_LOCKED');
    });
    expect(await readFile(store)).toEqual(bytes);
  });

  it('without a registered step, an older store cannot be migrated (and is not touched)', async () => {
    await writeV0Store(store, RAW_KEY, seeded());
    const bytes = await readFile(store);
    await expectCode(migrateStore(store, RAW_KEY, ctx), 'STORE_FORMAT', /cannot upgrade a store from format version 0/u);
    expect(await readFile(store)).toEqual(bytes);
  });
});

describe('CLI: rekey, import --replace, migrate', () => {
  let out = '';
  let err = '';
  async function cli(args: string[], env: Record<string, string> = {}): Promise<number> {
    out = '';
    err = '';
    const io: CliIo = {
      stdout: (s) => (out += s),
      stderr: (s) => (err += s),
      env: { TOCSIN_STORE: store, TOCSIN_CONFIG: join(dir, 'c.json'), TOCSIN_KEY: RAW_HEX, TOCSIN_ACTOR: 'tester', ...env },
      now: () => ctx.now,
      isTty: false,
    };
    return run(args, io);
  }

  beforeEach(async () => {
    expect(await cli(['init', '--timezone', 'Europe/Vilnius'])).toBe(0);
    expect(await cli(['create', '--title', 'Cloud outage', '--service', 'cloud'])).toBe(0);
  });

  it('rekey reads the new key from the environment, never echoes secrets, and the chain verifies', async () => {
    const NEW = 'cd'.repeat(32);
    expect(await cli(['rekey'], { TOCSIN_NEW_KEY: NEW }), err).toBe(0);
    expect(out).toMatch(/raw key replaced by a new raw key/u);
    expect(out + err).not.toContain(RAW_HEX);
    expect(out + err).not.toContain(NEW);
    expect(await cli(['list'])).toBe(1);
    expect(err).toMatch(/Wrong key/u);
    expect(await cli(['audit', '--verify', '--json'], { TOCSIN_KEY: NEW })).toBe(0);
    expect(JSON.parse(out)).toMatchObject({ ok: true });
    expect(await cli(['audit'], { TOCSIN_KEY: NEW })).toBe(0);
    expect(out).toMatch(/store\.rekeyed/u);
  });

  it('rekey to a passphrase from the environment, and back to a raw key from a 0600 key file', async () => {
    if (process.platform === 'win32') return;
    expect(await cli(['rekey'], { TOCSIN_NEW_PASSPHRASE: 'brand new long passphrase' }), err).toBe(0);
    expect(out).not.toContain('brand new long passphrase');
    const kf = join(dir, 'new.key');
    await writeFile(kf, `${'ef'.repeat(32)}\n`, { mode: 0o644 });
    await chmod(kf, 0o644);
    const env = { TOCSIN_KEY: '', TOCSIN_PASSPHRASE: 'brand new long passphrase' };
    expect(await cli(['rekey', '--new-key-file', kf], env)).toBe(1);
    expect(err).toMatch(/readable by other users/u);
    await chmod(kf, 0o600);
    expect(await cli(['rekey', '--new-key-file', kf], env), err).toBe(0);
    expect(out).toMatch(/passphrase replaced by a new raw key/u);
    expect(await cli(['show', 'INC-2026-0001'], { TOCSIN_KEY: 'ef'.repeat(32) })).toBe(0);
  });

  it('rekey refuses secrets on the command line, weak passphrases and a missing new key', async () => {
    const bytes = await readFile(store);
    expect(await cli(['rekey', '--new-key', 'cd'.repeat(32)])).toBe(2);
    expect(err).toMatch(/Unknown option/u);
    expect(await cli(['rekey', '--new-passphrase', 'x'.repeat(20)])).toBe(2);
    expect(await cli(['rekey'], { TOCSIN_NEW_PASSPHRASE: 'short' })).toBe(2);
    expect(err).toMatch(/at least 12/u);
    expect(await cli(['rekey'])).toBe(1);
    expect(err).toMatch(/TOCSIN_NEW_KEY or TOCSIN_NEW_PASSPHRASE/u);
    expect(await cli(['rekey'], { TOCSIN_NEW_KEY: RAW_HEX })).toBe(2);
    expect(err).toMatch(/same as the current/u);
    expect(await readFile(store)).toEqual(bytes);
  });

  it('import --replace restores a backup over a damaged store and keeps the damaged file', async () => {
    const bundle = join(dir, 'backup.tocsin-export');
    const exportEnv = { TOCSIN_EXPORT_KEY: '12'.repeat(32) };
    expect(await cli(['export', '--out', bundle], exportEnv), err).toBe(0);
    await writeFile(store, '{"format":"tocsin-store","vers');
    expect(await cli(['list'])).toBe(1);
    expect(err).toMatch(/truncated or damaged/u);

    expect(await cli(['import', '--in', bundle], exportEnv)).toBe(1);
    expect(err).toMatch(/pass --replace/u);
    expect(await readFile(store, 'utf8')).toBe('{"format":"tocsin-store","vers');

    expect(await cli(['import', '--in', bundle, '--replace'], exportEnv), err).toBe(0);
    expect(out).toMatch(/Restored 1 incident\(s\).*audit chain verified/u);
    expect(out).toMatch(/kept as .*s\.tocsin\.20260110T080000000Z\.bak/u);
    expect(await readFile(join(dir, 's.tocsin.20260110T080000000Z.bak'), 'utf8')).toBe('{"format":"tocsin-store","vers');
    expect(await cli(['audit', '--verify'])).toBe(0);
    expect(await cli(['show', 'INC-2026-0001'])).toBe(0);
    expect(out).toMatch(/Cloud outage/u);
  });

  it('import --replace with a tampered backup or the wrong export key changes nothing', async () => {
    const bundle = join(dir, 'backup.tocsin-export');
    const exportEnv = { TOCSIN_EXPORT_KEY: '12'.repeat(32) };
    expect(await cli(['export', '--out', bundle], exportEnv)).toBe(0);
    const bytes = await readFile(store);
    expect(await cli(['import', '--in', bundle, '--replace'], { TOCSIN_EXPORT_KEY: '13'.repeat(32) })).toBe(1);
    const b = JSON.parse(await readFile(bundle, 'utf8')) as { index: { t: string } };
    b.index.t = Buffer.alloc(16, 1).toString('base64');
    await writeFile(bundle, JSON.stringify(b));
    expect(await cli(['import', '--in', bundle, '--replace'], exportEnv)).toBe(1);
    expect(err).toMatch(/Wrong key/u);
    expect(await readFile(store)).toEqual(bytes);
    expect(await bakFiles()).toEqual([]);
  });

  it('migrate on a current store says so; on a newer one it refuses clearly', async () => {
    expect(await cli(['migrate'])).toBe(0);
    expect(out).toMatch(/already at format version 1; nothing to do/u);
    const f = JSON.parse(await readFile(store, 'utf8')) as Record<string, unknown>;
    await writeFile(store, JSON.stringify({ ...f, version: 2 }));
    expect(await cli(['migrate'])).toBe(1);
    expect(err).toMatch(/format version 2, written by a newer Tocsin\. This Tocsin reads format version 1 only/u);
  });
});
