// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { mkdir, readdir, readFile, stat, symlink, unlink as unlinkFile, utimes, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { appendAudit, verifyAudit, type AuditEntry } from '../src/audit/chain.js';
import { createIncident, initStore } from '../src/registry/ops.js';
import { constantTimeEqual, dataKey, open as openBox, parseRawKey, seal } from '../src/store/crypto.js';
import { canonicalJson, sha256Hex } from '../src/util/canonical-json.js';
import { readFileCapped, withLock, writeFileAtomic, writeNewFile } from '../src/store/fsutil.js';
import { createExportBundle, EncryptedStore, emptyData, readExportBundle, type StoreData } from '../src/store/store.js';
import { TocsinError } from '../src/util/errors.js';
import { FAST_SCRYPT, OTHER_KEY, RAW_KEY, tempDir } from './helpers.js';

const ctx = { now: Date.UTC(2026, 0, 10, 8), actor: 'tester' };

function seeded(): StoreData {
  const base = initStore(emptyData('2026-01-10T08:00:00.000Z'), ctx);
  return createIncident(base, { title: 'Seed incident', serviceTypes: ['cloud'] }, ctx).data;
}

let dir: string;
let cleanup: () => Promise<void>;
beforeEach(async () => {
  ({ dir, cleanup } = await tempDir());
});
afterEach(async () => {
  await cleanup();
});

async function expectCode(p: Promise<unknown>, code: string): Promise<void> {
  await expect(p).rejects.toSatisfy((e: unknown) => e instanceof TocsinError && e.code === code);
}

describe('crypto primitives', () => {
  const key = Buffer.alloc(32, 1);

  it('round-trips and uses a fresh nonce each time', () => {
    const a = seal(key, Buffer.from('hello'), 'aad');
    const b = seal(key, Buffer.from('hello'), 'aad');
    expect(a.n).not.toBe(b.n);
    expect(a.c).not.toBe(b.c);
    expect(openBox(key, a, 'aad').toString()).toBe('hello');
  });

  it('detects a flipped ciphertext bit, a changed tag, a changed nonce and wrong associated data', () => {
    const box = seal(key, Buffer.from('payload'), 'aad');
    const c = Buffer.from(box.c, 'base64');
    c[0] = (c[0] ?? 0) ^ 1;
    expect(() => openBox(key, { ...box, c: c.toString('base64') }, 'aad')).toThrow(/Wrong key/u);
    const t = Buffer.from(box.t, 'base64');
    t[3] = (t[3] ?? 0) ^ 0x80;
    expect(() => openBox(key, { ...box, t: t.toString('base64') }, 'aad')).toThrow(/Wrong key/u);
    const n = Buffer.from(box.n, 'base64');
    n[0] = (n[0] ?? 0) ^ 1;
    expect(() => openBox(key, { ...box, n: n.toString('base64') }, 'aad')).toThrow(/Wrong key/u);
    expect(() => openBox(key, box, 'other')).toThrow(/Wrong key/u);
    expect(() => openBox(Buffer.alloc(32, 2), box, 'aad')).toThrow(/Wrong key/u);
  });

  it('rejects truncated tags and malformed nonces', () => {
    const box = seal(key, Buffer.from('payload'), 'aad');
    expect(() => openBox(key, { ...box, t: Buffer.alloc(8).toString('base64') }, 'aad')).toThrow();
    expect(() => openBox(key, { ...box, n: '!!!' }, 'aad')).toThrow();
  });

  it('parses raw keys only as 32 bytes', () => {
    expect(parseRawKey('ab'.repeat(32))).toHaveLength(32);
    expect(parseRawKey(Buffer.alloc(32, 9).toString('base64'))).toHaveLength(32);
    expect(() => parseRawKey('ab'.repeat(31))).toThrow();
    expect(() => parseRawKey('not a key')).toThrow();
  });

  it('compares tokens in constant time and correctly', () => {
    expect(constantTimeEqual('abc', 'abc')).toBe(true);
    expect(constantTimeEqual('abc', 'abd')).toBe(false);
    expect(constantTimeEqual('abc', 'abcd')).toBe(false);
    expect(constantTimeEqual('', '')).toBe(true);
  });
});

describe('EncryptedStore', () => {
  it('creates, reopens and verifies; files are mode 0600 and contain no plaintext', async () => {
    const p = join(dir, 's.tocsin');
    const s = await EncryptedStore.create(p, RAW_KEY, seeded());
    s.close();
    const raw = await readFile(p, 'utf8');
    expect(raw).not.toContain('Seed incident');
    expect(raw).not.toContain('tester'); // actor names live in sealed audit records
    if (process.platform !== 'win32') expect((await stat(p)).mode & 0o777).toBe(0o600);
    const again = await EncryptedStore.open(p, RAW_KEY);
    expect(again.snapshot().incidents[0]?.title).toBe('Seed incident');
    expect(verifyAudit(again.snapshot().audit).ok).toBe(true);
  });

  it('passphrase stores use scrypt; a wrong passphrase fails', async () => {
    const p = join(dir, 'p.tocsin');
    (await EncryptedStore.create(p, { kind: 'passphrase', passphrase: 'a long enough passphrase' }, seeded(), { scrypt: FAST_SCRYPT })).close();
    const file = JSON.parse(await readFile(p, 'utf8')) as { kdf: { name: string; N: number } };
    expect(file.kdf).toMatchObject({ name: 'scrypt', N: FAST_SCRYPT.N });
    await expectCode(EncryptedStore.open(p, { kind: 'passphrase', passphrase: 'a long enough passphrasE' }), 'WRONG_KEY_OR_TAMPERED');
    await expectCode(EncryptedStore.open(p, RAW_KEY), 'WRONG_KEY_OR_TAMPERED');
    (await EncryptedStore.open(p, { kind: 'passphrase', passphrase: 'a long enough passphrase' })).close();
  });

  it('a wrong raw key fails', async () => {
    const p = join(dir, 's.tocsin');
    (await EncryptedStore.create(p, RAW_KEY, seeded())).close();
    await expectCode(EncryptedStore.open(p, OTHER_KEY), 'WRONG_KEY_OR_TAMPERED');
  });

  it('refuses to overwrite an existing store', async () => {
    const p = join(dir, 's.tocsin');
    (await EncryptedStore.create(p, RAW_KEY, seeded())).close();
    await expectCode(EncryptedStore.create(p, RAW_KEY, seeded()), 'CONFLICT');
  });

  describe('tamper detection', () => {
    let p: string;
    interface F { kdf: Record<string, unknown>; index: { n: string; c: string; t: string }; records: Record<string, { n: string; c: string; t: string }> }
    const load = async (): Promise<F> => JSON.parse(await readFile(p, 'utf8')) as F;
    const save = async (f: F): Promise<void> => writeFile(p, JSON.stringify(f));
    beforeEach(async () => {
      p = join(dir, 't.tocsin');
      let data = seeded();
      data = createIncident(data, { title: 'Second', serviceTypes: ['dns'] }, ctx).data;
      (await EncryptedStore.create(p, RAW_KEY, data)).close();
    });

    it('flipped byte in a record', async () => {
      const f = await load();
      const r = f.records['incident:INC-2026-0001'];
      if (r === undefined) throw new Error('missing');
      const c = Buffer.from(r.c, 'base64');
      c[5] = (c[5] ?? 0) ^ 0xff;
      r.c = c.toString('base64');
      await save(f);
      await expectCode(EncryptedStore.open(p, RAW_KEY), 'WRONG_KEY_OR_TAMPERED');
    });

    it('records swapped between ids', async () => {
      const f = await load();
      const a = f.records['incident:INC-2026-0001'];
      const b = f.records['incident:INC-2026-0002'];
      if (a === undefined || b === undefined) throw new Error('missing');
      f.records['incident:INC-2026-0001'] = b;
      f.records['incident:INC-2026-0002'] = a;
      await save(f);
      await expectCode(EncryptedStore.open(p, RAW_KEY), 'WRONG_KEY_OR_TAMPERED');
    });

    // An insider holding the key could also rewrite the sealed index; these tests do that, to show that
    // the per-record associated data and the audit-chain check hold on their own.
    const key = (): Buffer => dataKey((RAW_KEY as { key: Uint8Array }).key, Buffer.from(String((f0 as F).kdf['salt']), 'base64'), 'tocsin-store');
    let f0: F | undefined;
    const resealIndex = async (f: F): Promise<void> => {
      const records = Object.fromEntries(Object.entries(f.records).map(([id, b]) => [id, sha256Hex(`${b.n}.${b.c}.${b.t}`)]));
      f.index = seal(key(), Buffer.from(canonicalJson({ revision: 99, records }), 'utf8'), `tocsin-store/v1/index/${canonicalJson(f.kdf)}`);
      await save(f);
    };

    it('(helper check) an index re-sealed with the real key over unchanged records opens', async () => {
      const f = await load();
      f0 = f;
      await resealIndex(f);
      (await EncryptedStore.open(p, RAW_KEY)).close();
    });

    it('records swapped between ids are refused even with a matching index (record id is bound as associated data)', async () => {
      const f = await load();
      f0 = f;
      const a = f.records['incident:INC-2026-0001'];
      const b = f.records['incident:INC-2026-0002'];
      if (a === undefined || b === undefined) throw new Error('missing');
      f.records['incident:INC-2026-0001'] = b;
      f.records['incident:INC-2026-0002'] = a;
      await resealIndex(f);
      await expectCode(EncryptedStore.open(p, RAW_KEY), 'WRONG_KEY_OR_TAMPERED');
    });

    it('a re-sealed audit entry that breaks the hash chain is refused on open', async () => {
      const f = await load();
      f0 = f;
      const id = 'audit:1';
      const box = f.records[id];
      if (box === undefined) throw new Error('missing');
      const entry = JSON.parse(openBox(key(), box, `tocsin-store/v1/record/${id}`).toString('utf8')) as Record<string, unknown>;
      f.records[id] = seal(key(), Buffer.from(canonicalJson({ ...entry, actor: 'someone else' }), 'utf8'), `tocsin-store/v1/record/${id}`);
      await resealIndex(f);
      await expectCode(EncryptedStore.open(p, RAW_KEY), 'WRONG_KEY_OR_TAMPERED');
    });

    it('record deleted', async () => {
      const f = await load();
      delete f.records['incident:INC-2026-0002'];
      await save(f);
      await expectCode(EncryptedStore.open(p, RAW_KEY), 'WRONG_KEY_OR_TAMPERED');
    });

    it('record added', async () => {
      const f = await load();
      const a = f.records['incident:INC-2026-0001'];
      if (a === undefined) throw new Error('missing');
      f.records['incident:INC-2026-0003'] = a;
      await save(f);
      await expectCode(EncryptedStore.open(p, RAW_KEY), 'WRONG_KEY_OR_TAMPERED');
    });

    it('old copy of a record replayed after an update', async () => {
      const old = (await load()).records['incident:INC-2026-0001'];
      const s = await EncryptedStore.open(p, RAW_KEY);
      await s.transact((d) => ({ data: { ...d, incidents: d.incidents.map((i) => (i.id === 'INC-2026-0001' ? { ...i, title: 'Changed' } : i)) }, result: undefined }));
      s.close();
      const f = await load();
      if (old === undefined) throw new Error('missing');
      f.records['incident:INC-2026-0001'] = old;
      await save(f);
      await expectCode(EncryptedStore.open(p, RAW_KEY), 'WRONG_KEY_OR_TAMPERED');
    });

    it('KDF header changed', async () => {
      const f = await load();
      f.kdf = { ...f.kdf, salt: Buffer.alloc(16, 3).toString('base64') };
      await save(f);
      await expectCode(EncryptedStore.open(p, RAW_KEY), 'WRONG_KEY_OR_TAMPERED');
    });

    it('unsupported or abusive KDF parameters are refused before any work', async () => {
      const pp = join(dir, 'pp.tocsin');
      (await EncryptedStore.create(pp, { kind: 'passphrase', passphrase: 'a long enough passphrase' }, seeded(), { scrypt: FAST_SCRYPT })).close();
      const f = JSON.parse(await readFile(pp, 'utf8')) as { kdf: { N: number } };
      f.kdf.N = 2 ** 30;
      await writeFile(pp, JSON.stringify(f));
      await expectCode(EncryptedStore.open(pp, { kind: 'passphrase', passphrase: 'a long enough passphrase' }), 'STORE_FORMAT');
    });

    it('not JSON / wrong format / unknown fields', async () => {
      await writeFile(p, 'not json');
      await expectCode(EncryptedStore.open(p, RAW_KEY), 'STORE_FORMAT');
      await writeFile(p, JSON.stringify({ format: 'something-else', version: 1 }));
      await expectCode(EncryptedStore.open(p, RAW_KEY), 'STORE_FORMAT');
    });

    it('rollback of the whole file is detected by an open handle', async () => {
      const before = await readFile(p);
      const s = await EncryptedStore.open(p, RAW_KEY);
      await s.transact((d) => ({ data: d, result: undefined }));
      await writeFile(p, before);
      await expectCode(s.refresh(), 'WRONG_KEY_OR_TAMPERED');
      s.close();
    });
  });

  it('transactions re-read the file and keep unchanged ciphertexts', async () => {
    const p = join(dir, 's.tocsin');
    const a = await EncryptedStore.create(p, RAW_KEY, seeded());
    const before = JSON.parse(await readFile(p, 'utf8')) as { records: Record<string, unknown> };
    const b = await EncryptedStore.open(p, RAW_KEY);
    await b.transact((d) => createIncident(d, { title: 'From b', serviceTypes: ['cdn'] }, ctx));
    const r = await a.transact((d) => createIncident(d, { title: 'From a', serviceTypes: ['cdn'] }, ctx));
    expect(r.id).toBe('INC-2026-0003'); // a saw b's change
    const after = JSON.parse(await readFile(p, 'utf8')) as { records: Record<string, unknown> };
    expect(after.records['incident:INC-2026-0001']).toEqual(before.records['incident:INC-2026-0001']);
    a.close();
    b.close();
  });

  it('refuses a transaction result with a broken audit chain', async () => {
    const p = join(dir, 's.tocsin');
    const s = await EncryptedStore.create(p, RAW_KEY, seeded());
    await expect(s.transact((d) => ({ data: { ...d, audit: d.audit.slice(1) }, result: undefined }))).rejects.toThrow(/Audit log broken/u);
    s.close();
  });
});

describe('export / import', () => {
  it('round-trips under a separate key and verifies everything', async () => {
    const bundle = await createExportBundle(seeded(), OTHER_KEY);
    expect(bundle).not.toContain('Seed incident');
    const back = await readExportBundle(Buffer.from(bundle), OTHER_KEY);
    expect(back.incidents[0]?.title).toBe('Seed incident');
    await expectCode(readExportBundle(Buffer.from(bundle), RAW_KEY), 'WRONG_KEY_OR_TAMPERED');
  });

  it('an export is not accepted as a store and vice versa', async () => {
    const bundle = await createExportBundle(seeded(), RAW_KEY);
    const p = join(dir, 'x.tocsin');
    await writeFile(p, bundle);
    await expectCode(EncryptedStore.open(p, RAW_KEY), 'STORE_FORMAT');
    const sp = join(dir, 's.tocsin');
    (await EncryptedStore.create(sp, RAW_KEY, seeded())).close();
    await expectCode(readExportBundle(await readFile(sp), RAW_KEY), 'STORE_FORMAT');
  });

  it('a tampered export is rejected', async () => {
    const bundle = JSON.parse(await createExportBundle(seeded(), RAW_KEY, { scrypt: FAST_SCRYPT })) as { index: { c: string } };
    bundle.index.c = Buffer.from('tampered').toString('base64');
    await expectCode(readExportBundle(Buffer.from(JSON.stringify(bundle)), RAW_KEY), 'WRONG_KEY_OR_TAMPERED');
  });
});

describe('atomic and safe file writes', () => {
  it('writes atomically with mode 0600 and leaves no temp files', async () => {
    const p = join(dir, 'a.json');
    await writeFileAtomic(p, 'one');
    await writeFileAtomic(p, 'two');
    expect(await readFile(p, 'utf8')).toBe('two');
    expect((await readdir(dir)).filter((f) => f.includes('.tmp'))).toEqual([]);
    if (process.platform !== 'win32') expect((await stat(p)).mode & 0o777).toBe(0o600);
  });

  it('a failed replace keeps the old content and removes the temp file', async () => {
    const target = join(dir, 'target');
    await mkdir(target); // rename(file -> existing directory) fails
    await writeFile(join(target, 'keep'), 'old');
    await expectCode(writeFileAtomic(target, 'new'), 'IO');
    expect(await readFile(join(target, 'keep'), 'utf8')).toBe('old');
    expect((await readdir(dir)).filter((f) => f.includes('.tmp'))).toEqual([]);
  });

  it('writing into a missing directory fails cleanly', async () => {
    await expectCode(writeFileAtomic(join(dir, 'missing', 'x'), 'data'), 'IO');
  });

  it('writeNewFile never overwrites and never follows a symlink at the target', async () => {
    const p = join(dir, 'report.md');
    await writeNewFile(p, 'first');
    await expectCode(writeNewFile(p, 'second'), 'CONFLICT');
    expect(await readFile(p, 'utf8')).toBe('first');
    const victim = join(dir, 'victim');
    await writeFile(victim, 'safe');
    const link = join(dir, 'link.md');
    await symlink(victim, link);
    await expectCode(writeNewFile(link, 'pwned'), 'CONFLICT');
    expect(await readFile(victim, 'utf8')).toBe('safe');
  });

  it('readFileCapped refuses symlinks, directories and oversize files', async () => {
    const f = join(dir, 'f');
    await writeFile(f, 'x'.repeat(100));
    await expectCode(readFileCapped(f, 10), 'IO');
    await symlink(f, join(dir, 'l'));
    await expectCode(readFileCapped(join(dir, 'l'), 1000), 'IO');
    await expectCode(readFileCapped(dir, 1000), 'IO');
    await expectCode(readFileCapped(join(dir, 'nope'), 1000), 'NOT_FOUND');
  });

  it('the lock excludes a second writer and recovers a stale lock of a dead process', async () => {
    const t = join(dir, 'store');
    let inner: Promise<unknown> = Promise.resolve();
    await withLock(t, async () => {
      inner = withLock(t, () => Promise.resolve(1));
      await expectCode(inner, 'STORE_LOCKED');
    });
    await writeFile(`${t}.lock`, JSON.stringify({ pid: 2 ** 22 + 12345, at: 'x' }));
    const old = new Date(Date.now() - 10 * 60_000);
    await utimes(`${t}.lock`, old, old);
    await expect(withLock(t, () => Promise.resolve('ok'))).resolves.toBe('ok');
  });

  it('a fresh lock is not treated as stale', async () => {
    const t = join(dir, 'store');
    await writeFile(`${t}.lock`, JSON.stringify({ pid: 2 ** 22 + 12345 }));
    await expectCode(withLock(t, () => Promise.resolve('x')), 'STORE_LOCKED');
  });

  it('an old lock of a process that is still running is not stale', async () => {
    const t = join(dir, 'store');
    await writeFile(`${t}.lock`, JSON.stringify({ pid: process.pid, at: 'x' }));
    const old = new Date(Date.now() - 10 * 60_000);
    await utimes(`${t}.lock`, old, old);
    await expectCode(withLock(t, () => Promise.resolve('x')), 'STORE_LOCKED');
  });

  it('two writers recovering the same stale lock never both get it', async () => {
    const t = join(dir, 'store');
    for (let round = 0; round < 50; round++) {
      await writeFile(`${t}.lock`, JSON.stringify({ pid: 2 ** 22 + 12345, at: 'x' }));
      const old = new Date(Date.now() - 10 * 60_000);
      await utimes(`${t}.lock`, old, old);
      let inside = 0;
      let overlap = false;
      const body = async (): Promise<string> => {
        inside++;
        if (inside > 1) overlap = true;
        await new Promise((r) => setTimeout(r, 5));
        inside--;
        return 'ok';
      };
      const results = await Promise.allSettled([withLock(t, body), withLock(t, body), withLock(t, body)]);
      expect(overlap).toBe(false);
      expect(results.filter((r) => r.status === 'fulfilled').length).toBeGreaterThanOrEqual(1);
      expect((await readdir(dir)).filter((n) => n.includes('.lock'))).toEqual([]);
    }
  });

  it('only the holder of the recovery mutex may replace a stale lock', async () => {
    const t = join(dir, 'store');
    const stale = JSON.stringify({ pid: 2 ** 22 + 12345, at: 'x' });
    await writeFile(`${t}.lock`, stale);
    const old = new Date(Date.now() - 10 * 60_000);
    await utimes(`${t}.lock`, old, old);
    // Another process is recovering: we must leave the stale lock alone and report the store as locked.
    await writeFile(`${t}.lock.recover`, '');
    const err = await withLock(t, () => Promise.resolve('ok')).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(TocsinError);
    expect((err as TocsinError).code).toBe('STORE_LOCKED');
    expect((err as TocsinError).message).toContain('store.lock.recover');
    expect(await readFile(`${t}.lock`, 'utf8')).toBe(stale);
    // Once the mutex is gone, recovery succeeds and leaves neither file behind.
    await unlinkFile(`${t}.lock.recover`);
    expect(await withLock(t, () => Promise.resolve('ok'))).toBe('ok');
    expect((await readdir(dir)).filter((n) => n.includes('.lock'))).toEqual([]);
  });

  it('a stale lock that is a symlink is never recovered', async () => {
    const t = join(dir, 'store');
    const victim = join(dir, 'victim');
    await writeFile(victim, JSON.stringify({ pid: 2 ** 22 + 12345, at: 'x' }));
    const old = new Date(Date.now() - 10 * 60_000);
    await utimes(victim, old, old);
    await symlink(victim, `${t}.lock`);
    await expect(withLock(t, () => Promise.resolve('ok'))).rejects.toMatchObject({ code: 'STORE_LOCKED' });
    expect(await readFile(victim, 'utf8')).toContain('4206649');
  });

  it('a writer whose lock was taken over does not delete the new owner\'s lock', async () => {
    const t = join(dir, 'store');
    await withLock(t, async () => {
      // Simulate another process replacing our lock file (e.g. after a wrongful stale recovery).
      await unlinkFile(`${t}.lock`);
      await writeFile(`${t}.lock`, JSON.stringify({ pid: process.pid, at: 'other' }));
    });
    expect(await readFile(`${t}.lock`, 'utf8')).toContain('other');
  });
});

describe('audit chain', () => {
  const build = (): AuditEntry[] => {
    let log: AuditEntry[] = [];
    for (let i = 0; i < 4; i++) log = appendAudit(log, { at: '2026-01-01T00:00:00.000Z', actor: 'a', action: 'incident.updated', fields: [`f${i}`] });
    return log;
  };

  it('verifies an intact chain', () => {
    const r = verifyAudit(build());
    expect(r.ok).toBe(true);
    expect(r.entries).toBe(4);
  });

  it('detects a modified entry', () => {
    const log = build();
    log[1] = { ...(log[1] as AuditEntry), actor: 'mallory' };
    expect(verifyAudit(log)).toMatchObject({ ok: false, brokenAt: 2 });
  });

  it('detects a removed entry and reordering', () => {
    const log = build();
    expect(verifyAudit([log[0], log[2], log[3]] as AuditEntry[]).ok).toBe(false);
    expect(verifyAudit([log[1], log[0], log[2], log[3]] as AuditEntry[]).ok).toBe(false);
  });

  it('detects a recomputed hash that breaks the next link', () => {
    const log = build();
    const body = { ...(log[1] as AuditEntry), note: 'inserted' };
    const forged = appendAudit(log.slice(0, 1), { at: body.at, actor: body.actor, action: body.action, fields: body.fields, note: body.note });
    expect(verifyAudit([...forged, log[2] as AuditEntry, log[3] as AuditEntry]).ok).toBe(false);
  });
});
