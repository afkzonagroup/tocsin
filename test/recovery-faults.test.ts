// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * Fault injection for rekey, restore and migrate.
 *
 * `node:fs/promises` is wrapped so that every file-system call made by Tocsin is recorded with a label
 * (`<operation>:<file kind>#<n>`). One clean run of an operation gives its trace; then the operation is
 * repeated once per trace point with a simulated crash at that point: the call throws, and from then on
 * every file-system call fails, as for a process that died (no cleanup, no lock release). For each write a
 * second variant writes half the data first (a truncated file left behind). After each crash the files on
 * disk are inspected with the synchronous `node:fs` API, which is not wrapped.
 */

import { existsSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import type { FileHandle } from 'node:fs/promises';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { verifyAudit } from '../src/audit/chain.js';
import { createIncident, initStore } from '../src/registry/ops.js';
import type { KeySource } from '../src/store/crypto.js';
import { migrateStore } from '../src/store/migrate.js';
import { rekeyStore, restoreStore } from '../src/store/recovery.js';
import { EncryptedStore, emptyData, type StoreData } from '../src/store/store.js';
import { TocsinError } from '../src/util/errors.js';
import { FAST_SCRYPT, OTHER_KEY, RAW_KEY, tempDir } from './helpers.js';
import { V0_TO_V1, writeV0Store } from './migration-fixtures.js';

const fault = vi.hoisted(() => ({
  dir: '',
  store: '',
  tracing: false,
  trace: [] as string[],
  seen: new Map<string, number>(),
  /** Crash at this trace point; `partial` writes half the data of a writeFile first. */
  armed: undefined as { point: string; partial: boolean } | undefined,
  crashed: false,
  /** Corrupt the tag of the n-th sealed box (1-based, counted from `sealReset`); 0 = off. */
  corruptSeal: 0,
  seals: 0,
  /** Runs right after a successful rename onto the store path. */
  afterRename: undefined as undefined | (() => void),
}));

class Crash extends Error {}

function kindOf(path: unknown): string {
  const p = String(path);
  if (p === fault.store) return 'store';
  if (p === fault.dir) return 'dir';
  if (p.endsWith('.lock')) return 'lock';
  if (p.endsWith('.recover')) return 'recover';
  if (p.endsWith('.tmp')) return 'tmp';
  if (p.endsWith('.bak')) return 'bak';
  return 'other';
}

/** Records a call; returns true when this call is the armed crash point. */
function reach(label: string): { point: string; armed: boolean } {
  if (fault.crashed) throw new Crash('the process is dead');
  const n = (fault.seen.get(label) ?? 0) + 1;
  fault.seen.set(label, n);
  const point = `${label}#${n}`;
  if (fault.tracing) fault.trace.push(point);
  return { point, armed: fault.armed?.point === point };
}

function hit(label: string): void {
  const r = reach(label);
  if (r.armed) {
    fault.crashed = true;
    throw new Crash(`crash at ${r.point}`);
  }
}

vi.mock('node:fs/promises', async (importOriginal) => {
  const real = await importOriginal<typeof import('node:fs/promises')>();
  const HANDLE_OPS = new Set(['writeFile', 'sync', 'close', 'stat', 'readFile', 'read', 'write']);
  const wrapHandle = (fh: FileHandle, kind: string): FileHandle =>
    new Proxy(fh, {
      get(target, prop) {
        const v: unknown = Reflect.get(target, prop, target);
        if (typeof v !== 'function') return v;
        const fn = v as (...a: unknown[]) => Promise<unknown>;
        const name = String(prop);
        if (!HANDLE_OPS.has(name)) return fn.bind(target);
        return async (...args: unknown[]): Promise<unknown> => {
          if (name === 'close' && fault.crashed) {
            await fn.call(target).catch(() => undefined); // the OS closes a dead process's files
            throw new Crash('the process is dead');
          }
          const r = reach(`${name}:${kind}`);
          if (r.armed) {
            if (name === 'writeFile' && fault.armed?.partial === true) {
              const data = Buffer.from(args[0] as string | Uint8Array);
              await target.write(data.subarray(0, Math.floor(data.length / 2)));
            }
            if (name === 'close') await fn.call(target).catch(() => undefined);
            fault.crashed = true;
            throw new Crash(`crash at ${r.point}`);
          }
          return fn.apply(target, args);
        };
      },
    });
  return {
    ...real,
    open: async (path: Parameters<typeof real.open>[0], flags?: Parameters<typeof real.open>[1], mode?: Parameters<typeof real.open>[2]) => {
      const kind = kindOf(path);
      hit(`open:${kind}`);
      return wrapHandle(await real.open(path, flags, mode), kind);
    },
    rename: async (from: string, to: string) => {
      hit(`rename:${kindOf(from)}`);
      await real.rename(from, to);
      if (kindOf(to) === 'store') fault.afterRename?.();
    },
    chmod: async (path: string, mode: number) => {
      hit(`chmod:${kindOf(path)}`);
      return real.chmod(path, mode);
    },
    unlink: async (path: string) => {
      hit(`unlink:${kindOf(path)}`);
      return real.unlink(path);
    },
    lstat: async (path: string) => {
      hit(`lstat:${kindOf(path)}`);
      return real.lstat(path);
    },
    stat: async (path: string) => {
      hit(`stat:${kindOf(path)}`);
      return real.stat(path);
    },
  };
});

vi.mock('../src/store/crypto.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../src/store/crypto.js')>();
  return {
    ...real,
    seal: (key: Uint8Array, plaintext: Uint8Array, aad: string) => {
      const box = real.seal(key, plaintext, aad);
      fault.seals++;
      if (fault.corruptSeal === 0 || fault.seals !== fault.corruptSeal) return box;
      const t = Buffer.from(box.t, 'base64');
      t[0] = (t[0] ?? 0) ^ 1;
      return { ...box, t: t.toString('base64') };
    },
  };
});

const ctx = { now: Date.UTC(2026, 0, 10, 8), actor: 'tester' };
const PASS_A: KeySource = { kind: 'passphrase', passphrase: 'first long passphrase' };
const PASS_B: KeySource = { kind: 'passphrase', passphrase: 'second long passphrase' };

function seeded(n: number): StoreData {
  let data = initStore(emptyData('2026-01-10T08:00:00.000Z'), ctx);
  for (let i = 0; i < n; i++) data = createIncident(data, { title: `Incident ${i + 1}`, serviceTypes: ['cloud'] }, ctx).data;
  return data;
}

let dir: string;
let cleanup: () => Promise<void>;
beforeEach(async () => {
  ({ dir, cleanup } = await tempDir());
  fault.dir = dir;
  fault.store = join(dir, 's.tocsin');
  disarm();
});
afterEach(async () => {
  disarm();
  await cleanup();
});

function disarm(): void {
  fault.tracing = false;
  fault.trace = [];
  fault.seen = new Map();
  fault.armed = undefined;
  fault.crashed = false;
  fault.corruptSeal = 0;
  fault.seals = 0;
  fault.afterRename = undefined;
}

/** Empties the directory (synchronously, outside the wrapped API) for the next run. */
function resetDir(): void {
  for (const n of readdirSync(dir)) rmSync(join(dir, n), { recursive: true, force: true });
}

async function tryLoad(source: KeySource): Promise<StoreData | undefined> {
  try {
    const s = await EncryptedStore.open(fault.store, source);
    const d = s.snapshot();
    s.close();
    return d;
  } catch (e) {
    if (e instanceof TocsinError) return undefined;
    throw e;
  }
}

/** Runs `op` with tracing and returns the ordered trace points. */
async function traceOf(op: () => Promise<unknown>): Promise<string[]> {
  fault.seen = new Map();
  fault.trace = [];
  fault.tracing = true;
  await op();
  fault.tracing = false;
  return [...fault.trace];
}

/** Every crash variant for a trace: each point, plus a half-written variant of each writeFile. */
function crashPoints(trace: readonly string[]): { point: string; partial: boolean }[] {
  return trace.flatMap((point) => [{ point, partial: false }, ...(point.startsWith('writeFile:') ? [{ point, partial: true }] : [])]);
}

async function crashAt(point: { point: string; partial: boolean }, op: () => Promise<unknown>): Promise<void> {
  fault.seen = new Map();
  fault.armed = point;
  fault.crashed = false;
  await op().catch(() => undefined); // a crash may surface as an error, or be swallowed by best-effort cleanup
  fault.armed = undefined;
  fault.crashed = false;
}

/**
 * The point at which the new content reaches the store path. Crashes up to it must leave the old store.
 * (Without a rename, every point counts as "before"; the durability test checks that the rename exists.)
 */
function renameIndex(trace: readonly string[]): number {
  const i = trace.indexOf('rename:tmp#1');
  return i < 0 ? trace.length : i;
}

describe('rekey: interrupted at every step, exactly one key opens a complete, verifying store', () => {
  const combos: [string, KeySource, KeySource][] = [
    ['raw to raw', RAW_KEY, OTHER_KEY],
    ['passphrase to passphrase', PASS_A, PASS_B],
    ['raw to passphrase', RAW_KEY, PASS_A],
    ['passphrase to raw', PASS_A, RAW_KEY],
  ];

  for (const [name, from, to] of combos) {
    it(name, { timeout: 120_000 }, async () => {
      const data = seeded(2);
      (await EncryptedStore.create(fault.store, from, data, { scrypt: FAST_SCRYPT })).close();
      const initial = readFileSync(fault.store);
      const setup = (): Promise<void> => {
        resetDir();
        writeFileSync(fault.store, initial, { mode: 0o600 });
        return Promise.resolve();
      };
      const op = (): Promise<unknown> => rekeyStore(fault.store, from, to, ctx, { scrypt: FAST_SCRYPT });
      await setup();
      const trace = await traceOf(op);
      const renameAt = renameIndex(trace);
      const points = crashPoints(trace);
      expect(points.length).toBeGreaterThan(20);
      const results: string[] = [];
      for (const point of points) {
        await setup();
        await crashAt(point, op);
        const oldData = await tryLoad(from);
        const newData = await tryLoad(to);
        const label = `${point.point}${point.partial ? ' (half written)' : ''}`;
        expect(oldData === undefined, `${label}: exactly one key opens`).not.toBe(newData === undefined);
        const expectNew = trace.indexOf(point.point) > renameAt;
        const opened = (expectNew ? newData : oldData) as StoreData;
        expect(opened, `${label}: ${expectNew ? 'new' : 'old'} key opens`).toBeDefined();
        expect(verifyAudit(opened.audit).ok, `${label}: chain`).toBe(true);
        expect(opened.incidents).toEqual(data.incidents);
        expect(opened.audit.slice(0, data.audit.length)).toEqual(data.audit);
        expect(opened.audit.length).toBe(data.audit.length + (expectNew ? 1 : 0));
        results.push(`${label}: ${expectNew ? 'new' : 'old'}`);

        // Recovery: remove the dead process's lock (as the error message says), then finish the rotation.
        rmSync(`${fault.store}.lock`, { force: true });
        if (!expectNew) await op();
        const final = await tryLoad(to);
        expect(final, `${label}: rotation completes after recovery`).toBeDefined();
        expect(verifyAudit((final as StoreData).audit).ok).toBe(true);
        expect((final as StoreData).audit.filter((e) => e.action === 'store.rekeyed')).toHaveLength(1);
      }
      // Both outcomes occur: crashes before the rename keep the old key, crashes after it the new one.
      expect(results.some((r) => r.endsWith(': old'))).toBe(true);
      expect(results.some((r) => r.endsWith(': new'))).toBe(true);
    });
  }

  it('a crash after the temp file is complete leaves a stray temp file that only the new key opens, and the old key the store', async () => {
    (await EncryptedStore.create(fault.store, RAW_KEY, seeded(1))).close();
    await crashAt({ point: 'chmod:tmp#1', partial: false }, () => rekeyStore(fault.store, RAW_KEY, OTHER_KEY, ctx));
    const tmp = readdirSync(dir).filter((n) => n.endsWith('.tmp'));
    expect(tmp).toHaveLength(1);
    expect(await tryLoad(RAW_KEY)).toBeDefined();
    expect(existsSync(`${fault.store}.lock`)).toBe(true); // a dead process leaves its lock
  });

  it('a crash in the middle of writing the temp file leaves a truncated temp file and an intact store', async () => {
    (await EncryptedStore.create(fault.store, RAW_KEY, seeded(1))).close();
    const before = readFileSync(fault.store);
    await crashAt({ point: 'writeFile:tmp#1', partial: true }, () => rekeyStore(fault.store, RAW_KEY, OTHER_KEY, ctx));
    const tmp = readdirSync(dir).filter((n) => n.endsWith('.tmp'));
    expect(tmp).toHaveLength(1);
    expect(readFileSync(join(dir, tmp[0] ?? '')).length).toBeLessThan(before.length);
    expect(readFileSync(fault.store)).toEqual(before);
    expect(await tryLoad(RAW_KEY)).toBeDefined();
  });
});

describe('durability order', () => {
  async function seededStore(): Promise<void> {
    (await EncryptedStore.create(fault.store, RAW_KEY, seeded(1))).close();
  }

  it('rekey: temp file fsynced before the rename, directory fsynced after it, all under the lock', async () => {
    await seededStore();
    const t = await traceOf(() => rekeyStore(fault.store, RAW_KEY, OTHER_KEY, ctx));
    const at = (p: string): number => t.indexOf(p);
    expect(at('sync:tmp#1')).toBeGreaterThan(at('writeFile:tmp#1'));
    expect(at('rename:tmp#1')).toBeGreaterThan(0);
    expect(at('sync:tmp#1')).toBeLessThan(at('rename:tmp#1'));
    expect(at('open:dir#1')).toBeGreaterThan(at('rename:tmp#1'));
    expect(at('sync:dir#1')).toBeGreaterThan(at('open:dir#1'));
    expect(at('open:lock#1')).toBe(0);
    expect(at('unlink:lock#1')).toBe(t.length - 1);
    // The file is read back (verified on disk) after the rename.
    expect(at('readFile:store#2')).toBeGreaterThan(at('sync:dir#1'));
  });

  it('restore and migrate: the .bak copy is fsynced and its directory entry made durable before the store is replaced', async () => {
    await seededStore();
    const r = await traceOf(() => restoreStore(fault.store, RAW_KEY, seeded(2), ctx, { replace: true }));
    expect(r.indexOf('sync:bak#1')).toBeGreaterThan(-1);
    expect(r.indexOf('sync:dir#1')).toBeGreaterThan(r.indexOf('sync:bak#1'));
    expect(r.indexOf('sync:dir#1')).toBeLessThan(r.indexOf('rename:tmp#1'));
    resetDir();
    await writeV0Store(fault.store, RAW_KEY, seeded(1));
    const m = await traceOf(() => migrateStore(fault.store, RAW_KEY, ctx, [V0_TO_V1]));
    expect(m.indexOf('sync:bak#1')).toBeGreaterThan(-1);
    expect(m.indexOf('sync:dir#1')).toBeGreaterThan(m.indexOf('sync:bak#1'));
    expect(m.indexOf('sync:dir#1')).toBeLessThan(m.indexOf('rename:tmp#1'));
  });
});

describe('restore --replace: interrupted at every step, the old store is never lost', () => {
  it('the store is the old file byte for byte, or the restored store with a complete .bak of the old one', { timeout: 120_000 }, async () => {
    const oldData = seeded(1);
    const incoming = seeded(3);
    const setup = async (): Promise<Buffer> => {
      resetDir();
      (await EncryptedStore.create(fault.store, RAW_KEY, oldData)).close();
      return readFileSync(fault.store);
    };
    const op = (): Promise<unknown> => restoreStore(fault.store, OTHER_KEY, incoming, ctx, { replace: true });
    await setup();
    const trace = await traceOf(op);
    const renameAt = renameIndex(trace);
    for (const point of crashPoints(trace)) {
      const original = await setup();
      await crashAt(point, op);
      const label = `${point.point}${point.partial ? ' (half written)' : ''}`;
      const now = readFileSync(fault.store);
      const bak = join(dir, 's.tocsin.20260110T080000000Z.bak');
      if (trace.indexOf(point.point) <= renameAt) {
        expect(now.equals(original), `${label}: old store untouched`).toBe(true);
        expect(await tryLoad(RAW_KEY)).toEqual(oldData);
      } else {
        const restored = await tryLoad(OTHER_KEY);
        expect(restored, `${label}: restored store opens`).toBeDefined();
        expect(verifyAudit((restored as StoreData).audit).ok).toBe(true);
        expect((restored as StoreData).incidents).toEqual(incoming.incidents);
        expect(readFileSync(bak).equals(original), `${label}: complete .bak`).toBe(true);
      }
    }
  });
});

describe('migrate: interrupted at every step, the store is the original or a complete migrated store', () => {
  it('and a complete .bak of the original exists whenever the store was replaced', { timeout: 120_000 }, async () => {
    const data = seeded(2);
    await writeV0Store(fault.store, RAW_KEY, data);
    const initial = readFileSync(fault.store);
    const setup = (): Promise<Buffer> => {
      resetDir();
      writeFileSync(fault.store, initial, { mode: 0o600 });
      return Promise.resolve(initial);
    };
    const op = (): Promise<unknown> => migrateStore(fault.store, RAW_KEY, ctx, [V0_TO_V1]);
    await setup();
    const trace = await traceOf(op);
    const renameAt = renameIndex(trace);
    for (const point of crashPoints(trace)) {
      const original = await setup();
      await crashAt(point, op);
      const label = `${point.point}${point.partial ? ' (half written)' : ''}`;
      if (trace.indexOf(point.point) <= renameAt) {
        expect(readFileSync(fault.store).equals(original), `${label}: original untouched`).toBe(true);
        rmSync(`${fault.store}.lock`, { force: true });
        rmSync(join(dir, 's.tocsin.v0-20260110T080000000Z.bak'), { force: true }); // a half-written .bak blocks the same name
        await op(); // running it again completes the migration
      } else {
        expect(readFileSync(join(dir, 's.tocsin.v0-20260110T080000000Z.bak')).equals(original), `${label}: complete .bak`).toBe(true);
      }
      const migrated = await tryLoad(RAW_KEY);
      expect(migrated, `${label}: migrated store opens`).toBeDefined();
      expect(verifyAudit((migrated as StoreData).audit).ok).toBe(true);
      expect((migrated as StoreData).incidents).toEqual(data.incidents);
      expect((migrated as StoreData).audit.at(-1)?.action).toBe('store.migrated');
    }
  });
});

describe('verification controls', () => {
  /** Counts the seals of a clean run, then corrupts the last one (the sealed index of the file to be written). */
  async function lastSealOf(setup: () => Promise<void>, op: () => Promise<unknown>): Promise<number> {
    await setup();
    fault.seals = 0;
    await op();
    const n = fault.seals;
    await setup();
    fault.seals = 0;
    return n;
  }

  const cases: [string, () => Promise<void>, () => Promise<unknown>, KeySource][] = [
    [
      'rekey',
      async () => {
        resetDir();
        (await EncryptedStore.create(fault.store, RAW_KEY, seeded(1))).close();
      },
      () => rekeyStore(fault.store, RAW_KEY, OTHER_KEY, ctx),
      RAW_KEY,
    ],
    [
      'restore',
      async () => {
        resetDir();
        (await EncryptedStore.create(fault.store, RAW_KEY, seeded(1))).close();
      },
      () => restoreStore(fault.store, OTHER_KEY, seeded(2), ctx, { replace: true }),
      RAW_KEY,
    ],
    [
      'migrate',
      async () => {
        resetDir();
        await writeV0Store(fault.store, RAW_KEY, seeded(1));
      },
      () => migrateStore(fault.store, RAW_KEY, ctx, [V0_TO_V1]),
      RAW_KEY,
    ],
  ];

  for (const [name, setup, op, key] of cases) {
    it(`${name}: a file that would not verify is never written (in-memory check before the rename)`, async () => {
      const n = await lastSealOf(setup, op);
      const before = readFileSync(fault.store);
      fault.corruptSeal = n;
      const err = await op().then(
        () => undefined,
        (e: unknown) => e,
      );
      fault.corruptSeal = 0;
      expect(err).toBeInstanceOf(TocsinError);
      expect((err as TocsinError).message).toMatch(/Wrong key|before writing/u);
      expect(readFileSync(fault.store).equals(before)).toBe(true);
      expect(readdirSync(dir).filter((f) => f.endsWith('.bak') || f.endsWith('.tmp'))).toEqual([]);
      if (name !== 'migrate') expect(await tryLoad(key)).toBeDefined();
    });

    it(`${name}: damage between the rename and the read-back is reported, not hidden`, async () => {
      await setup();
      fault.afterRename = () => {
        const b = readFileSync(fault.store);
        writeFileSync(fault.store, b.subarray(0, b.length - 40));
      };
      await expect(op()).rejects.toBeInstanceOf(TocsinError);
    });
  }
});
