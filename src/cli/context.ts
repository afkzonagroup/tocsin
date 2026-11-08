// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { userInfo } from 'node:os';
import { validateConfig, type TocsinConfig } from '../model/config.js';
import { assertPassphrase, parseRawKey, type KeySource } from '../store/crypto.js';
import { isGroupOrWorldAccessible, readFileCapped, safePath } from '../store/fsutil.js';
import { TocsinError } from '../util/errors.js';
import type { CliIo } from './io.js';

/** Paths and secrets come from flags or environment variables; secrets never from flags (they would show in `ps`). */

export const DEFAULT_STORE = 'tocsin-store.tocsin';
export const DEFAULT_CONFIG = 'tocsin.config.json';

export function storePath(flag: string | undefined, io: CliIo): string {
  return safePath(flag ?? io.env['TOCSIN_STORE'] ?? DEFAULT_STORE, 'store');
}

export function configPath(flag: string | undefined, io: CliIo): string {
  return safePath(flag ?? io.env['TOCSIN_CONFIG'] ?? DEFAULT_CONFIG, 'config');
}

export async function loadConfig(path: string): Promise<TocsinConfig> {
  const buf = await readFileCapped(path, 256 * 1024).catch((err: unknown) => {
    if (err instanceof TocsinError && err.code === 'NOT_FOUND') {
      throw new TocsinError('CONFIG', `No configuration at ${path}. Run "tocsin init" to create one, or pass --config.`);
    }
    throw err;
  });
  let parsed: unknown;
  try {
    parsed = JSON.parse(buf.toString('utf8'));
  } catch {
    throw new TocsinError('CONFIG', 'The configuration file is not valid JSON.');
  }
  try {
    return validateConfig(parsed);
  } catch (err) {
    throw new TocsinError('CONFIG', `Configuration: ${err instanceof Error ? err.message : 'invalid'}`);
  }
}

/** Key file: 32-byte key as hex/base64 text; refused when readable by group or others. */
async function keyFromFile(path: string): Promise<KeySource> {
  const p = safePath(path, 'key file');
  const buf = await readFileCapped(p, 1024);
  if (await isGroupOrWorldAccessible(p)) throw new TocsinError('CONFIG', 'The key file is readable by other users. Run: chmod 600 <file>');
  return { kind: 'raw', key: parseRawKey(buf.toString('utf8')) };
}

export interface KeyOptions {
  readonly keyFile?: string | undefined;
  /** Ask twice (new store / new export). */
  readonly confirm?: boolean;
  /** Environment variable prefix: TOCSIN (store) or TOCSIN_EXPORT (export bundles). */
  readonly prefix?: 'TOCSIN' | 'TOCSIN_EXPORT';
  readonly label?: string;
}

/**
 * Resolves the key: --key-file, then <PREFIX>_KEY (raw key), then <PREFIX>_PASSPHRASE, then an
 * interactive prompt with echo off.
 */
export async function resolveKey(io: CliIo, opts: KeyOptions = {}): Promise<KeySource> {
  const prefix = opts.prefix ?? 'TOCSIN';
  if (opts.keyFile !== undefined) return keyFromFile(opts.keyFile);
  const raw = io.env[`${prefix}_KEY`];
  if (raw !== undefined && raw !== '') return { kind: 'raw', key: parseRawKey(raw) };
  const envPass = io.env[`${prefix}_PASSPHRASE`];
  if (envPass !== undefined && envPass !== '') {
    assertPassphrase(envPass);
    return { kind: 'passphrase', passphrase: envPass };
  }
  if (io.promptSecret === undefined) {
    throw new TocsinError('CONFIG', `No key: set ${prefix}_KEY or ${prefix}_PASSPHRASE, use --key-file, or run in a terminal.`);
  }
  const label = opts.label ?? 'Store passphrase';
  const first = await io.promptSecret(`${label}: `);
  if (opts.confirm === true) {
    assertPassphrase(first);
    const second = await io.promptSecret(`${label} (again): `);
    if (first !== second) throw new TocsinError('VALIDATION', 'The passphrases do not match.');
  }
  return { kind: 'passphrase', passphrase: first };
}

export function actorFrom(io: CliIo): string {
  const a = io.env['TOCSIN_ACTOR'];
  if (a !== undefined && a.trim() !== '') return a.trim().slice(0, 100);
  try {
    return userInfo().username.slice(0, 100) || 'unknown';
  } catch {
    return 'unknown';
  }
}
