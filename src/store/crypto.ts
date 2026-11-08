// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes, scrypt as scryptCb, timingSafeEqual, type ScryptOptions } from 'node:crypto';
import { TocsinError, invalid } from '../util/errors.js';
import { codePointLength } from '../util/validate.js';

/**
 * AES-256-GCM with a fresh random 96-bit nonce per encryption and a 128-bit tag. The data key is derived
 * with HKDF-SHA256 from a master key, which is either a raw 256-bit key or scrypt(passphrase, salt).
 */

export const NONCE_BYTES = 12;
export const TAG_BYTES = 16;
export const KEY_BYTES = 32;
export const SALT_BYTES = 16;

export interface ScryptParams {
  readonly N: number;
  readonly r: number;
  readonly p: number;
}

/** Default: N = 2^17, r = 8, p = 1 (128 MiB, OWASP-recommended minimum class). */
export const DEFAULT_SCRYPT: ScryptParams = { N: 2 ** 17, r: 8, p: 1 };
/** Lowest parameters accepted when reading a file (tests use these to stay fast). */
export const MIN_SCRYPT_N = 2 ** 14;
export const MAX_SCRYPT_N = 2 ** 20;

/** Base64 encoded sealed box. */
export interface Box {
  readonly n: string;
  readonly c: string;
  readonly t: string;
}

export type KeySource = { readonly kind: 'raw'; readonly key: Uint8Array } | { readonly kind: 'passphrase'; readonly passphrase: string };

export function assertScryptParams(p: ScryptParams): void {
  const powerOfTwo = Number.isSafeInteger(p.N) && p.N > 1 && (p.N & (p.N - 1)) === 0;
  if (!powerOfTwo || p.N < MIN_SCRYPT_N || p.N > MAX_SCRYPT_N) throw new TocsinError('STORE_FORMAT', 'Unsupported scrypt cost parameter.');
  if (p.r !== 8 || !Number.isSafeInteger(p.p) || p.p < 1 || p.p > 4) throw new TocsinError('STORE_FORMAT', 'Unsupported scrypt parameters.');
}

function scrypt(passphrase: string, salt: Uint8Array, p: ScryptParams): Promise<Buffer> {
  const opts: ScryptOptions = { N: p.N, r: p.r, p: p.p, maxmem: 256 * p.N * p.r + 1024 * 1024 };
  return new Promise((resolve, reject) => {
    scryptCb(passphrase.normalize('NFC'), salt, KEY_BYTES, opts, (err, key) => {
      if (err !== null) reject(err);
      else resolve(key);
    });
  });
}

/** Minimum passphrase length (code points). */
export const MIN_PASSPHRASE = 12;

export function assertPassphrase(passphrase: string): void {
  if (codePointLength(passphrase) < MIN_PASSPHRASE) invalid(`The passphrase must have at least ${MIN_PASSPHRASE} characters.`);
  if (passphrase.length > 1024) invalid('The passphrase is too long (max 1024 characters).');
}

/**
 * Parses a raw 256-bit key given as 64 hex characters or as base64 / base64url (43-44 characters).
 */
export function parseRawKey(text: string): Buffer {
  const t = text.trim();
  let key: Buffer | undefined;
  if (/^[0-9a-fA-F]{64}$/u.test(t)) key = Buffer.from(t, 'hex');
  else if (/^[A-Za-z0-9+/]{43}=?$/u.test(t)) key = Buffer.from(t, 'base64');
  else if (/^[A-Za-z0-9_-]{43}$/u.test(t)) key = Buffer.from(t, 'base64url');
  if (key?.length !== KEY_BYTES) invalid('The key must be 32 bytes, given as 64 hex characters or base64.');
  return key;
}

/** Derives the master key for a key source. */
export async function masterKey(source: KeySource, salt: Uint8Array, params: ScryptParams | undefined): Promise<Buffer> {
  if (source.kind === 'raw') {
    if (source.key.length !== KEY_BYTES) invalid('The key must be 32 bytes.');
    return Buffer.from(source.key);
  }
  if (params === undefined) throw new TocsinError('STORE_FORMAT', 'This file was written with a raw key, not a passphrase.');
  assertScryptParams(params);
  return scrypt(source.passphrase, salt, params);
}

/** HKDF-SHA256 data key, bound to the file salt and purpose. */
export function dataKey(master: Uint8Array, salt: Uint8Array, purpose: string): Buffer {
  return Buffer.from(hkdfSync('sha256', master, salt, `tocsin ${purpose} v1 aes-256-gcm`, KEY_BYTES));
}

export function seal(key: Uint8Array, plaintext: Uint8Array, aad: string): Box {
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: TAG_BYTES });
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const c = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { n: nonce.toString('base64'), c: c.toString('base64'), t: cipher.getAuthTag().toString('base64') };
}

const B64 = /^[A-Za-z0-9+/]*={0,2}$/u;

function b64(field: string, v: string, exactLen?: number): Buffer {
  if (!B64.test(v)) throw new TocsinError('WRONG_KEY_OR_TAMPERED', `Malformed ${field}.`);
  const buf = Buffer.from(v, 'base64');
  if (exactLen !== undefined && buf.length !== exactLen) throw new TocsinError('WRONG_KEY_OR_TAMPERED', `Malformed ${field}.`);
  return buf;
}

/** Decrypts and authenticates a box. Any failure is reported as "wrong key or tampered" (no oracle detail). */
export function open(key: Uint8Array, box: Box, aad: string): Buffer {
  const nonce = b64('nonce', box.n, NONCE_BYTES);
  const tag = b64('tag', box.t, TAG_BYTES);
  const data = b64('ciphertext', box.c);
  try {
    const d = createDecipheriv('aes-256-gcm', key, nonce, { authTagLength: TAG_BYTES });
    d.setAAD(Buffer.from(aad, 'utf8'));
    d.setAuthTag(tag);
    return Buffer.concat([d.update(data), d.final()]);
  } catch {
    throw new TocsinError('WRONG_KEY_OR_TAMPERED', 'Wrong key or passphrase, or the file was modified.');
  }
}

/** Constant-time string comparison (hashes first so length differences do not leak through timing). */
export function constantTimeEqual(a: string, b: string): boolean {
  const ha = createHash('sha256').update(a, 'utf8').digest();
  const hb = createHash('sha256').update(b, 'utf8').digest();
  return timingSafeEqual(ha, hb);
}

export function randomSalt(): Buffer {
  return randomBytes(SALT_BYTES);
}
