// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { chmod, link, lstat, open, readFile, rename, stat, unlink } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';
import { TocsinError } from '../util/errors.js';

/** O_NONBLOCK so that opening a FIFO or device for the size check cannot hang. */
const NONBLOCK = constants.O_NONBLOCK;

/** Private file mode: owner read/write only. */
export const PRIVATE_MODE = 0o600;

/** Validates a user-supplied path and returns it resolved. Rejects NUL bytes and empty names. */
export function safePath(p: string, what: string): string {
  if (p.length === 0 || p.length > 4096 || p.includes('\0')) throw new TocsinError('VALIDATION', `${what}: invalid path.`);
  return resolve(p);
}

async function fsyncDir(dir: string): Promise<void> {
  let fh;
  try {
    fh = await open(dir, constants.O_RDONLY);
    await fh.sync();
  } catch {
    // Some platforms (Windows, some network file systems) cannot fsync a directory. The rename is still atomic.
  } finally {
    await fh?.close();
  }
}

/**
 * Atomic replace: write a temp file in the same directory (created exclusively with mode 0600),
 * fsync it, rename it over the target, then fsync the directory. Readers see the old or the new
 * content, never a partial file.
 */
export async function writeFileAtomic(path: string, data: string | Uint8Array, mode: number = PRIVATE_MODE): Promise<void> {
  const dir = dirname(path);
  const tmp = join(dir, `.${basename(path)}.${randomBytes(8).toString('hex')}.tmp`);
  let renamed = false;
  try {
    const fh = await open(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, mode);
    try {
      await fh.writeFile(data);
      await fh.sync();
    } finally {
      await fh.close();
    }
    await chmod(tmp, mode);
    await rename(tmp, path);
    renamed = true;
    await fsyncDir(dir);
  } catch (err) {
    if (!renamed) await unlink(tmp).catch(() => undefined);
    if (err instanceof TocsinError) throw err;
    throw new TocsinError('IO', `Could not write ${basename(path)}: ${(err as NodeJS.ErrnoException).code ?? 'I/O error'}.`, { cause: err });
  }
}

/**
 * Creates a new file exclusively (fails if it exists, never follows a symlink at the target), mode 0600.
 * Used for report output so that existing files are never silently replaced.
 */
export async function writeNewFile(path: string, data: string | Uint8Array, mode: number = PRIVATE_MODE): Promise<void> {
  try {
    const fh = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, mode);
    try {
      await fh.writeFile(data);
      await fh.sync();
    } finally {
      await fh.close();
    }
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'EEXIST') throw new TocsinError('CONFLICT', `${basename(path)} already exists; choose another name.`);
    throw new TocsinError('IO', `Could not write ${basename(path)}: ${code ?? 'I/O error'}.`, { cause: err });
  }
}

/** Reads a regular file with a size cap. Refuses symlinks, so a planted link cannot redirect the read. */
export async function readFileCapped(path: string, maxBytes: number): Promise<Buffer> {
  // Open once without following symlinks, then check and read through the same handle, so the file
  // cannot be swapped between the check and the read.
  let fh;
  try {
    fh = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | NONBLOCK);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') throw new TocsinError('NOT_FOUND', `${basename(path)} does not exist.`);
    if (code === 'ELOOP' || code === 'EMLINK') throw new TocsinError('IO', `${basename(path)} is a symbolic link; refusing to follow it.`);
    throw new TocsinError('IO', `Could not read ${basename(path)}: ${code ?? 'I/O error'}.`);
  }
  try {
    const st = await fh.stat();
    if (!st.isFile()) throw new TocsinError('IO', `${basename(path)} is not a regular file.`);
    if (st.size > maxBytes) throw new TocsinError('IO', `${basename(path)} is larger than ${Math.floor(maxBytes / 1024 / 1024)} MiB.`);
    const buf = await fh.readFile();
    if (buf.length > maxBytes) throw new TocsinError('IO', `${basename(path)} is too large.`);
    return buf;
  } finally {
    await fh.close().catch(() => undefined);
  }
}

export async function exists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch {
    return false;
  }
}

/** True when group or others can read/write the file (POSIX only; always false on Windows). */
export async function isGroupOrWorldAccessible(path: string): Promise<boolean> {
  if (process.platform === 'win32') return false;
  const st = await stat(path);
  return (st.mode & 0o077) !== 0;
}

const LOCK_STALE_MS = 2 * 60_000;

/**
 * Exclusive advisory lock next to the store (`<store>.lock`). Held only for one read-modify-write.
 * A lock older than two minutes whose process no longer exists is treated as stale and removed.
 */
export async function withLock<T>(target: string, fn: () => Promise<T>): Promise<T> {
  const lockPath = `${target}.lock`;
  let fh;
  for (let attempt = 0; attempt < 2 && fh === undefined; attempt++) {
    try {
      fh = await open(lockPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, PRIVATE_MODE);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw new TocsinError('IO', 'Could not create the lock file.', { cause: err });
      if (attempt === 0 && (await removeIfStale(lockPath))) continue;
      throw new TocsinError('STORE_LOCKED', `The store is locked by another process (${basename(lockPath)}). If no other Tocsin process is running, delete that file.`);
    }
  }
  if (fh === undefined) throw new TocsinError('STORE_LOCKED', 'The store is locked by another process.');
  let ours: { dev: number; ino: number } | undefined;
  // A random token identifies our lock. Inode numbers alone are not enough: Linux file systems reuse the
  // inode of a deleted file at once, so a replacement lock can carry the same dev/ino as ours.
  const token = randomBytes(16).toString('hex');
  try {
    ours = await fh.stat();
    await fh.writeFile(JSON.stringify({ pid: process.pid, at: new Date().toISOString(), token }));
    await fh.close();
    return await fn();
  } finally {
    await fh.close().catch(() => undefined);
    // Remove the lock only if it is still the file we created: same inode and still carrying our token.
    // Inode and token are read through one handle opened without following symlinks.
    if (await isOurLock(lockPath, ours, token)) await unlink(lockPath).catch(() => undefined);
  }
}

async function isOurLock(lockPath: string, ours: { dev: number; ino: number } | undefined, token: string): Promise<boolean> {
  if (ours === undefined) return false;
  const fh = await open(lockPath, constants.O_RDONLY | constants.O_NOFOLLOW).catch(() => undefined);
  if (fh === undefined) return false;
  try {
    const st = await fh.stat();
    if (st.dev !== ours.dev || st.ino !== ours.ino) return false;
    const content = (await fh.readFile({ encoding: 'utf8' })).slice(0, 4096);
    return content.includes(`"token":"${token}"`);
  } catch {
    return false;
  } finally {
    await fh.close().catch(() => undefined);
  }
}

async function removeIfStale(lockPath: string): Promise<boolean> {
  try {
    const st = await lstat(lockPath);
    if (Date.now() - st.mtimeMs < LOCK_STALE_MS) return false;
    const info = JSON.parse((await readFile(lockPath, 'utf8')).slice(0, 200)) as { pid?: unknown };
    if (typeof info.pid === 'number' && Number.isSafeInteger(info.pid) && info.pid > 0) {
      try {
        process.kill(info.pid, 0);
        return false; // process still alive
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== 'ESRCH') return false;
      }
    }
    // Move the stale lock aside atomically: when several processes recover it at once, only one rename
    // succeeds. If the file moved is not the one judged stale (a fresh lock replaced it in between),
    // put it back and give up.
    const aside = `${lockPath}.${randomBytes(6).toString('hex')}.stale`;
    await rename(lockPath, aside);
    const moved = await lstat(aside);
    if (moved.dev !== st.dev || moved.ino !== st.ino) {
      await link(aside, lockPath).catch(() => undefined);
      await unlink(aside).catch(() => undefined);
      return false;
    }
    await unlink(aside);
    return true;
  } catch {
    return false;
  }
}
