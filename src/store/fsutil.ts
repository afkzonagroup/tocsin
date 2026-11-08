// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { chmod, lstat, open, rename, stat, unlink, type FileHandle } from 'node:fs/promises';
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
 * A lock older than two minutes whose process no longer exists is treated as stale and replaced.
 */
export async function withLock<T>(target: string, fn: () => Promise<T>): Promise<T> {
  const lockPath = `${target}.lock`;
  let fh: FileHandle | undefined;
  try {
    fh = await open(lockPath, LOCK_FLAGS, PRIVATE_MODE);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'EEXIST') throw new TocsinError('IO', 'Could not create the lock file.', { cause: err });
    fh = await takeOverStaleLock(lockPath);
  }
  if (fh === undefined) {
    throw new TocsinError('STORE_LOCKED', `The store is locked by another process (${basename(lockPath)}). If no other Tocsin process is running, delete that file and any ${basename(lockPath)}.recover next to it.`);
  }
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

const LOCK_FLAGS = constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL;

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

/**
 * Replace a stale lock with our own. Only the process holding `<lock>.recover` (created with O_EXCL) may
 * judge the lock stale, remove it and create its own, so two processes recovering the same stale lock can
 * never remove each other's fresh lock. (An earlier design moved the stale file aside and compared inode
 * numbers, which Linux reuses at once.) Returns the new lock's handle, or undefined when the lock is live,
 * another process is recovering it, or a new owner got there first.
 */
async function takeOverStaleLock(lockPath: string): Promise<FileHandle | undefined> {
  const mutexPath = `${lockPath}.recover`;
  let mutex: FileHandle;
  try {
    mutex = await open(mutexPath, LOCK_FLAGS, PRIVATE_MODE);
  } catch {
    return undefined;
  }
  try {
    if (!(await isStaleLock(lockPath))) return undefined;
    // Under the mutex nobody else removes a stale lock, so the file judged stale is the one removed.
    await unlink(lockPath).catch((e: unknown) => {
      if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
    });
    // A process that was not recovering may create the lock in between; then it owns it and we back off.
    return await open(lockPath, LOCK_FLAGS, PRIVATE_MODE);
  } catch {
    return undefined;
  } finally {
    await mutex.close().catch(() => undefined);
    await unlink(mutexPath).catch(() => undefined);
  }
}

/** A lock is stale when it is a regular file older than two minutes whose process no longer exists. */
async function isStaleLock(lockPath: string): Promise<boolean> {
  const fh = await open(lockPath, constants.O_RDONLY | constants.O_NOFOLLOW | NONBLOCK).catch(() => undefined);
  if (fh === undefined) return false;
  try {
    const st = await fh.stat();
    if (!st.isFile() || Date.now() - st.mtimeMs < LOCK_STALE_MS) return false;
    const buf = Buffer.alloc(200);
    const { bytesRead } = await fh.read(buf, 0, buf.length, 0);
    let pid: unknown;
    try {
      pid = (JSON.parse(buf.subarray(0, bytesRead).toString('utf8')) as { pid?: unknown }).pid;
    } catch {
      pid = undefined; // unreadable content in an old lock: no process to protect
    }
    if (typeof pid === 'number' && Number.isSafeInteger(pid) && pid > 0) {
      try {
        process.kill(pid, 0);
        return false; // process still alive
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== 'ESRCH') return false;
      }
    }
    return true;
  } catch {
    return false;
  } finally {
    await fh.close().catch(() => undefined);
  }
}
