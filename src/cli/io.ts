// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

/** Terminal I/O helpers: colour without dependencies, NO_COLOR support, control-character stripping. */

export interface CliIo {
  readonly stdout: (s: string) => void;
  readonly stderr: (s: string) => void;
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly now: () => number;
  /** Whether stdout is a terminal (colour is only used on a terminal). */
  readonly isTty: boolean;
  /** Reads a secret without echo. Undefined when no interactive terminal is available. */
  readonly promptSecret?: (question: string) => Promise<string>;
  /** Reads all of standard input (for `-` values). */
  readonly readStdin?: () => Promise<string>;
}

export type Colour = 'red' | 'yellow' | 'green' | 'bold' | 'dim';

const CODES: Readonly<Record<Colour, string>> = { red: '31', yellow: '33', green: '32', bold: '1', dim: '2' };

/** True when colour may be used: a terminal, NO_COLOR unset or empty (https://no-color.org), not disabled by flag. */
export function colourEnabled(io: Pick<CliIo, 'env' | 'isTty'>, noColourFlag = false): boolean {
  if (noColourFlag) return false;
  const nc = io.env['NO_COLOR'];
  if (nc !== undefined && nc !== '') return false;
  if (io.env['TERM'] === 'dumb') return false;
  return io.isTty;
}

export function paint(enabled: boolean, colour: Colour, text: string): string {
  return enabled ? `\u001b[${CODES[colour]}m${text}\u001b[0m` : text;
}

/** Removes control characters (incl. ESC) and bidi overrides from text bound for a terminal. */
export function term(text: string): string {
  // eslint-disable-next-line no-control-regex -- stripping terminal control characters is the purpose
  return text.replace(/[\u0000-\u0008\u000B-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]/gu, '');
}

/** Pads to a display width (code points). */
export function pad(text: string, width: number): string {
  const len = Array.from(text).length;
  return len >= width ? text : text + ' '.repeat(width - len);
}

/** Prompt for a secret on the controlling terminal with echo off. */
export function ttyPromptSecret(question: string): Promise<string> {
  const stdin = process.stdin;
  const stdout = process.stderr;
  return new Promise((resolve, reject) => {
    if (!stdin.isTTY) {
      reject(new Error('No terminal for the passphrase prompt.'));
      return;
    }
    stdout.write(question);
    let value = '';
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');
    const done = (err?: Error): void => {
      stdin.setRawMode(false);
      stdin.pause();
      stdin.removeListener('data', onData);
      stdout.write('\n');
      if (err === undefined) resolve(value);
      else reject(err);
    };
    const onData = (chunk: string): void => {
      for (const ch of chunk) {
        if (ch === '\r' || ch === '\n') {
          done();
          return;
        }
        if (ch === '\u0003') {
          done(new Error('Cancelled.'));
          return;
        }
        if (ch === '\u007f' || ch === '\b') value = Array.from(value).slice(0, -1).join('');
        else if (ch >= ' ' && value.length < 1024) value += ch;
      }
    };
    stdin.on('data', onData);
  });
}

export async function readAllStdin(maxBytes = 1024 * 1024): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const c of process.stdin) {
    const b = Buffer.isBuffer(c) ? c : Buffer.from(String(c));
    size += b.length;
    if (size > maxBytes) throw new Error('Standard input too large.');
    chunks.push(b);
  }
  return Buffer.concat(chunks).toString('utf8');
}
