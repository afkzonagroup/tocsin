// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

// Checks the output of `npm pack --dry-run --json` (file given as argument): the tarball must contain every
// file that package.json points to (main, types, bin, exports) and the licence. Run `npm run build` first:
// a package published without its compiled code installs but does nothing.

import { readFileSync } from 'node:fs';
import process from 'node:process';

/** @param {string} path @returns {unknown} */
const readJson = (path) => JSON.parse(readFileSync(path, 'utf8'));

/** @param {unknown} v @returns {v is Record<string, unknown>} */
const isObject = (v) => v !== null && typeof v === 'object';

const pkg = readJson('package.json');
const packed = readJson(process.argv[2] ?? '');

/** @type {Set<string>} */
const files = new Set();
const first = Array.isArray(packed) ? /** @type {unknown} */ (packed[0]) : undefined;
if (isObject(first) && Array.isArray(first.files)) {
  for (const entry of /** @type {unknown[]} */ (first.files)) {
    if (isObject(entry) && typeof entry.path === 'string') files.add(entry.path);
  }
}

/** @type {Set<string>} */
const required = new Set(['LICENSE', 'package.json']);
/** @param {unknown} value */
const add = (value) => {
  if (typeof value === 'string') {
    if (!value.includes('*')) required.add(value.replace(/^\.\//, ''));
  } else if (isObject(value)) {
    for (const v of Object.values(value)) add(v);
  }
};
if (isObject(pkg)) for (const key of ['main', 'types', 'bin', 'exports']) add(pkg[key]);

const missing = [...required].filter((p) => !files.has(p));
if (files.size === 0 || missing.length > 0) {
  process.stderr.write(`The package would miss: ${missing.join(', ') || 'everything'}. Run npm run build first.\n`);
  process.exitCode = 1;
} else {
  process.stdout.write(`Package contents OK: ${String(files.size)} files, all ${String(required.size)} entry points present.\n`);
}
