// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { writeFile } from 'node:fs/promises';
import { open as openBox, seal, type Box, type KeySource } from '../src/store/crypto.js';
import type { MigrationStep } from '../src/store/migrate.js';
import { STORE_FORMAT, keyFor, newKdf, type Kdf, type StoreData } from '../src/store/store.js';
import { canonicalJson } from '../src/util/canonical-json.js';
import { FAST_SCRYPT } from './helpers.js';

/**
 * A test-only "format version 0": the whole data set sealed in one AES-GCM box. It exists only so that the
 * migration runner, its checks and its fault handling are exercised before a real version 2 exists.
 */

function v0Aad(kdf: Kdf): string {
  return `${STORE_FORMAT}/v0/data/${canonicalJson(kdf)}`;
}

/** Writes a version 0 store holding `data` at `revision`. */
export async function writeV0Store(path: string, source: KeySource, data: StoreData, revision = 3): Promise<void> {
  const kdf = newKdf(source, FAST_SCRYPT);
  const key = await keyFor(source, kdf, STORE_FORMAT);
  const box = seal(key, Buffer.from(canonicalJson({ revision, data }), 'utf8'), v0Aad(kdf));
  key.fill(0);
  await writeFile(path, `${JSON.stringify({ format: STORE_FORMAT, version: 0, cipher: 'aes-256-gcm', kdf, data: box })}\n`, { mode: 0o600 });
}

/** The test-only migration from version 0 to 1. It authenticates the box before using its content. */
export const V0_TO_V1: MigrationStep = {
  from: 0,
  to: 1,
  description: 'test-only: one sealed box to sealed records',
  async run(file, source, tools) {
    const kdf = tools.parseKdf(file['kdf']);
    const key = await tools.deriveKey(source, kdf);
    try {
      const plain = openBox(key, file['data'] as Box, v0Aad(kdf));
      const { revision, data } = JSON.parse(plain.toString('utf8')) as { revision: number; data: StoreData };
      return tools.encodeCurrent(kdf, key, data, revision);
    } finally {
      key.fill(0);
    }
  },
};
