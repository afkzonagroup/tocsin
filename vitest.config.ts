// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
    testTimeout: 20_000,
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      reporter: ['text-summary', 'text'],
      // Core logic must stay at or above 90 % line coverage. The CLI/UI glue is covered by flow tests.
      thresholds: {
        'src/{assess,audit,model,registry,reports,stages,store,time,connectors}/**/*.ts': { lines: 90 },
      },
    },
  },
});
