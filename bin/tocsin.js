#!/usr/bin/env node
// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only
import process from 'node:process';
import { run } from '../dist/cli/main.js';
import { readAllStdin, ttyPromptSecret } from '../dist/cli/io.js';

const io = {
  stdout: (s) => process.stdout.write(s),
  stderr: (s) => process.stderr.write(s),
  env: process.env,
  now: () => Date.now(),
  isTty: process.stdout.isTTY === true,
  promptSecret: process.stdin.isTTY === true ? ttyPromptSecret : undefined,
  readStdin: () => readAllStdin(),
};

process.exitCode = await run(process.argv.slice(2), io);
