// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

/** Error codes. Messages never contain secrets or stack traces meant for end users. */
export type TocsinErrorCode =
  | 'VALIDATION'
  | 'NOT_FOUND'
  | 'CONFLICT'
  | 'STAGE_ORDER'
  | 'WRONG_KEY_OR_TAMPERED'
  | 'STORE_FORMAT'
  | 'STORE_LOCKED'
  | 'IO'
  | 'CONFIG'
  | 'SSRF_BLOCKED'
  | 'NETWORK'
  | 'IMPORT_FORMAT';

/** The only error type thrown on purpose by this package. */
export class TocsinError extends Error {
  readonly code: TocsinErrorCode;

  constructor(code: TocsinErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'TocsinError';
    this.code = code;
  }
}

/** Throws a VALIDATION error. */
export function invalid(message: string): never {
  throw new TocsinError('VALIDATION', message);
}

/** Message safe to show to a user: our own messages verbatim, everything else generic. */
export function publicMessage(err: unknown): string {
  if (err instanceof TocsinError) return err.message;
  return 'Unexpected internal error.';
}
