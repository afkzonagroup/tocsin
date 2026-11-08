// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import type { Tri } from '../util/validate.js';

/**
 * Exact-integer threshold helpers. No floating point is used for any legal threshold.
 * "more than" and "exceeds" are strict (>) as in the official text.
 */

export type Status = 'met' | 'not-met' | 'unknown';

/** Share of a total expressed as a fraction num/den (5 % = 1/20, 1 % = 1/100, 0.1 % = 1/1000). */
export interface Share {
  readonly num: number;
  readonly den: number;
  readonly label: string;
}

export const FIVE_PERCENT: Share = { num: 1, den: 20, label: '5 %' };
export const ONE_PERCENT: Share = { num: 1, den: 100, label: '1 %' };
export const ONE_TENTH_PERCENT: Share = { num: 1, den: 1000, label: '0,1 %' };

/** IR 2024/2690 Art 3(1)(a): EUR 500 000 in cents. */
export const FINANCIAL_LOSS_CAP_CENTS = 50_000_000;
/** IR Arts 7, 9-13: 1 million users. */
export const ONE_MILLION = 1_000_000;
/** IR Art 14(c): 200 000 users or relying parties. */
export const TWO_HUNDRED_THOUSAND = 200_000;
/** IR Art 14(e): 100 users or relying parties. */
export const ONE_HUNDRED = 100;

export const THIRTY_MINUTES = 30 * 60;
export const TWENTY_MINUTES = 20 * 60;
export const ONE_HOUR = 60 * 60;
/** IR Arts 5(b), 6(b): 10 seconds in milliseconds. */
export const TEN_SECONDS_MS = 10_000;

/**
 * `count` is more than `share` of `total` or more than `cap`, "whichever number is smaller".
 * Since x > min(a, b) ⇔ x > a ∨ x > b, no division or rounding is needed.
 */
export function exceedsShareOrCap(count: number | undefined, total: number | undefined, share: Share, cap: number): Status {
  if (count === undefined) return 'unknown';
  if (count > cap) return 'met';
  if (total === undefined) return count === 0 ? 'not-met' : 'unknown';
  return count * share.den > total * share.num ? 'met' : 'not-met';
}

/**
 * IR Art 3(1)(a): direct financial loss exceeds EUR 500 000 or 5 % of the total annual turnover in the
 * preceding financial year, whichever is lower.
 */
export function financialLossStatus(lossCents: number | undefined, turnoverCents: number | undefined): Status {
  return exceedsShareOrCap(lossCents, turnoverCents, FIVE_PERCENT, FINANCIAL_LOSS_CAP_CENTS);
}

/** Strictly more than `limit`. */
export function moreThan(value: number | undefined, limit: number): Status {
  if (value === undefined) return 'unknown';
  return value > limit ? 'met' : 'not-met';
}

export function fromTri(t: Tri | undefined): Status {
  if (t === 'yes') return 'met';
  if (t === 'no') return 'not-met';
  return 'unknown';
}

/** Logical AND over three-valued statuses. */
export function all(...xs: Status[]): Status {
  if (xs.includes('not-met')) return 'not-met';
  if (xs.includes('unknown')) return 'unknown';
  return 'met';
}

/** Formats integer euro cents as "EUR 500 000.00". */
export function formatEuro(cents: number): string {
  const whole = Math.floor(cents / 100)
    .toString()
    .replace(/\B(?=(\d{3})+(?!\d))/gu, ' ');
  return `EUR ${whole}.${String(cents % 100).padStart(2, '0')}`;
}
