// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import { lookup as dnsLookup } from 'node:dns/promises';
import { BlockList, isIP } from 'node:net';
import { TocsinError } from '../util/errors.js';

/**
 * SSRF guard for outbound webhooks. A destination is allowed only when every address its host name
 * resolves to is a public unicast address. The connection is then pinned to the checked address, so a
 * second DNS answer (DNS rebinding) cannot redirect it.
 */

const v4 = new BlockList();
for (const [net, prefix] of [
  ['0.0.0.0', 8], // "this" network
  ['10.0.0.0', 8], // private
  ['100.64.0.0', 10], // CGNAT
  ['127.0.0.0', 8], // loopback
  ['169.254.0.0', 16], // link-local, incl. cloud metadata 169.254.169.254
  ['172.16.0.0', 12], // private
  ['192.0.0.0', 24], // IETF protocol assignments
  ['192.0.2.0', 24], // TEST-NET-1
  ['192.88.99.0', 24], // 6to4 relay anycast
  ['192.168.0.0', 16], // private
  ['198.18.0.0', 15], // benchmarking
  ['198.51.100.0', 24], // TEST-NET-2
  ['203.0.113.0', 24], // TEST-NET-3
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4], // reserved + broadcast
] as const) {
  v4.addSubnet(net, prefix, 'ipv4');
}

const v6 = new BlockList();
for (const [net, prefix] of [
  ['::', 128], // unspecified
  ['::1', 128], // loopback
  ['::', 96], // IPv4-compatible (deprecated)
  ['64:ff9b::', 96], // NAT64 well-known prefix
  ['64:ff9b:1::', 48], // local-use NAT64
  ['100::', 64], // discard-only
  ['2001::', 23], // IETF protocol assignments (incl. Teredo 2001::/32)
  ['2001:db8::', 32], // documentation
  ['2002::', 16], // 6to4 (embeds an IPv4 address)
  ['3fff::', 20], // documentation (RFC 9637)
  ['5f00::', 16], // SRv6 SIDs
  ['fc00::', 7], // unique local, incl. AWS metadata fd00:ec2::254
  ['fe80::', 10], // link-local
  ['fec0::', 10], // site-local (deprecated)
  ['ff00::', 8], // multicast
] as const) {
  v6.addSubnet(net, prefix, 'ipv6');
}

/** IPv6 global unicast (2000::/3, RFC 4291). Everything outside it is unassigned or special-purpose. */
const v6GlobalUnicast = new BlockList();
v6GlobalUnicast.addSubnet('2000::', 3, 'ipv6');

/** Extracts the IPv4 address from an IPv4-mapped IPv6 address (::ffff:a.b.c.d or ::ffff:xxxx:xxxx). */
function mappedV4(ip: string): string | undefined {
  const lower = ip.toLowerCase();
  const dotted = /^(?:0{0,4}:){0,5}:?ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/u.exec(lower);
  if (dotted !== null) return dotted[1];
  const hex = /^(?:0{0,4}:){0,5}:?ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/u.exec(lower);
  if (hex !== null) {
    const hi = parseInt(hex[1] as string, 16);
    const lo = parseInt(hex[2] as string, 16);
    return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  }
  return undefined;
}

/** True when `ip` must never be contacted (private, loopback, link-local, metadata, multicast, reserved…). */
export function isBlockedAddress(ip: string): boolean {
  const family = isIP(ip);
  if (family === 4) return v4.check(ip, 'ipv4');
  if (family === 6) {
    const m = mappedV4(ip);
    if (m !== undefined) return isIP(m) !== 4 || v4.check(m, 'ipv4');
    if (/^::ffff:/iu.test(ip)) return true;
    return !v6GlobalUnicast.check(ip, 'ipv6') || v6.check(ip, 'ipv6');
  }
  return true; // not an IP literal
}

export interface ResolvedTarget {
  readonly url: URL;
  readonly address: string;
  readonly family: 4 | 6;
}

export type Resolver = (host: string) => Promise<{ address: string; family: number }[]>;

const defaultResolver: Resolver = (host) => dnsLookup(host, { all: true, order: 'verbatim' });

export interface GuardOptions {
  /** Allow http: (programmatic use and tests only; configuration always requires https). */
  readonly allowHttp?: boolean;
  /** Optional host allow-list (exact, lower-case names). */
  readonly allowedHosts?: readonly string[];
  /** DNS resolver (injectable for tests). */
  readonly resolver?: Resolver;
  /** Address policy (injectable for tests). Defaults to {@link isBlockedAddress}. */
  readonly isBlocked?: (ip: string) => boolean;
}

/** Validates a webhook URL and resolves it to one checked address. */
export async function resolveSafeTarget(rawUrl: string, opts: GuardOptions = {}): Promise<ResolvedTarget> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new TocsinError('SSRF_BLOCKED', 'The webhook URL is not valid.');
  }
  if (url.protocol !== 'https:' && !(opts.allowHttp === true && url.protocol === 'http:')) throw new TocsinError('SSRF_BLOCKED', 'Webhook URLs must use https.');
  if (url.username !== '' || url.password !== '') throw new TocsinError('SSRF_BLOCKED', 'Webhook URLs must not contain credentials.');
  if (url.port !== '' && url.port !== '443' && !(opts.allowHttp === true)) throw new TocsinError('SSRF_BLOCKED', 'Webhook URLs must use the default https port.');
  const host = url.hostname.replace(/^\[|\]$/gu, '').toLowerCase();
  if (opts.allowedHosts !== undefined && !opts.allowedHosts.includes(host)) throw new TocsinError('SSRF_BLOCKED', 'The webhook host is not in the allow-list.');
  const blocked = opts.isBlocked ?? isBlockedAddress;
  let answers: { address: string; family: number }[];
  if (isIP(host) !== 0) {
    answers = [{ address: host, family: isIP(host) }];
  } else {
    if (host === 'localhost' || host.endsWith('.localhost') || !host.includes('.')) throw new TocsinError('SSRF_BLOCKED', 'Webhook host must be a public domain name.');
    try {
      answers = await (opts.resolver ?? defaultResolver)(host);
    } catch {
      throw new TocsinError('NETWORK', 'Could not resolve the webhook host.');
    }
  }
  if (answers.length === 0) throw new TocsinError('NETWORK', 'The webhook host has no addresses.');
  // Every answer must be public; otherwise an attacker-controlled zone could mix in a private address.
  for (const a of answers) {
    if (blocked(a.address)) throw new TocsinError('SSRF_BLOCKED', 'The webhook host resolves to a private or reserved address.');
  }
  const first = answers[0] as { address: string; family: number };
  return { url, address: first.address, family: first.family === 6 ? 6 : 4 };
}
