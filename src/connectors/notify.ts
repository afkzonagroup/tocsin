// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

import type { TocsinConfig, WebhookConfig, WebhookEvent } from '../model/config.js';
import { STAGE_LABELS } from '../model/types.js';
import { computeDeadlines, type Deadline } from '../stages/deadlines.js';
import { formatInZone, toMs } from '../time/zone.js';
import type { StoreData } from '../store/store.js';
import type { WebhookMessage } from './webhook.js';

/**
 * Plans webhook notifications from the register. Pure: the caller sends them and records the dedupe
 * keys of the ones that were delivered, so each notification goes out once per webhook.
 */

export interface PlannedNotification {
  readonly webhookId: string;
  readonly key: string;
  readonly message: WebhookMessage;
}

/** Removes characters that chat tools interpret as markup, so user text cannot form links or mentions. */
export function plainForChat(text: string): string {
  return text.replace(/[<>[\]()*_~`|\\#@!]/gu, ' ').replace(/\s+/gu, ' ').trim().slice(0, 120);
}

function label(d: Deadline): string {
  return d.kind === 'recipients' ? 'Notice to recipients of services' : STAGE_LABELS[d.kind];
}

const RECENT_SUBMISSION_MS = 24 * 3_600_000;

/** Plans "due soon", "overdue" and "stage submitted" messages for every configured webhook. */
export function planNotifications(data: StoreData, cfg: TocsinConfig, now: number): PlannedNotification[] {
  const hooks = cfg.webhooks ?? [];
  const sent = new Set(data.meta.notified);
  const out: PlannedNotification[] = [];
  for (const inc of data.incidents) {
    const deadlines = computeDeadlines(inc, cfg.timeZone, now);
    for (const hook of hooks) {
      const title = hook.includeTitle === true ? plainForChat(inc.title) : undefined;
      const push = (event: WebhookEvent, d: Deadline, text: string): void => {
        const key = `${hook.id}|${inc.id}|${d.kind}|${d.requestId ?? ''}|${event}|${d.dueAt ?? d.submittedAt ?? ''}`;
        if (sent.has(key) || !hook.events.includes(event)) return;
        out.push({
          webhookId: hook.id,
          key,
          message: {
            event,
            incidentId: inc.id,
            stage: d.kind,
            stageLabel: label(d),
            state: d.state,
            ...(d.dueAt === undefined ? {} : { dueAt: d.dueAt, dueLocal: formatInZone(d.dueAt, cfg.timeZone) }),
            ...(title === undefined ? {} : { title }),
            text: `[Tocsin] ${inc.id}${title === undefined ? '' : ` (${title})`}: ${text}`,
          },
        });
      };
      for (const d of deadlines) {
        if (d.dueAt !== undefined && d.state === 'overdue') {
          push('deadline-overdue', d, `${label(d)} is OVERDUE (was due ${formatInZone(d.dueAt, cfg.timeZone)}).`);
        } else if (d.dueAt !== undefined && d.state === 'open' && toMs(d.dueAt) - now <= dueSoonMs(hook)) {
          push('deadline-due-soon', d, `${label(d)} is due ${formatInZone(d.dueAt, cfg.timeZone)}.`);
        } else if (d.submittedAt !== undefined && d.kind !== 'recipients' && now - toMs(d.submittedAt) <= RECENT_SUBMISSION_MS && now >= toMs(d.submittedAt)) {
          push('stage-submitted', d, `${label(d)} recorded as submitted ${formatInZone(d.submittedAt, cfg.timeZone)}${d.state === 'late' ? ' (after the deadline)' : ''}.`);
        }
      }
    }
  }
  return out;
}

function dueSoonMs(hook: WebhookConfig): number {
  return (hook.dueSoonHours ?? 6) * 3_600_000;
}
