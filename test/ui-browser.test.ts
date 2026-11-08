// Copyright 2026 MB AFKzona Group
// SPDX-License-Identifier: AGPL-3.0-only

/**
 * The web UI in a real browser (Playwright's Chromium). Header-level tests cannot see how a browser fills in
 * Origin, Referer and Sec-Fetch-* on a form post: under `Referrer-Policy: no-referrer` Chromium sends
 * `Origin: null`, and the Origin check refused every form. This test logs in and submits real forms.
 */

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { chromium, type Browser } from 'playwright-core';
import { createIncident, initStore } from '../src/registry/ops.js';
import { EncryptedStore, emptyData } from '../src/store/store.js';
import { startUi, type UiHandle } from '../src/ui/server.js';
import { CFG, RAW_KEY, tempDir } from './helpers.js';

const TOKEN = 'B'.repeat(43);
let browser: Browser;
let ui: UiHandle;
let store: EncryptedStore;
let cleanup: () => Promise<void>;

beforeAll(async () => {
  const t = await tempDir();
  cleanup = t.cleanup;
  const ctx = { now: Date.now(), actor: 't' };
  const data = createIncident(initStore(emptyData(new Date().toISOString()), ctx), { title: 'Storage cluster outage', serviceTypes: ['cloud'] }, ctx).data;
  store = await EncryptedStore.create(`${t.dir}/s.tocsin`, RAW_KEY, data);
  ui = await startUi({ store, config: CFG, host: '127.0.0.1', port: 0, actor: 'browser-test', loginToken: TOKEN });
  browser = await chromium.launch();
}, 60_000);

afterAll(async () => {
  await browser.close();
  await ui.close();
  store.close();
  await cleanup();
});

describe('web UI in Chromium', () => {
  it('logs in and submits forms (Origin is sent and accepted)', async () => {
    const page = await browser.newPage();
    const origins: string[] = [];
    page.on('request', (r) => {
      if (r.method() === 'POST') origins.push(r.headers()['origin'] ?? '(none)');
    });
    await page.goto(ui.loginUrl);
    await expect.poll(() => page.url()).toBe(`${ui.origin}/`);
    expect(await page.locator('body').innerText()).toContain('Storage cluster outage');

    // Create an incident through the real form.
    await page.goto(`${ui.origin}/new`);
    await page.locator('#title').fill('Browser-created incident');
    await page.locator('input[name="serviceTypes"]').first().check();
    const [created] = await Promise.all([page.waitForResponse((r) => r.request().method() === 'POST' && r.url().endsWith('/incidents')), page.getByRole('button', { name: 'Create' }).click()]);
    expect(created.status()).toBeLessThan(400);
    await page.waitForLoadState();
    expect(await page.locator('body').innerText()).toContain('Browser-created incident');

    // Log out: also a form post.
    const [logout] = await Promise.all([page.waitForResponse((r) => r.request().method() === 'POST' && r.url().endsWith('/logout')), page.getByRole('button', { name: 'Lock' }).click()]);
    expect(logout.status()).toBeLessThan(400);
    expect(origins.length).toBeGreaterThan(0);
    for (const o of origins) expect(o).toBe(ui.origin);
    await page.close();
  }, 60_000);

  it('still refuses a post from another origin', async () => {
    const page = await browser.newPage();
    await page.goto(ui.loginUrl);
    const res = await page.request.post(`${ui.origin}/logout`, { headers: { origin: 'http://evil.example' }, form: { _csrf: 'x' } });
    expect([401, 403]).toContain(res.status());
    await page.close();
  });
});
