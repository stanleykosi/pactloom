import { test, expect, type Page } from '@playwright/test';
// Synthetic browser fixtures only: no signer, chain, secret, artifact or financial runtime.
const caps = { api_version: '1', engine_version: 'synthetic-client-journey', features: { local_agreements: { status: 'supported', operations: ['create'] }, protected_transport_runtime: { status: 'experimental', api_access: 'local_http' }, offline_signing: { status: 'supported', api_access: 'local_http' } }, profiles: [], adapters: [], limits: {}, runtime: { background_observation: false, storage: 'local_metadata_unencrypted' } };
const draft = { schema_version: 1, agreement_id: 'synthetic-shared-payment', obligation_id: 'synthetic-obligation', revision: 1, purpose: 'Synthetic shared research invoice', organizer_identity: 'synthetic-organizer', network_profile_id: 'zcash-testnet-unqualified', recipients: [{ recipient_id: 'synthetic-recipient', address: 'utestsyntheticneveruseforfunds', amount: '250000000', memo: null, instruction_provenance: 'Synthetic display only; address unverified' }], funding_policy: { kind: 'exact', target: '250000000' }, fee_policy: { kind: 'pro_rata' }, privacy_profile: { mode: 'local_only', proving_operator: null, dedicated_accounts_required: true }, coordination_deadline: null, confirmation_policy: { required_confirmations: 10 }, extensions: [] };
function view() { return { agreement: structuredClone(draft), revision: 1, progress: 'gathering_intent', authorization_exposure: 'unknown', chain_observation: 'unknown', intents: [], proposals: [], verification_reports: [], cancellation_requested: false }; }
async function fixture(page: Page, permissions = ['read', 'propose', 'intent', 'coordinate']) {
  const state = { fail: false, agreements: [view()] as any[], mutations: [] as any[], reads: [] as string[] };
  await page.route('http://127.0.0.1:4318/v1/**', async route => {
    const request = route.request(), path = new URL(request.url()).pathname.slice(3);
    const fulfill = (body: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body), headers: { 'Access-Control-Allow-Origin': 'http://127.0.0.1:4319' } });
    if (request.method() === 'OPTIONS') return route.fulfill({ status: 204, headers: { 'Access-Control-Allow-Origin': 'http://127.0.0.1:4319', 'Access-Control-Allow-Headers': 'Authorization,Content-Type,X-Wholepact-CSRF,Idempotency-Key,If-Match,X-Request-ID', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS' } });
    if (path === '/session') return fulfill({ schema_version: 1, client_id: 'synthetic-client', permissions, agreement_ids: [], all_agreements: true, session_token: 'synthetic-session', csrf_token: 'synthetic-csrf', expires_in_seconds: 1800 });
    expect(request.headers().authorization).toBe('Bearer synthetic-session');
    if (request.method() === 'GET') state.reads.push(path);
    if (path === '/capabilities') return fulfill(caps);
    if (path === '/events') return route.fulfill({ status: 200, contentType: 'text/event-stream', body: ': synthetic fixture\n\n' });
    if (path === '/agreements' && request.method() === 'GET') return state.fail ? fulfill({ code: 'TEMPORARILY_UNAVAILABLE', message: 'Synthetic local service interruption', retryable: true }, 503) : fulfill(state.agreements);
    if (['/authorizations', '/accounts', '/invitations'].includes(path) || path.endsWith('/transport')) return fulfill([]);
    if (path === '/records') return fulfill({ status: 'unavailable', records: null, reason_code: 'SYNTHETIC_NO_RECORD_RUNTIME', account_exposure: 'unknown_not_established_by_records' });
    if (request.method() === 'POST') {
      state.mutations.push({ path, headers: request.headers(), body: request.postDataJSON() });
      expect(request.headers()['x-wholepact-csrf']).toBe('synthetic-csrf');
      if (path === '/agreements') { const saved = { ...view(), agreement: request.postDataJSON() }; state.agreements.push(saved); return fulfill(saved); }
      if (path.endsWith('/intents')) { const saved = state.agreements.find(a => path.includes(a.agreement.agreement_id)); saved.intents.push(request.postDataJSON()); saved.revision++; return fulfill(saved); }
    }
    return fulfill({ code: 'UNSUPPORTED_CAPABILITY', message: 'Synthetic fixture does not support this operation', retryable: false }, 501);
  });
  return state;
}
async function connect(page: Page) { await page.goto('/'); await page.getByLabel('Session bootstrap token').fill('synthetic-bootstrap'); await page.getByRole('button', { name: 'Open local workspace' }).click(); await expect(page.getByRole('heading', { name: 'A clear view of your commitments.' })).toBeVisible(); }
async function openPlan(page: Page) { await page.getByRole('button', { name: /Synthetic shared research invoice/ }).click(); await expect(page.getByRole('heading', { name: 'Synthetic shared research invoice' })).toBeVisible(); }

test('guided local plan uses existing exact draft and nonbinding intent handlers', async ({ page }) => {
  const state = await fixture(page); await connect(page); await page.getByRole('button', { name: 'Create a payment', exact: true }).click();
  await page.getByLabel('What are you agreeing to fund?').fill('Synthetic guided payment'); await page.getByLabel('Organizer identity', { exact: true }).fill('synthetic-owner'); await page.getByLabel('Exact recipient amount (ZEC)').fill('1.00000001'); await page.getByLabel('Shielded receiving instructions').fill('utestsyntheticneverfund');
  await expect(page.getByRole('button', { name: 'Save local draft' })).toBeDisabled(); await page.getByRole('checkbox').check(); await page.getByRole('button', { name: 'Save local draft' }).click(); await expect(page.getByRole('heading', { name: 'Synthetic guided payment' })).toBeVisible();
  expect(state.mutations).toHaveLength(1); expect(state.mutations[0].body.funding_policy.target).toBe('100000001'); expect(state.mutations[0].headers['idempotency-key']).toBeTruthy();
  await page.getByRole('button', { name: 'Add my contribution plan' }).click(); await page.getByLabel('Agreement-scoped participant identifier').fill('synthetic-contributor'); await page.getByLabel('Contribution (ZEC)', { exact: true }).fill('1'); await page.getByLabel('Fee cap (ZEC)').fill('0.00001'); await page.getByLabel('Maximum net debit, including fees (ZEC)').fill('1.00001'); await page.getByRole('dialog').getByRole('checkbox').check(); await page.getByRole('dialog').getByRole('button', { name: 'Record intent', exact: true }).click();
  await expect(page.getByText('synthetic-contributor', { exact: true })).toBeVisible(); expect(state.mutations).toHaveLength(2); expect(state.mutations[1].headers['if-match']).toBe('"1"'); expect(state.mutations[1].body.maximum_net_debit).toBe('100001000');
});
test('invitation guide and approval options never manufacture authority even with optimistic capability data', async ({ page }) => {
  const state = await fixture(page); await connect(page); await openPlan(page);
  await expect(page.getByRole('heading', { name: 'Check what may still spend' })).toBeVisible();
  await page.getByRole('button', { name: 'Invite contributors', exact: true }).click(); let dialog = page.getByRole('dialog'); await expect(dialog).toContainText('cannot create or send a private invitation'); await expect(dialog.getByRole('button', { name: 'View private messages' })).toBeEnabled(); await dialog.getByRole('button', { name: 'View private messages' }).click(); await expect(page.getByRole('region', { name: 'Private messages', exact: true })).toBeFocused();
  const trigger = page.getByRole('button', { name: 'Local & offline approval options' }); await trigger.click(); dialog = page.getByRole('dialog'); await expect(dialog.getByRole('button', { name: 'Local signing · unavailable' })).toBeDisabled(); await expect(dialog.getByRole('button', { name: 'Offline signing · unavailable' })).toBeDisabled(); await dialog.locator('summary').click(); await expect(dialog).toContainText('Independent verification remains the default'); await expect(dialog).toContainText('end-to-end flow is unfinished'); await page.keyboard.press('Escape'); await expect(trigger).toBeFocused();
  await page.getByRole('button', { name: 'Inspect payment status' }).click(); await expect(page.getByRole('region', { name: 'Payment status', exact: true })).toBeFocused(); await page.getByText('Where this status comes from', { exact: true }).click(); await expect(page.getByText(/No observation source, synchronized chain height/)).toBeVisible();
  expect(state.mutations).toHaveLength(0); expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
});
test('read-only sessions and stale service reads cannot enable new planning actions', async ({ page }) => {
  const state = await fixture(page, ['read']); await connect(page); await expect(page.getByRole('button', { name: 'Create a payment', exact: true })).toBeDisabled(); await expect(page.getByRole('button', { name: 'New agreement' })).toBeDisabled(); await openPlan(page); await expect(page.getByRole('button', { name: 'Add my contribution plan' })).toBeDisabled();
  state.fail = true; await page.getByRole('button', { name: 'Refresh workspace' }).click(); await expect(page.getByRole('heading', { name: 'Refresh before continuing' })).toBeVisible(); await page.getByRole('button', { name: 'Invite contributors', exact: true }).click(); await expect(page.getByRole('dialog').getByRole('button', { name: 'View private messages' })).toBeDisabled(); expect(state.mutations).toHaveLength(0);
});
test('an open draft is blocked if its service context becomes stale', async ({ page }) => {
  const state = await fixture(page); await connect(page); await page.getByRole('button', { name: 'Create a payment', exact: true }).click(); state.fail = true;
  // The regular refresh path runs behind the open modal; no mutation is performed.
  await page.evaluate(() => (document.querySelector('button[aria-label="Refresh workspace"]') as HTMLButtonElement).click());
  await expect(page.getByRole('dialog')).toContainText('Refresh the local service'); await expect(page.getByLabel('What are you agreeing to fund?')).toBeDisabled(); await expect(page.getByRole('button', { name: 'Save local draft' })).toBeDisabled(); expect(state.mutations).toHaveLength(0);
});
test('desktop and narrow journey stay readable with advanced tools behind a disclosure', async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 1365, height: 1000 }); await fixture(page); await connect(page); await page.screenshot({ path: testInfo.outputPath('synthetic-overview-desktop.png'), fullPage: true }); await openPlan(page);
  const advanced = page.locator('details.advanced-preparation'); await expect(advanced).not.toHaveAttribute('open'); await expect(advanced.locator('.panel').first()).not.toBeVisible(); await advanced.locator(':scope > summary').click(); await expect(advanced).toHaveAttribute('open'); await advanced.locator(':scope > summary').click(); await page.screenshot({ path: testInfo.outputPath('synthetic-payment-desktop.png'), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 }); await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true); await page.screenshot({ path: testInfo.outputPath('synthetic-payment-mobile.png'), fullPage: true }); await page.getByRole('button', { name: 'Invite contributors', exact: true }).click(); await expect.poll(() => page.getByRole('dialog').evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true); await page.screenshot({ path: testInfo.outputPath('synthetic-invitation-mobile.png') });
});

test('navigation cannot erase a failed refresh and re-enable a new draft', async ({ page }) => {
  const state = await fixture(page); await connect(page); state.fail = true; await page.getByRole('button', { name: 'Refresh workspace' }).click(); await expect(page.getByRole('alert')).toContainText('Local information may be stale');
  await page.getByRole('button', { name: 'Agreements', exact: true }).click(); await expect(page.getByRole('button', { name: 'New agreement' })).toBeDisabled(); await page.getByRole('button', { name: 'Overview', exact: true }).click(); await expect(page.getByRole('button', { name: 'Create a payment', exact: true })).toBeDisabled(); expect(state.mutations).toHaveLength(0);
});

test('keyboard skip link focuses current content without routing away or adding history', async ({ page }) => {
  const state = await fixture(page); await connect(page); await openPlan(page);
  const originalUrl = page.url();
  const historyLength = await page.evaluate(() => history.length);
  const skip = page.getByRole('link', { name: 'Skip to content', exact: true });
  await skip.focus(); await page.keyboard.press('Enter');
  await expect(page.locator('#main-content')).toBeFocused();
  await expect(page.getByRole('heading', { name: 'Synthetic shared research invoice', exact: true })).toBeVisible();
  expect(page.url()).toBe(originalUrl);
  expect(await page.evaluate(() => history.length)).toBe(historyLength);
  await page.getByRole('button', { name: 'Settings', exact: true }).click();
  await page.goBack(); await expect(page).toHaveURL(originalUrl);
  await expect(page.getByRole('heading', { name: 'Agreements', exact: true })).toBeVisible();
  expect(state.mutations).toHaveLength(0);
});
