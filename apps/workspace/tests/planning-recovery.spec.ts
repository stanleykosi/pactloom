import { test, expect, type Page } from '@playwright/test';
// Authored browser checks against synthetic responses only; never financial E2E.
const draft = { schema_version: 1, agreement_id: 'synthetic-plan', obligation_id: 'synthetic-obligation', revision: 1, purpose: 'Synthetic original payment', organizer_identity: 'synthetic-owner', network_profile_id: 'zcash-testnet-unqualified', recipients: [{ recipient_id: 'synthetic-recipient', address: 'synthetic-never-funded', amount: '100000000', memo: null, instruction_provenance: 'Synthetic only' }], funding_policy: { kind: 'exact', target: '100000000' }, fee_policy: { kind: 'pro_rata' }, privacy_profile: { mode: 'local_only', proving_operator: null, dedicated_accounts_required: true }, coordination_deadline: null, confirmation_policy: { required_confirmations: 10 }, extensions: [] };
async function fixture(page: Page, kind: 'draft' | 'intent', first: '500' | 'loss' | 'reject' | 'success' = '500', hold = false) {
  const view = () => ({ agreement: structuredClone(draft), revision: 1, intents: [] as any[], cancellation_requested: false, progress: 'gathering_intent', authorization_exposure: 'unknown', chain_observation: 'unknown' });
  let agreements = kind === 'intent' ? [view()] : [];
  const writes: { body: string | null; key: string; revision: string | undefined }[] = [];
  let saved: any; let release!: () => void; const gate = new Promise<void>(resolve => { release = resolve; });
  await page.route('http://127.0.0.1:4318/v1/**', async route => {
    const request = route.request(), path = new URL(request.url()).pathname.slice(3);
    const json = (value: unknown, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(value), headers: { 'Access-Control-Allow-Origin': 'http://127.0.0.1:4319' } });
    if (request.method() === 'OPTIONS') return route.fulfill({ status: 204, headers: { 'Access-Control-Allow-Origin': 'http://127.0.0.1:4319', 'Access-Control-Allow-Headers': 'Authorization,Content-Type,X-Wholepact-CSRF,Idempotency-Key,If-Match,X-Request-ID', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS' } });
    if (path === '/session') return json({ session_token: 'synthetic-session', csrf_token: 'synthetic-csrf', client_id: 'synthetic-client', permissions: ['read', 'propose', 'intent', 'coordinate'], all_agreements: true, agreement_ids: [] });
    if (path === '/capabilities') return json({ features: { local_agreements: { status: 'supported', operations: ['create'], api_access: 'local_http' } }, profiles: [], adapters: [], limits: {}, runtime: { storage: 'local_metadata_unencrypted' } });
    if (path === '/events') return route.fulfill({ contentType: 'text/event-stream', body: ': synthetic\n\n' });
    if (path === '/agreements' && request.method() === 'GET') return json(agreements);
    if (['/authorizations', '/accounts', '/invitations'].includes(path) || path.endsWith('/transport')) return json([]);
    if (path === '/records') return json({ status: 'unavailable', records: null });
    if (request.method() === 'POST' && (path === '/agreements' || path.endsWith('/intents'))) {
      writes.push({ body: request.postData(), key: request.headers()['idempotency-key']!, revision: request.headers()['if-match'] });
      if (writes.length === 1 && first === 'reject') return json({ code: 'INVALID_TERMS', message: 'Synthetic definitive rejection', retryable: false }, 422);
      if (!saved) { saved = kind === 'draft' ? { ...view(), agreement: request.postDataJSON() } : { ...agreements[0], revision: 2, intents: [request.postDataJSON()] }; agreements = [structuredClone(saved)]; }
      if (writes.length === 1) { if (hold) await gate; if (first === '500') return json({ code: 'STORAGE_UNAVAILABLE', message: 'Synthetic post-commit error', retryable: false }, 500); if (first === 'loss') return route.fulfill({ status: 200, contentType: 'application/json', body: '{' }); }
      return json(saved);
    }
    return json({ code: 'UNSUPPORTED_CAPABILITY', message: 'Synthetic route unavailable', retryable: false }, 501);
  });
  await page.goto('/'); await page.getByLabel('Session bootstrap token').fill('synthetic-bootstrap'); await page.getByRole('button', { name: 'Open local workspace' }).click();
  return { writes, release };
}
async function fillDraft(page: Page) {
  await page.getByRole('button', { name: 'Create a payment', exact: true }).click();
  await page.getByLabel('What are you agreeing to fund?').fill('Synthetic recovery draft'); await page.getByLabel('Organizer identity', { exact: true }).fill('synthetic-owner'); await page.getByLabel('Exact recipient amount (ZEC)').fill('1.00000001'); await page.getByLabel('Shielded receiving instructions').fill('synthetic-never-funded'); await page.getByRole('dialog').getByRole('checkbox').check();
}
test('planning recovery: pending draft closes and reopens, post-commit 500 retries the original identity', async ({ page }) => {
  const f = await fixture(page, 'draft', '500', true); await fillDraft(page); await page.getByRole('button', { name: 'Save local draft' }).click();
  await expect(page.getByRole('dialog')).toContainText('The original save is in progress'); await page.getByRole('button', { name: 'Close window', exact: true }).click(); await expect(page.getByRole('button', { name: 'Create a payment', exact: true })).toBeDisabled();
  await page.getByRole('button', { name: 'Resume original draft', exact: true }).click(); await expect(page.getByRole('button', { name: 'Saving original request…' })).toBeDisabled(); expect(f.writes).toHaveLength(1);
  f.release(); await expect(page.getByRole('dialog')).toContainText('The original save outcome is uncertain'); await page.keyboard.press('Escape'); await page.getByRole('button', { name: 'Agreements', exact: true }).click(); await page.getByRole('button', { name: 'Resume original draft', exact: true }).click();
  await page.getByText('Exact original request', { exact: true }).click(); await expect(page.getByRole('dialog')).toContainText('100000001'); await page.getByRole('button', { name: 'Retry exact original request', exact: true }).dblclick(); await expect(page.getByRole('heading', { name: 'Synthetic recovery draft', exact: true })).toBeVisible();
  expect(f.writes).toHaveLength(2); expect(f.writes[1]).toEqual(f.writes[0]); expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
});
test('planning recovery: interrupted contribution survives navigation and retries its opening revision', async ({ page }) => {
  const f = await fixture(page, 'intent', 'loss'); await page.getByRole('button', { name: /Synthetic original payment/ }).click(); await page.getByRole('button', { name: 'Add my contribution plan' }).click();
  await page.getByLabel('Agreement-scoped participant identifier').fill('synthetic-person'); await page.getByLabel('Contribution (ZEC)', { exact: true }).fill('1'); await page.getByLabel('Fee cap (ZEC)').fill('0.00001'); await page.getByLabel('Maximum net debit, including fees (ZEC)').fill('1.00001'); await page.getByRole('dialog').getByRole('checkbox').check(); await page.getByRole('dialog').getByRole('button', { name: 'Record intent', exact: true }).click();
  await expect(page.getByRole('dialog')).toContainText('The original save outcome is uncertain'); await page.getByRole('button', { name: 'Close window', exact: true }).click(); await page.getByRole('button', { name: 'Settings', exact: true }).click(); await page.getByRole('button', { name: 'Agreements', exact: true }).click(); await page.getByRole('button', { name: /Synthetic original payment/ }).click();
  await page.getByRole('button', { name: 'Resume original contribution plan', exact: true }).click(); await expect(page.getByRole('dialog')).toContainText('Original journal revision'); await page.getByRole('button', { name: 'Retry exact original request', exact: true }).click(); await expect(page.getByText('synthetic-person', { exact: true })).toBeVisible();
  expect(f.writes).toHaveLength(2); expect(f.writes[1]).toEqual(f.writes[0]); expect(f.writes[1].revision).toBe('"1"');
});
test('planning recovery: invalid input and cancellation before dispatch do not create a retained command', async ({ page }) => {
  const f = await fixture(page, 'draft'); await fillDraft(page); await page.getByLabel('Exact recipient amount (ZEC)').fill('1e3'); await page.getByRole('button', { name: 'Save local draft' }).click(); await expect(page.getByRole('alert')).toBeVisible(); expect(f.writes).toHaveLength(0);
  await page.getByRole('button', { name: 'Cancel', exact: true }).click(); await expect(page.getByRole('button', { name: 'Resume original draft' })).toHaveCount(0); await page.getByRole('button', { name: 'Create a payment', exact: true }).click(); await expect(page.getByRole('dialog').getByRole('checkbox')).not.toBeChecked(); await expect(page.getByLabel('What are you agreeing to fund?')).toHaveValue(''); expect(f.writes).toHaveLength(0);
});
test('planning recovery: a recognized first rejection restores editable draft fields', async ({ page }) => {
  const f = await fixture(page, 'draft', 'reject'); await fillDraft(page); await page.getByRole('button', { name: 'Save local draft' }).click(); await expect(page.getByRole('alert')).toContainText('Synthetic definitive rejection'); await expect(page.getByLabel('What are you agreeing to fund?')).toBeEnabled(); await expect(page.getByRole('button', { name: 'Resume original draft' })).toHaveCount(0); expect(f.writes).toHaveLength(1);
});

test('planning recovery: completion after dismissal remains visible without blocking a new draft', async ({ page }) => {
  const f = await fixture(page, 'draft', 'success', true); await fillDraft(page); await page.getByRole('button', { name: 'Save local draft' }).click(); await expect(page.getByRole('dialog')).toContainText('The original save is in progress'); await page.getByRole('button', { name: 'Close window', exact: true }).click();
  f.release(); await expect(page.getByText('Original draft saved locally', { exact: true })).toBeVisible(); await expect(page.getByRole('button', { name: 'Create a payment', exact: true })).toBeEnabled(); await expect(page.getByRole('button', { name: 'Resume original draft' })).toHaveCount(0); expect(f.writes).toHaveLength(1);
  await page.getByRole('button', { name: 'View saved draft', exact: true }).click(); await expect(page.getByRole('heading', { name: 'Synthetic recovery draft', exact: true })).toBeVisible(); await page.getByRole('button', { name: 'Dismiss save confirmation', exact: true }).click(); await expect(page.getByText('Original draft saved locally', { exact: true })).toHaveCount(0); expect(f.writes).toHaveLength(1);
});
