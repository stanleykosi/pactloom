/** Pure React server rendering only. No browser, listener, provider or financial runtime. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { registerHooks } from 'node:module';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
const sourceRoot = new URL('../../src/', import.meta.url).href;
const hooks = registerHooks({
  resolve(specifier, context, next) {
    if (specifier.startsWith('.') && context.parentURL?.startsWith(sourceRoot) && !/\.[a-z]+$/.test(specifier)) {
      for (const suffix of ['.ts', '.tsx']) { const url = new URL(specifier + suffix, context.parentURL); if (existsSync(url)) return { url: url.href, shortCircuit: true }; }
    }
    return next(specifier, context);
  },
  load(url, context, next) {
    if (url.startsWith(sourceRoot) && url.endsWith('.tsx')) return { format: 'module', shortCircuit: true, source: ts.transpileModule(readFileSync(fileURLToPath(url), 'utf8'), { compilerOptions: { jsx: ts.JsxEmit.ReactJSX, module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } }).outputText };
    return next(url, context);
  },
});
const { PaymentStart, PaymentJourney, PaymentObservationDetails } = await import('../../src/payment-journey.tsx');
const { CreateAgreement, ReviewAgreement } = await import('../../src/agreements.tsx');
const draft = { schema_version: 1, agreement_id: 'synthetic-plan', obligation_id: 'synthetic-obligation', revision: 1, purpose: 'Synthetic plan', organizer_identity: 'synthetic-organizer', network_profile_id: 'synthetic-only', recipients: [{ recipient_id: 'synthetic-recipient', address: '<img src=x onerror=alert(1)>', amount: '100000001', instruction_provenance: 'Synthetic unverified instructions' }], funding_policy: { kind: 'exact', target: '100000001' }, fee_policy: { kind: 'pro_rata' }, privacy_profile: { mode: 'local_only', dedicated_accounts_required: true, proving_operator: null }, confirmation_policy: { required_confirmations: 10 }, extensions: [] };
const view = { agreement: draft, revision: 1, progress: 'draft', cancellation_requested: false, authorization_exposure: 'unknown', chain_observation: 'unknown', intents: [], proposals: [], candidates: [], verification_reports: [] };
const noop = () => {};
const render = (component, props) => renderToStaticMarkup(React.createElement(component, props));

test('guided start renders a labeled journey and truthful unavailable action', () => {
  const html = render(PaymentStart, { onCreate: noop, allowed: false, reason: 'Synthetic service unavailable' });
  assert.match(html, /aria-label="Shared payment journey"/); assert.match(html, /disabled=""[^>]*>Create a payment/); assert.match(html, /Nothing|local planning/); assert.match(html, /signing and payment remain unavailable/); assert.doesNotMatch(html, /<img|<iframe|<script/);
});
test('guided unknown exposure is not payment readiness and ungranted contribution remains disabled', () => {
  const html = render(PaymentJourney, { view, capabilities: null, permissions: ['read'], stale: false, onReview: noop, onIntent: noop });
  assert.match(html, /Check what may still spend/); assert.match(html, /1\.00000001/); assert.match(html, /disabled=""[^>]*>Add my contribution plan/); assert.match(html, /Signing is unavailable in this client/); assert.doesNotMatch(html, /Ready to pay|Payment complete|Funds locked/);
});
test('status provenance remains unknown without evidence and actual observations are historical', () => {
  assert.match(render(PaymentObservationDetails, { view }), /No observation source, synchronized chain height/);
  const html = render(PaymentObservationDetails, { view: { ...view, observations: [{ observation_id: 'synthetic-observation', source_id: '<script>unsafe</script>', synchronized: true, observed_at: '2026-10-16T10:00:00Z', tip_height: 123, confirmations: 3 }] } });
  assert.match(html, /current freshness not established/); assert.match(html, /3 \/ 10 required/); assert.doesNotMatch(html, /<script>/); assert.match(html, /&lt;script&gt;/);
});
test('terms review keeps recipient text inert; source discloses advanced tools and focus destinations', () => {
  const html = render(ReviewAgreement, { agreement: view, onClose: noop });
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/); assert.doesNotMatch(html, /<img/);
  const source = readFileSync(new URL('../../src/agreements.tsx', import.meta.url), 'utf8');
  assert.match(source, /<details className="advanced-preparation">/); assert.doesNotMatch(source, /<details className="advanced-preparation" open/); assert.match(source, /id="payment-status"[^>]*tabIndex=\{-1\}/); assert.match(source, /id="private-messages"[^>]*tabIndex=\{-1\}/);
});
test('new draft fields and submit are disabled when capability or freshness is missing', () => {
  const html = render(CreateAgreement, { client: {}, capabilities: null, create: { allowed: false, reason: 'Synthetic stale context' }, onClose: noop, onCreated: noop });
  assert.equal((html.match(/<fieldset disabled=""/g) ?? []).length, 3); assert.match(html, /disabled=""[^>]*>Save local draft/); assert.match(html, /Synthetic stale context/); assert.doesNotMatch(html, /checked=""/);
});
process.on('exit', () => hooks.deregister());
