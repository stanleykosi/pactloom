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
const { RetainedPlanningCommand, SavedPlanningCommand, PlanningSaveNotice } = await import('../../src/planning-command.tsx');
const { beginPlanningCommand } = await import('../../src/planning-command-session.ts');
const render=(component,props)=>renderToStaticMarkup(React.createElement(component,props));
const noop=()=>{};
const command=beginPlanningCommand({}, {kind:'draft',draft:{agreement_id:'synthetic-plan',purpose:'<img src=x onerror=alert(1)>',recipients:[],funding_policy:{kind:'exact',target:'100000001'}},key:'synthetic-retry'});
test('pending recovery has an honest close label, disabled retry, and escaped exact request',()=>{
 const html=render(RetainedPlanningCommand,{command,error:'',onClose:noop,onRetry:noop});
 assert.match(html,/Closing this window does not cancel/);assert.match(html,/disabled=""[^>]*>Saving original request/);assert.match(html,/Close window/);assert.match(html,/100000001/);assert.match(html,/&lt;img/);assert.doesNotMatch(html,/<img|<script|<iframe/);
});
test('uncertain recovery enables only deliberate exact retry and explains memory lifetime',()=>{
 const html=render(RetainedPlanningCommand,{command:{...command,phase:'uncertain'},error:'Synthetic unavailable',onClose:noop,onRetry:noop});
 assert.match(html,/Retry exact original request/);assert.doesNotMatch(html,/disabled=""/);assert.match(html,/Reloading or disconnecting loses/);assert.match(html,/role="alert"/);assert.match(html,/nothing retries automatically/);
});
test('confirmed save never claims approval or available funds',()=>{
 const html=render(SavedPlanningCommand,{onClose:noop});assert.match(html,/Original save confirmed/);assert.match(html,/not payment approval/);assert.doesNotMatch(html,/Authorize|Pay now|funds reserved/);
});
test('post-dismiss completion notice binds identities and revision and provides only view/dismiss controls',()=>{
 for(const kind of ['draft','intent']){
  const resolution={key:'synthetic-key',kind,agreementId:'synthetic-agreement',...(kind==='intent'?{intentId:'synthetic-intent'}:{}),journalRevision:kind==='draft'?1:8,outcome:'saved'};
  const html=render(PlanningSaveNotice,{resolution,onView:noop,onDismiss:noop});assert.match(html,/synthetic-agreement/);assert.match(html,/journal revision/);assert.match(html,/No payment was approved/);assert.match(html,/Dismiss save confirmation/);assert.doesNotMatch(html,/Retry|Authorize|disabled/);if(kind==='intent')assert.match(html,/synthetic-intent/);
 }
});
hooks.deregister();
