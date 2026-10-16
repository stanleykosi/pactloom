import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseZec, formatZec, zatoshis, sumZatoshis } from '../dist/index.js';
test('strict amount parsing and exact eight-place round trip', () => {
  assert.equal(parseZec('2.00006'), '200006000');
  assert.equal(formatZec('200006000', true), '2.00006000');
  assert.equal(parseZec('0.00000001'), '1');
  assert.equal(sumZatoshis(['200006000', '300009000', '500015000']), '1000030000');
  for (const bad of ['1e8', '1,2', ' 1', '1 ', '-1', '+1', '.2', '01', '1.', '0.000000001', 'NaN']) assert.throws(() => parseZec(bad));
});
test('Zcash monetary bounds match the Rust core', () => {
  assert.equal(zatoshis('2100000000000000'), '2100000000000000');
  assert.throws(() => zatoshis('2100000000000001'));
  assert.throws(() => sumZatoshis(['2100000000000000','1']));
  assert.equal(parseZec(formatZec('2100000000000000')), '2100000000000000');
});
