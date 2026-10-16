import type { Zatoshis } from './types.js';
const UNIT = 100_000_000n;
const MAX = 2_100_000_000_000_000n;
/** Strict wire parser. Canonical values only, bounded to the Zcash monetary supply limit. */
export function zatoshis(value: string): Zatoshis {
  if (!/^(0|[1-9][0-9]*)$/.test(value) || value.length > 20 || BigInt(value) > MAX) throw new RangeError('Expected a canonical zatoshi string no larger than 21 million ZEC.');
  return value as Zatoshis;
}
/** A dot decimal is intentional. Locale separators/exponents never silently change money. */
export function parseZec(value: string): Zatoshis {
  if (!/^(0|[1-9][0-9]*)(\.[0-9]{1,8})?$/.test(value) || value.length > 30) throw new RangeError('Enter ZEC with a decimal point and up to 8 fractional digits, without separators.');
  const [whole = '0', fraction = ''] = value.split('.');
  return zatoshis((BigInt(whole) * UNIT + BigInt(fraction.padEnd(8, '0'))).toString());
}
export function formatZec(value: Zatoshis | string, exact = false): string {
  const amount = BigInt(zatoshis(value));
  const whole = amount / UNIT;
  const fraction = (amount % UNIT).toString().padStart(8, '0');
  return exact ? `${whole}.${fraction}` : `${whole}${fraction.replace(/0+$/, '') ? `.${fraction.replace(/0+$/, '')}` : ''}`;
}
export function sumZatoshis(values: readonly (Zatoshis | string)[]): Zatoshis {
  return zatoshis(values.reduce((total, value) => total + BigInt(zatoshis(value)), 0n).toString());
}
