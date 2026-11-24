import { test } from 'node:test';
import assert from 'node:assert/strict';
import { pricingCtaHref } from './pricing.ts';

test('pricing CTA stays in-app and lands on the download section', () => {
  assert.equal(pricingCtaHref(), '/app#download');
  assert.doesNotMatch(pricingCtaHref(), /\?plan=/);
});
