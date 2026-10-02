/**
 * Commerce tester (Phase 4, AUTHORISED active tier only).
 *
 * Maps the money surface of a store and checks the class of bugs that make
 * headlines — "booked without paying" — WITHOUT ever placing an order or
 * mutating state:
 *
 *   1. Client-side price trust: price/amount/total values carried in form
 *      fields the shopper controls (hidden inputs, data attributes). If the
 *      server trusts them, checkout is negotiable. Confirming exploitation
 *      requires a state-changing request, so this module reports the surface
 *      with exact manual-verification steps instead of firing the exploit.
 *   2. Commerce endpoint map: cart / checkout / order / coupon / payment
 *      endpoints discovered on the origin, with the standard business-logic
 *      checklist (coupon reuse & stacking, negative/zero quantity, currency
 *      switching, price re-validation at payment time).
 *
 * Only GET requests are made (cart/checkout page fetches), through the
 * scope-checked, rate-limited ActiveHttpClient like every other tester.
 */
import type { ActiveHttpClient } from './httpClient';
import type { DomScanData, Finding } from '../lib/types';

let seq = 0;
const nid = (p: string) => `commerce-${p}-${seq++}`;

const PRICE_FIELD_RE = /^(price|amount|total|subtotal|grand_total|mrp|rate|cost|fee)$/i;
const COMMERCE_PATH_RE = /(cart|checkout|order|coupon|discount|promo|payment|billing|invoice|gift-?card|redeem)/i;

export interface CommerceEndpointLike {
  path: string;
  status?: number;
}

export async function testCommerce(
  http: ActiveHttpClient,
  targetUrl: string,
  dom: DomScanData,
  apiEndpoints: CommerceEndpointLike[],
): Promise<{ findings: Finding[] }> {
  const findings: Finding[] = [];
  const origin = new URL(targetUrl).origin;

  /* ---- 1. Commerce endpoint map ------------------------------------ */
  const commercePaths = new Map<string, number | undefined>();
  for (const e of apiEndpoints) {
    if (COMMERCE_PATH_RE.test(e.path)) commercePaths.set(e.path, e.status);
  }
  for (const f of dom.forms) {
    try {
      const u = new URL(f.action || targetUrl, targetUrl);
      if (u.origin === origin && COMMERCE_PATH_RE.test(u.pathname)) {
        if (!commercePaths.has(u.pathname)) commercePaths.set(u.pathname, undefined);
      }
    } catch {
      /* ignore malformed form actions */
    }
  }

  const hasCommerce = commercePaths.size > 0 || dom.forms.some((f) => COMMERCE_PATH_RE.test(f.action));
  if (!hasCommerce) return { findings };

  findings.push({
    id: nid('map'),
    category: 'commerce',
    title: `Commerce surface: ${commercePaths.size} cart/checkout/order endpoint${commercePaths.size === 1 ? '' : 's'}`,
    description:
      'Commerce endpoints discovered on this origin: ' +
      ([...commercePaths.keys()].slice(0, 25).join(', ') || '(form actions only)') +
      '. Business-logic flaws live here: verify server-side that (1) prices are recomputed ' +
      'from the catalogue at payment time, never trusted from the client; (2) coupons enforce ' +
      'single-use, per-user limits and cannot stack; (3) quantities reject zero/negative values; ' +
      '(4) the charged currency matches the displayed currency; (5) order state cannot advance ' +
      'to paid/fulfilled without a verified gateway callback.',
    severity: 'info',
    confidence: 'high',
    remediation:
      'Treat every client-supplied price, discount and quantity as hostile input; recompute totals server-side from trusted catalogue data.',
  });

  /* ---- 2. Client-side price trust in the landing DOM ---------------- */
  const priceInputs = dom.inputs.filter(
    (i) => i.hidden && PRICE_FIELD_RE.test(i.name || i.id),
  );
  for (const input of priceInputs.slice(0, 5)) {
    findings.push({
      id: nid('price-field'),
      category: 'commerce',
      title: `Client-carried price field "${input.name || input.id}"`,
      description:
        `A hidden form field named "${input.name || input.id}" carries a price-like value the ` +
        'shopper\'s browser submits. If the server uses this value instead of recomputing the ' +
        'price from its catalogue, anyone can edit it in DevTools and check out at any price — ' +
        'the classic "booked without paying" bug. BugSeek does not place orders, so confirm ' +
        'manually on an authorised test account: add an item, edit this field to 1, complete a ' +
        'TEST checkout, and see whether the charged total follows the field or the catalogue.',
      severity: 'medium',
      confidence: 'medium',
      location: targetUrl,
      evidence: `hidden input name="${input.name}" id="${input.id}" (value not captured)`,
      remediation:
        'Never accept prices from the client. Submit only product IDs and quantities; compute all amounts server-side.',
    });
  }

  /* ---- 3. Fetch cart/checkout pages (GET only) for more price fields */
  const pagePaths = [...commercePaths.keys()]
    .filter((p) => /(cart|checkout)/i.test(p))
    .slice(0, 2);
  for (const p of pagePaths) {
    try {
      const res = await http.get(origin + p);
      if (res.status !== 200 || !res.contentType.includes('html')) continue;
      const hiddenPrice = res.bodyText.match(
        /<input[^>]+type=["']hidden["'][^>]+name=["']([a-z_]*(?:price|amount|total)[a-z_]*)["']/i,
      );
      if (hiddenPrice) {
        findings.push({
          id: nid('price-page'),
          category: 'commerce',
          title: `Price field "${hiddenPrice[1]}" submitted from ${p}`,
          description:
            `The page at ${p} renders a hidden field named "${hiddenPrice[1]}". Same risk as the ` +
            'landing-page case: if checkout trusts it, totals are negotiable from DevTools. ' +
            'Verify manually with a test account and a test-mode gateway before reporting.',
          severity: 'medium',
          confidence: 'medium',
          location: origin + p,
          remediation: 'Compute totals server-side from product IDs and quantities only.',
        });
      }
      const couponField = /<input[^>]+name=["'][^"']*(coupon|promo|discount)[^"']*["']/i.test(res.bodyText);
      if (couponField) {
        findings.push({
          id: nid('coupon'),
          category: 'commerce',
          title: `Coupon field present on ${p} — check reuse & stacking`,
          description:
            `A coupon/discount field is rendered on ${p}. The profitable questions are all ` +
            'server-side: does the same code redeem twice? Stack with other codes? Apply to ' +
            'gift cards or shipping? Survive case changes (SAVE10 vs save10)? None of these can ' +
            'be answered without submitting orders, so they are listed for manual verification ' +
            'on an authorised test account.',
          severity: 'info',
          confidence: 'high',
          location: origin + p,
          remediation:
            'Enforce coupon redemption atomically server-side: one redemption per code per user, validated at payment time.',
        });
      }
    } catch {
      /* unreachable commerce page — the map finding already covers the surface */
    }
  }

  return { findings };
}
