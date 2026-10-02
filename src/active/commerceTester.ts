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

export interface CommerceTrafficLike {
  url: string;
  paramNames: string[];
}

export async function testCommerce(
  http: ActiveHttpClient,
  targetUrl: string,
  dom: DomScanData,
  apiEndpoints: CommerceEndpointLike[],
  traffic: CommerceTrafficLike[] = [],
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
      'to paid/fulfilled without a verified gateway callback; (6) payment RETURN URLs are ' +
      'verified against the gateway server-side and consumed exactly once — replaying a success ' +
      'return (e.g. after cancelling a second payment) must never fulfil an order; (7) a payment ' +
      'token is bound to one order and one amount and is burned on first use — one successful ' +
      'payment must never settle a second order; (8) redemption/payment endpoints are atomic ' +
      'under concurrency — two simultaneous submits of the same payment or coupon must not ' +
      'double-spend it (race condition).',
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

  /* ---- 4. Payment replay & reuse surface --------------------------- */
  // The "pay once, redeem forever" family: payment identifiers that travel
  // in URLs, bearer payment links, and long-lived payment cookies. All
  // three make a payment token replayable; whether the server burns tokens
  // after first use can only be proven with live orders (manual steps).
  const PAY_PARAM_RE = /(payment|txn|transaction|checkout|session|token|razorpay|paytm|order_?id)/i;
  const seenPayParams = new Map<string, string>(); // param name -> example path
  const urlsToScan = [
    ...traffic.map((t) => t.url),
    ...apiEndpoints.map((e) => origin + e.path),
    ...dom.forms.map((f) => f.action),
  ];
  for (const raw of urlsToScan) {
    try {
      const u = new URL(raw, targetUrl);
      if (u.origin !== origin) continue;
      for (const name of u.searchParams.keys()) {
        if (PAY_PARAM_RE.test(name) && !seenPayParams.has(name)) {
          seenPayParams.set(name, u.pathname);
        }
      }
      if (/\/cs_(live|test)_/.test(u.pathname) && !seenPayParams.has('stripe-session-in-path')) {
        seenPayParams.set('stripe-session-in-path', u.pathname);
      }
    } catch {
      /* malformed URL — skip */
    }
  }
  for (const [name, path] of [...seenPayParams.entries()].slice(0, 6)) {
    findings.push({
      id: nid('pay-param'),
      category: 'commerce',
      title: `Payment identifier "${name}" travels in URLs (seen on ${path})`,
      description:
        `A payment-related identifier ("${name}") is carried as a URL parameter on ${path}. URLs get ` +
        'logged by servers, proxies, analytics and browser history, and anyone holding the link may ' +
        'be able to replay it. The questions that decide whether this is a vulnerability are all ' +
        'server-side and need a test account + test-mode gateway: (1) pay once, capture the success ' +
        'return/callback URL, then CANCEL a second payment at the gateway and replay the first ' +
        'success URL against the second order — if it fulfils, the return handler trusts the ' +
        'browser instead of verifying with the gateway; (2) submit the SAME payment token against ' +
        'a second order — it must be rejected as already consumed; (3) fire the redeem/pay request ' +
        'twice in parallel — exactly one may succeed (idempotency / race protection).',
      severity: 'medium',
      confidence: 'medium',
      location: origin + path,
      evidence: `parameter name "${name}" on ${path} (values are never recorded)`,
      remediation:
        'Bind every payment token server-side to one order + one amount, burn it on first use, verify gateway callbacks by signature AND a server-to-server status check, and make state transitions idempotent.',
    });
  }

  const orderPay = urlsToScan.find((u) => /\/order-pay\/\d+/i.test(u));
  if (orderPay) {
    findings.push({
      id: nid('order-pay'),
      category: 'commerce',
      title: 'Bearer payment link (order-pay) detected',
      description:
        'A /checkout/order-pay/<id>/ style link is in use: the URL itself is the credential — ' +
        'whoever holds it can view and pay the order, no login required. That is safe ONLY if the ' +
        'accompanying key is long, random, single-order, and expires. Verify manually: open the ' +
        'link logged-out (should work — that is by design), then check whether the order id alone ' +
        '(incrementing/decrementing it) or a missing/short key still renders an order, and whether ' +
        'the link keeps working after the order is paid or cancelled.',
      severity: 'medium',
      confidence: 'medium',
      location: targetUrl,
      remediation:
        'Use 128-bit+ random keys on payment links, expire them on payment/cancellation, and never let the numeric order id act as an authenticator.',
    });
  }

  try {
    const cookies = await chrome.cookies.getAll({ url: targetUrl });
    const now = Date.now() / 1000;
    const longLived = cookies.filter(
      (c) =>
        /(pay|checkout|order|wc_|woocommerce|cart)/i.test(c.name) &&
        !c.session &&
        c.expirationDate !== undefined &&
        c.expirationDate - now > 7 * 24 * 3600,
    );
    if (longLived.length > 0) {
      findings.push({
        id: nid('pay-cookie'),
        category: 'commerce',
        title: `Long-lived payment/cart cookies: ${longLived.map((c) => c.name).join(', ')}`,
        description:
          'Payment- or cart-related cookies persist for more than a week: ' +
          longLived
            .map((c) => `${c.name} (~${Math.round(((c.expirationDate ?? now) - now) / 86400)} days)`)
            .join(', ') +
          '. Long-lived client-side payment state is replay material — if any of these cookies ' +
          'influences what an order costs or whether it counts as paid, a saved copy can be ' +
          'replayed after cancellation or refund. Verify the server treats cookies as hints ' +
          'only and re-derives all payment state from its own records.',
        severity: 'low',
        confidence: 'medium',
        location: targetUrl,
        evidence: 'cookie names + lifetimes only (values never captured)',
        remediation: 'Keep payment state server-side; cookies should carry at most an opaque, expiring cart reference.',
      });
    }
  } catch {
    /* cookies API unavailable in this context — surface checks above still apply */
  }

  return { findings };
}
