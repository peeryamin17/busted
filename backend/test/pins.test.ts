/**
 * Unit tests for target pins + block/allow rule tables + the assessment
 * -identity header (src/guardrails/pins.ts, src/guardrails/identityHeader.ts).
 * No network, no DB, no LLM.
 *
 * Run:  npx tsx test/pins.test.ts   (from backend/)
 */
import {
  MemoryPinStore,
  checkTargetPin,
  isLocalOrPrivateHost,
  parseCidr,
  validateTargetRule,
  type TargetPin,
  type TargetRule,
} from '../src/guardrails/pins.js';
import {
  ASSESSMENT_HEADER_NAME,
  ASSESSMENT_HEADER_VALUE,
  ASSESSMENT_TASK_HEADER_NAME,
  assessmentHeaders,
} from '../src/guardrails/identityHeader.js';

let failures = 0;
function check(name: string, cond: boolean, extra?: unknown) {
  if (!cond) { failures++; console.error(`FAIL: ${name}`, extra ?? ''); }
  else console.log(`ok: ${name}`);
}

const TASK = '11111111-1111-1111-1111-111111111111';
const USER = 'user-1';

async function main() {
  const store = new MemoryPinStore();

  // ── 1. Pinned host → allowed; unpinned new host → ask ──
  {
    const pin = await store.addPin({ taskId: TASK, host: 'example.com', pinnedBy: USER });
    check('pin: records approver', pin.pinnedBy === USER, pin);
    check('pin: records time', typeof pin.pinnedAt === 'string' && !Number.isNaN(Date.parse(pin.pinnedAt)), pin);
    check('pin: canonical is host when no port', pin.canonical === 'example.com', pin);
    check('pin: active on creation', pin.active === true);

    const pins = await store.listPins(TASK);
    const gate = (host: string, port?: number | null) =>
      checkTargetPin({ taskId: TASK, host, port, pins, rules: [] });
    check('gate: pinned host → allowed', gate('example.com').decision === 'allowed');
    check('gate: pinned host case-insensitive → allowed', gate('EXAMPLE.com').decision === 'allowed');
    check('gate: unpinned new host → ask', gate('other.com').decision === 'ask');
    check('gate: ask reason names the host', gate('other.com').reason.includes('other.com'));
  }

  // ── 2. Port-specific pins ──
  {
    await store.addPin({ taskId: TASK, host: 'porty.com', port: 8443, pinnedBy: USER });
    const pins = await store.listPins(TASK);
    const gate = (host: string, port?: number | null) =>
      checkTargetPin({ taskId: TASK, host, port, pins, rules: [] });
    check('gate: port-specific pin matches its port', gate('porty.com', 8443).decision === 'allowed');
    check('gate: port-specific pin does not cover other ports', gate('porty.com', 443).decision === 'ask');
    check('gate: any-port pin covers any port', gate('example.com', 8443).decision === 'allowed');
  }

  // ── 3. Block beats allow, and block beats a pin ──
  {
    const allow = await store.addRule({
      userId: USER, taskId: TASK, kind: 'domain-suffix', pattern: 'example.com', action: 'allow', createdBy: USER,
    });
    const block = await store.addRule({
      userId: USER, taskId: TASK, kind: 'exact-host', pattern: 'evil.example.com', action: 'block', createdBy: USER,
    });
    const rules = await store.listRules(USER, TASK);
    const pins = await store.listPins(TASK);
    const gate = (host: string) => checkTargetPin({ taskId: TASK, host, pins, rules });
    check('gate: allow rule covers sibling subdomain', gate('shop.example.com').decision === 'allowed');
    check('gate: block rule beats allow rule', gate('evil.example.com').decision === 'blocked');
    // A pin on the blocked host must NOT rescue it.
    await store.addPin({ taskId: TASK, host: 'evil.example.com', pinnedBy: USER });
    const pins2 = await store.listPins(TASK);
    check(
      'gate: block rule beats a pin',
      checkTargetPin({ taskId: TASK, host: 'evil.example.com', pins: pins2, rules }).decision === 'blocked',
    );
    check('rule: allow rule stored with kind/pattern/action', allow.kind === 'domain-suffix' && allow.action === 'allow', allow);
    check('rule: block rule stored', block.action === 'block', block);
  }

  // ── 4. Domain-suffix matching ──
  {
    const rules: TargetRule[] = [{
      id: 'r1', userId: USER, taskId: null, kind: 'domain-suffix', pattern: 'example.com',
      action: 'allow', createdBy: USER, createdAt: new Date().toISOString(), active: true, deactivatedAt: null,
    }];
    const gate = (host: string) => checkTargetPin({ taskId: TASK, host, pins: [], rules });
    check('suffix: sub.example.com matches example.com', gate('sub.example.com').decision === 'allowed');
    check('suffix: example.com itself matches', gate('example.com').decision === 'allowed');
    check('suffix: evilexample.com does NOT match', gate('evilexample.com').decision === 'ask');
    check('suffix: example.com.evil.com does NOT match', gate('example.com.evil.com').decision === 'ask');
  }

  // ── 5. CIDR matching incl. /32; invalid CIDR rejected at creation ──
  {
    check('cidr: /24 parses', parseCidr('203.0.113.0/24')?.prefix === 24);
    check('cidr: /32 parses', parseCidr('203.0.113.7/32')?.prefix === 32);
    check('cidr: /7 rejected (below /8)', parseCidr('203.0.113.0/7') === null);
    check('cidr: /33 rejected', parseCidr('203.0.113.0/33') === null);
    check('cidr: non-IP rejected', parseCidr('example.com/24') === null);
    check('cidr: missing prefix rejected', parseCidr('203.0.113.0') === null);

    const rules: TargetRule[] = [{
      id: 'r2', userId: USER, taskId: null, kind: 'cidr', pattern: '203.0.113.0/24',
      action: 'allow', createdBy: USER, createdAt: new Date().toISOString(), active: true, deactivatedAt: null,
    }];
    const gate = (host: string) => checkTargetPin({ taskId: TASK, host, pins: [], rules });
    check('cidr: 203.0.113.42 inside /24 → allowed', gate('203.0.113.42').decision === 'allowed');
    check('cidr: 203.0.114.1 outside /24 → ask', gate('203.0.114.1').decision === 'ask');
    check('cidr: hostname never matches a cidr rule', gate('example.com').decision === 'ask');

    const exact: TargetRule[] = [{
      id: 'r3', userId: USER, taskId: null, kind: 'cidr', pattern: '203.0.113.7/32',
      action: 'allow', createdBy: USER, createdAt: new Date().toISOString(), active: true, deactivatedAt: null,
    }];
    const gate32 = (host: string) => checkTargetPin({ taskId: TASK, host, pins: [], rules: exact });
    check('cidr: /32 matches exactly that IP', gate32('203.0.113.7').decision === 'allowed');
    check('cidr: /32 does not match the neighbour', gate32('203.0.113.8').decision === 'ask');

    let threw = false;
    try {
      await store.addRule({ userId: USER, kind: 'cidr', pattern: 'not-a-cidr', action: 'allow', createdBy: USER });
    } catch (e) {
      threw = /invalid CIDR/.test((e as Error).message);
    }
    check('cidr: invalid CIDR rejected at rule creation', threw);
    let threw2 = false;
    try {
      validateTargetRule('cidr', '10.0.0.0/7');
    } catch {
      threw2 = true;
    }
    check('cidr: /7 rejected by validator', threw2);
  }

  // ── 6. URL-prefix rules ──
  {
    const rules: TargetRule[] = [{
      id: 'r4', userId: USER, taskId: null, kind: 'url-prefix', pattern: 'https://example.com/admin',
      action: 'allow', createdBy: USER, createdAt: new Date().toISOString(), active: true, deactivatedAt: null,
    }];
    const gate = (host: string, url?: string) => checkTargetPin({ taskId: TASK, host, url, pins: [], rules });
    check('url-prefix: matching prefix → allowed', gate('example.com', 'https://example.com/admin/panel').decision === 'allowed');
    check('url-prefix: different path → ask', gate('example.com', 'https://example.com/shop').decision === 'ask');
    check('url-prefix: no url supplied → cannot match → ask', gate('example.com').decision === 'ask');
  }

  // ── 7. Localhost / private → blocked (second line, no DNS) ──
  {
    for (const h of ['localhost', 'app.local', '127.0.0.1', '127.5.6.7', '10.1.2.3', '172.16.0.9', '172.31.255.255', '192.168.1.1', '::1', '::ffff:127.0.0.1']) {
      check(`private: ${h} → blocked`, isLocalOrPrivateHost(h));
      check(
        `gate: ${h} → blocked even when pinned`,
        checkTargetPin({ taskId: TASK, host: h, pins: [makePin(h)], rules: [] }).decision === 'blocked',
      );
    }
    check('private: public IP is not private', !isLocalOrPrivateHost('8.8.8.8'));
    check('private: public hostname is not private', !isLocalOrPrivateHost('example.com'));
    check('private: 172.15.x is public', !isLocalOrPrivateHost('172.15.0.1'));
    check('private: 172.32.x is public', !isLocalOrPrivateHost('172.32.0.1'));
    check('private: ::ffff:8.8.8.8 is public', !isLocalOrPrivateHost('::ffff:8.8.8.8'));
  }

  // ── 8. Deactivating a pin returns the host to ask; unpin never deletes ──
  {
    const before = await store.listPins(TASK, { includeInactive: true });
    const removed = await store.deactivatePin(TASK, 'example.com');
    check('unpin: deactivating returns the pin, now inactive', removed !== null && removed.active === false, removed);
    check('unpin: deactivatedAt stamped', removed !== null && typeof removed.deactivatedAt === 'string', removed);
    const pins = await store.listPins(TASK);
    check(
      'gate: deactivated pin → ask again',
      checkTargetPin({ taskId: TASK, host: 'example.com', pins, rules: [] }).decision === 'ask',
    );
    const history = await store.listPins(TASK, { includeInactive: true });
    check('unpin: history still holds the pin', history.length === before.length, { before: before.length, after: history.length });
    check('unpin: history shows it inactive', history.some((p) => p.host === 'example.com' && !p.active));
    check('unpin: deactivating again → null', (await store.deactivatePin(TASK, 'example.com')) === null);
    // Re-pinning after unpin creates a fresh active pin; the old row stays.
    const repin = await store.addPin({ taskId: TASK, host: 'example.com', pinnedBy: USER });
    check('repin: new active pin after unpin', repin.active === true && repin.id !== removed!.id);
    const history2 = await store.listPins(TASK, { includeInactive: true });
    check('repin: old inactive row still in history', history2.filter((p) => p.host === 'example.com').length === 2);
  }

  // ── 9. Rules: user-wide vs task-scoped, remove deactivates ──
  {
    const wide = await store.addRule({
      userId: USER, kind: 'exact-host', pattern: 'wide.example.com', action: 'allow', createdBy: USER,
    });
    check('rule: user-wide rule has null taskId', wide.taskId === null, wide);
    const scoped = await store.listRules(USER, TASK);
    check('rule: user-wide rule visible from a task', scoped.some((r) => r.id === wide.id));
    const removed = await store.removeRule(wide.id, USER);
    check('rule: remove deactivates, never deletes', removed !== null && removed.active === false, removed);
    const after = await store.listRules(USER, TASK);
    check('rule: removed rule no longer active-listed', !after.some((r) => r.id === wide.id));
    const history = await store.listRules(USER, TASK, { includeInactive: true });
    check('rule: removed rule still in history', history.some((r) => r.id === wide.id && !r.active));
    check('rule: removing another user\'s rule → null', (await store.removeRule(wide.id, 'user-2')) === null);
  }

  // ── 10. Gate with a Set of canonical pins ──
  {
    const gate = (host: string) =>
      checkTargetPin({ taskId: TASK, host, pins: new Set(['example.com', 'api.example.com:8443']), rules: [] });
    check('gate(set): canonical host → allowed', gate('example.com').decision === 'allowed');
    check('gate(set): unlisted host → ask', gate('other.com').decision === 'ask');
  }

  // ── 11. Assessment-identity header ──
  {
    const withTask = assessmentHeaders(TASK);
    check('identity: two headers with a task id', Object.keys(withTask).length === 2, withTask);
    check('identity: version header is 1.0', withTask[ASSESSMENT_HEADER_NAME] === ASSESSMENT_HEADER_VALUE);
    check('identity: task header carries the task id', withTask[ASSESSMENT_TASK_HEADER_NAME] === TASK);
    const withoutTask = assessmentHeaders();
    check('identity: exactly one header without a task id', Object.keys(withoutTask).length === 1, withoutTask);
    check('identity: the one header is the version marker', withoutTask[ASSESSMENT_HEADER_NAME] === '1.0');
    const allValues = [...Object.values(withTask), ...Object.values(withoutTask)].join(' ');
    check('identity: no user-identifying value anywhere', !/user|email|@|scan/i.test(allValues), allValues);
    check('identity: header names are the documented ones', ASSESSMENT_HEADER_NAME === 'BugSeek-Assessment' && ASSESSMENT_TASK_HEADER_NAME === 'BugSeek-Assessment-Task');
  }

  if (failures > 0) { console.error(`${failures} pin test(s) failed`); process.exit(1); }
  console.log('ALL PIN TESTS PASSED');
  process.exit(0);
}

function makePin(host: string): TargetPin {
  return {
    id: 'pin-test', taskId: TASK, host, port: null, pinnedBy: USER,
    pinnedAt: new Date().toISOString(), active: true, deactivatedAt: null, canonical: host,
  };
}

main().catch((e) => { console.error('pins test crashed', e); process.exit(1); });
