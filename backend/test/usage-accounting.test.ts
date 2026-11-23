/* LLM token accounting tests. No live network:
   recordLlmUsage round-trips through MemoryDatabase: per-call token
   counts with the cache-read/cache-write split, provider + model + tier,
   latency and status; the opt-in wire trace (LLM_WIRE_TRACE=1) is dropped
   when the flag is off, stored redacted when on, bounded to 1 MiB per
   attempt and capped at 8 attempts retained per user. Accounting never
   throws, even when the database does. */
import { MemoryDatabase } from '../src/db/db.js';
import type { Database } from '../src/db/db.js';
import {
  LLM_WIRE_TRACE_MAX_BYTES,
  recordLlmUsage,
} from '../src/auth/usage.js';

let failures = 0;
function check(name: string, cond: boolean, extra?: unknown) {
  if (!cond) {
    failures++;
    console.error(`FAIL: ${name}`, extra ?? '');
  } else {
    console.log(`ok: ${name}`);
  }
}

async function main() {
  const savedFlag = process.env.LLM_WIRE_TRACE;
  const setFlag = (v: string | undefined) => {
    if (v === undefined) delete process.env.LLM_WIRE_TRACE;
    else process.env.LLM_WIRE_TRACE = v;
  };

  // --- 1. Routine entry with cache split round-trips. ---
  {
    const db = new MemoryDatabase();
    setFlag(undefined);
    await recordLlmUsage(db, {
      userId: 'user-1',
      provider: 'gemini',
      model: 'gemini-2.5-flash',
      tier: 'routine',
      inputTokens: 1200,
      outputTokens: 300,
      cacheReadTokens: 800,
      cacheWriteTokens: 400,
      latencyMs: 1234,
      status: 'ok',
    });
    const rows = await db.listLlmUsage('user-1', 10);
    check('one usage row recorded', rows.length === 1, rows.length);
    const r = rows[0];
    check('provider + model stored', r?.provider === 'gemini' && r?.model === 'gemini-2.5-flash', r);
    check('tier stored', r?.tier === 'routine', r?.tier);
    check('input/output tokens stored', r?.inputTokens === 1200 && r?.outputTokens === 300, r);
    check(
      'cache read/write split stored',
      r?.cacheReadTokens === 800 && r?.cacheWriteTokens === 400,
      r,
    );
    check('latency stored', r?.latencyMs === 1234, r?.latencyMs);
    check('status stored', r?.status === 'ok', r?.status);
    check('no trace rows without a trace', (await db.listLlmWireTraces('user-1', 10)).length === 0);
  }

  // --- 2. Trace dropped when the env flag is off; defaults apply. ---
  {
    const db = new MemoryDatabase();
    setFlag(undefined);
    await recordLlmUsage(db, {
      userId: 'user-2',
      provider: 'qwen',
      model: 'qwen3-coder',
      inputTokens: 10,
      outputTokens: 5,
      trace: { request: '{"model":"qwen3-coder"}', response: 'hello' },
    });
    const rows = await db.listLlmUsage('user-2', 10);
    check('usage row still recorded without trace flag', rows.length === 1, rows.length);
    check('status defaults to ok', rows[0]?.status === 'ok', rows[0]?.status);
    check('cache counts default to 0', rows[0]?.cacheReadTokens === 0 && rows[0]?.cacheWriteTokens === 0, rows[0]);
    check('trace dropped when flag is off', (await db.listLlmWireTraces('user-2', 10)).length === 0);
  }

  // --- 3. Trace stored (redacted) when the flag is on. ---
  {
    const db = new MemoryDatabase();
    setFlag('1');
    const googleKey = 'AIzaSyB1234567890abcdefghijklmnopqrstu';
    const openAiKey = 'sk-proj-abcdefghij1234567890ABCDEFGHIJ';
    const bearerKey = 'sk_live_abcdefghij1234567890';
    await recordLlmUsage(db, {
      userId: 'user-3',
      provider: 'gemini',
      model: 'gemini-2.5-pro',
      tier: 'reasoning',
      inputTokens: 50,
      outputTokens: 20,
      latencyMs: 900,
      status: 'error',
      trace: {
        request:
          `POST /v1/models/gemini-2.5-pro:generateContent\n` +
          `Authorization: Bearer ${bearerKey}\n` +
          `{"key": "${googleKey}", "prompt": "find the bug"}`,
        response: `{"text": "key was ${openAiKey} and done"}`,
      },
    });
    const traces = await db.listLlmWireTraces('user-3', 10);
    check('one trace row stored when flag is on', traces.length === 1, traces.length);
    const t = traces[0];
    check('trace links to its usage row', t?.llmUsageId === (await db.listLlmUsage('user-3', 10))[0]?.id, t);
    const bodies = `${t?.requestBody ?? ''}\n${t?.responseBody ?? ''}`;
    check('raw Google key is gone from stored trace', !bodies.includes(googleKey), bodies.slice(0, 200));
    check('raw OpenAI key is gone from stored trace', !bodies.includes(openAiKey), bodies.slice(0, 200));
    check('raw bearer key is gone from stored trace', !bodies.includes(bearerKey), bodies.slice(0, 200));
    check('no "Bearer sk-" material survives', !/Bearer\s+sk-/i.test(bodies), bodies.slice(0, 200));
    check('redaction markers present', bodies.includes('[REDACTED'), bodies.slice(0, 200));
    check('non-secret body text survives redaction', bodies.includes('find the bug'), bodies.slice(0, 200));
    const usage = await db.listLlmUsage('user-3', 10);
    check('error status round-trips', usage[0]?.status === 'error', usage[0]?.status);
    check('reasoning tier round-trips', usage[0]?.tier === 'reasoning', usage[0]?.tier);
  }

  // --- 4. Trace cap: 9 attempts in, oldest gone, 8 retained. ---
  {
    const db = new MemoryDatabase();
    setFlag('1');
    for (let i = 0; i < 9; i++) {
      await recordLlmUsage(db, {
        userId: 'user-4',
        provider: 'gemini',
        model: 'gemini-2.5-flash',
        inputTokens: 1,
        outputTokens: 1,
        trace: { request: `request-${i}`, response: `response-${i}` },
      });
    }
    const traces = await db.listLlmWireTraces('user-4', 50);
    check('cap keeps 8 traces', traces.length === 8, traces.length);
    const seen = new Set(traces.map((t) => t.requestBody));
    check('oldest trace (request-0) is gone', !seen.has('request-0'), [...seen]);
    check('newest trace (request-8) is kept', seen.has('request-8'), [...seen]);
    check('middle traces kept', seen.has('request-1') && seen.has('request-7'), [...seen]);
    check(
      'usage rows are not capped (all 9 kept)',
      (await db.listLlmUsage('user-4', 50)).length === 9,
    );
  }

  // --- 5. Per-attempt byte bound: oversized body truncated, key redacted. ---
  {
    const db = new MemoryDatabase();
    setFlag('1');
    const bigKey = `sk-${'A'.repeat(40)}`;
    const bigBody = `${bigKey}\n${'x'.repeat(LLM_WIRE_TRACE_MAX_BYTES + 100)}`;
    await recordLlmUsage(db, {
      userId: 'user-5',
      provider: 'qwen',
      model: 'qwen3-coder',
      inputTokens: 1,
      outputTokens: 1,
      trace: { request: bigBody },
    });
    const traces = await db.listLlmWireTraces('user-5', 10);
    const stored = traces[0]?.requestBody ?? '';
    check('oversized body is truncated', stored.endsWith('…[truncated]'), stored.slice(-30));
    check(
      'stored body stays near the 1 MiB cap',
      Buffer.byteLength(stored, 'utf8') <= LLM_WIRE_TRACE_MAX_BYTES + 64,
      Buffer.byteLength(stored, 'utf8'),
    );
    check('key in oversized body is redacted', !stored.includes(bigKey) && stored.includes('[REDACTED'), stored.slice(0, 80));
  }

  // --- 6. No-throw: a failing database never breaks the caller. ---
  {
    setFlag('1');
    const failingDb = {
      insertLlmUsage: async () => {
        throw new Error('boom');
      },
      insertLlmWireTrace: async () => {
        throw new Error('boom');
      },
    } as unknown as Database;
    let threw = false;
    try {
      await recordLlmUsage(failingDb, {
        provider: 'gemini',
        model: 'gemini-2.5-flash',
        inputTokens: 1,
        outputTokens: 1,
        trace: { request: 'r', response: 's' },
      });
    } catch {
      threw = true;
    }
    check('recordLlmUsage does not throw when usage insert fails', !threw);

    // Trace insert failing after a good usage insert must not throw either.
    let usageInserted = false;
    const flakyDb = {
      insertLlmUsage: async () => {
        usageInserted = true;
        return {
          id: 'u-1',
          userId: null,
          provider: 'gemini',
          model: 'gemini-2.5-flash',
          inputTokens: 1,
          outputTokens: 1,
          cacheReadTokens: 0,
          cacheWriteTokens: 0,
          status: 'ok' as const,
          createdAt: new Date().toISOString(),
        };
      },
      insertLlmWireTrace: async () => {
        throw new Error('trace boom');
      },
    } as unknown as Database;
    threw = false;
    try {
      await recordLlmUsage(flakyDb, {
        provider: 'gemini',
        model: 'gemini-2.5-flash',
        inputTokens: 1,
        outputTokens: 1,
        trace: { request: 'r' },
      });
    } catch {
      threw = true;
    }
    check('recordLlmUsage does not throw when trace insert fails', !threw && usageInserted);
  }

  // --- 7. Anonymous (no-user) entries record and list. ---
  {
    const db = new MemoryDatabase();
    setFlag(undefined);
    await recordLlmUsage(db, {
      provider: 'gemini',
      model: 'gemini-2.5-flash',
      inputTokens: 7,
      outputTokens: 3,
    });
    const rows = await db.listLlmUsage(null, 10);
    check('anonymous entry lists under null user', rows.length === 1 && rows[0]?.userId === null, rows);
  }

  setFlag(savedFlag);
  if (failures > 0) {
    console.error(`FAILED: ${failures} test(s) failed`);
    process.exit(1);
  }
  console.log('ALL USAGE ACCOUNTING TESTS PASSED');
}

main().catch((err) => {
  console.error('Test runner failed:', err);
  process.exit(1);
});
