import { QwenProvider, FailoverProvider, isTextGenerationModel } from '../src/llm/qwen.js';
import { GeminiProvider } from '../src/llm/gemini.js';
import { MockProvider } from '../src/llm/mock.js';

let failures = 0;
function check(name: string, ok: boolean, extra?: unknown) {
  if (ok) console.log('PASS', name);
  else {
    failures++;
    console.error('FAIL', name, extra ?? '');
  }
}

const BASE = 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1';

function chatOk(text: string, usage?: Record<string, unknown>) {
  return new Response(
    JSON.stringify({
      choices: [{ message: { role: 'assistant', content: text }, finish_reason: 'stop' }],
      usage: usage ?? { prompt_tokens: 100, completion_tokens: 25, total_tokens: 125 },
    }),
    { status: 200, headers: { 'content-type': 'application/json' } }
  );
}

async function main() {
  const originalFetch = globalThis.fetch;

  try {
    // 0. Model name filtering tests
    check('identifies qwen3.8-flash as text model', isTextGenerationModel('qwen3.8-flash'));
    check('identifies qwen3.7-plus as text model', isTextGenerationModel('qwen3.7-plus'));
    check('identifies qwen3-coder-flash as text model', isTextGenerationModel('qwen3-coder-flash'));
    check('filters out embedding models', !isTextGenerationModel('text-embedding-v3'));
    check('filters out tts models', !isTextGenerationModel('qwen-tts'));
    check('filters out audio models', !isTextGenerationModel('qwen-audio-turbo'));
    check('filters out image models', !isTextGenerationModel('qwen-image-plus'));
    check('filters out vl models', !isTextGenerationModel('qwen-vl-max'));
    check('filters out omni models', !isTextGenerationModel('qwen-omni-turbo'));
    check('filters out rerank models', !isTextGenerationModel('qwen-rerank'));
    check('filters out transcription models', !isTextGenerationModel('qwen-transcription'));

    // 1. GET /models discovery parses and filters non-text models
    QwenProvider.resetModelCache();
    let fetchCalls: Array<{ url: string; options: any }> = [];

    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      fetchCalls.push({ url, options: init });
      if (url === `${BASE}/models`) {
        return new Response(
          JSON.stringify({
            data: [
              { id: 'qwen3.8-flash' },
              { id: 'qwen3.7-plus' },
              { id: 'qwen3-coder-flash' },
              { id: 'qwen3.8-max' },
              { id: 'text-embedding-v3' },
              { id: 'qwen-vl-max' },
              { id: 'qwen-tts' },
            ],
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }
      return new Response('Not Found', { status: 404 });
    }) as typeof fetch;

    const provider = new QwenProvider('test-qwen-key-12345');
    const available = await provider.getAvailableModels();
    check('discovers text models from GET /models', available.length === 4);
    check('discovery keeps qwen3.8-flash', available.includes('qwen3.8-flash'));
    check('discovery keeps qwen3-coder-flash', available.includes('qwen3-coder-flash'));
    check('discovery filters out embedding model', !available.includes('text-embedding-v3'));
    check('discovery filters out vl model', !available.includes('qwen-vl-max'));
    check('discovery filters out tts model', !available.includes('qwen-tts'));

    // Verify caching (second call shouldn't call fetch again)
    const callCountBefore = fetchCalls.length;
    const cached = await provider.getAvailableModels();
    check('uses cached models without repeating network fetch', fetchCalls.length === callCountBefore && cached.length === 4);

    // 2. Candidate resolution per tier
    const routineCandidates = provider.getCandidateModels('routine', available);
    check('selects qwen3.8-flash as top candidate for routine', routineCandidates[0] === 'qwen3.8-flash');

    const reasoningCandidates = provider.getCandidateModels('reasoning', available);
    check('selects qwen3.7-plus as top candidate for reasoning', reasoningCandidates[0] === 'qwen3.7-plus');
    check('reasoning pool escalates to qwen3.8-max after plus', reasoningCandidates.includes('qwen3.8-max'));

    const codeCandidates = provider.getCandidateModels('code', available);
    check('selects qwen3.7-plus first for code', codeCandidates[0] === 'qwen3.7-plus');
    check('code pool includes qwen3-coder-flash when discovered', codeCandidates.includes('qwen3-coder-flash'));
    check('code pool escalates to qwen3.8-max', codeCandidates.includes('qwen3.8-max'));

    // 3. Timeout on first candidate cascades to the next candidate
    QwenProvider.resetModelCache();
    fetchCalls = [];
    let sawTimeoutModel = false;
    let sawFallbackModel = false;
    let chatCalls = 0;

    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      fetchCalls.push({ url, options: init });

      if (url === `${BASE}/models`) {
        return new Response(
          JSON.stringify({
            data: [
              { id: 'qwen3.8-flash' },
              { id: 'qwen3.7-plus' },
            ],
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }

      if (url === `${BASE}/chat/completions`) {
        const body = JSON.parse(String((init as any)?.body ?? '{}'));
        chatCalls++;
        // First candidate hangs: AbortSignal.timeout fires a TimeoutError
        if (body.model === 'qwen3.8-flash') {
          sawTimeoutModel = true;
          throw new DOMException('The operation timed out.', 'TimeoutError');
        }
        if (body.model === 'qwen3.7-plus') {
          sawFallbackModel = true;
          return chatOk('Cascade after timeout ok.', { prompt_tokens: 90, completion_tokens: 20 });
        }
      }

      return new Response('Not Found', { status: 404 });
    }) as typeof fetch;

    const timeoutProvider = new QwenProvider('test-qwen-key-timeout');
    const timeoutResult = await timeoutProvider.complete({
      messages: [{ role: 'user', content: 'Scan analysis' }],
      tier: 'routine',
    });
    check('cascades past a timed-out model to the next candidate', timeoutResult.text.includes('Cascade after timeout ok.'));
    check('tried the timed-out model first', sawTimeoutModel);
    check('reached the fallback model', sawFallbackModel);
    check('timed-out model was NOT retried on the same endpoint', chatCalls === 2);

    // 4. 429 backs off then succeeds on the same candidate
    QwenProvider.resetModelCache();
    let attempts429 = 0;

    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === `${BASE}/models`) {
        return new Response(JSON.stringify({ data: [{ id: 'qwen3.8-flash' }] }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      if (url === `${BASE}/chat/completions`) {
        attempts429++;
        if (attempts429 === 1) {
          return new Response(JSON.stringify({ error: { message: 'Rate limit exceeded' } }), {
            status: 429,
            headers: { 'content-type': 'application/json' },
          });
        }
        return chatOk('Recovered after 429.');
      }
      return new Response('Not Found', { status: 404 });
    }) as typeof fetch;

    const retryProvider = new QwenProvider('test-qwen-key-429');
    const retryResult = await retryProvider.complete({
      messages: [{ role: 'user', content: 'Scan analysis' }],
      tier: 'routine',
    });
    check('429 backs off then succeeds', retryResult.text.includes('Recovered after 429.'));
    check('429 retried exactly once', attempts429 === 2);

    // 5. 401 fails fast without cascading
    QwenProvider.resetModelCache();
    let calls401 = 0;

    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === `${BASE}/models`) {
        return new Response(JSON.stringify({ data: [{ id: 'qwen3.8-flash' }] }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      if (url === `${BASE}/chat/completions`) {
        calls401++;
        return new Response(
          JSON.stringify({ error: { code: 'invalid_api_key', message: 'Incorrect API key provided.' } }),
          { status: 401, headers: { 'content-type': 'application/json' } }
        );
      }
      return new Response('Not Found', { status: 404 });
    }) as typeof fetch;

    let failedFast = false;
    try {
      const failingProvider = new QwenProvider('invalid-qwen-key');
      await failingProvider.complete({
        messages: [{ role: 'user', content: 'Test prompt' }],
      });
    } catch (err: any) {
      if (err.message.includes('401') && err.message.includes('Incorrect API key')) {
        failedFast = true;
      }
    }
    check('fails fast on 401 error without cycling models', failedFast);
    check('401 made exactly one chat call', calls401 === 1);

    // 6. Usage parsing incl. cached_tokens -> cacheReadTokens
    QwenProvider.resetModelCache();

    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === `${BASE}/models`) {
        return new Response(JSON.stringify({ data: [{ id: 'qwen3.8-flash' }] }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      if (url === `${BASE}/chat/completions`) {
        return chatOk('Usage parse ok.', {
          prompt_tokens: 1000,
          completion_tokens: 50,
          prompt_tokens_details: { cached_tokens: 800 },
        });
      }
      return new Response('Not Found', { status: 404 });
    }) as typeof fetch;

    const usageProvider = new QwenProvider('test-qwen-key-usage');
    const usageResult = await usageProvider.complete({
      messages: [{ role: 'user', content: 'Test prompt' }],
    });
    check('tracks input tokens correctly', usageResult.usage.inputTokens === 1000);
    check('tracks output tokens correctly', usageResult.usage.outputTokens === 50);
    check('parses cached_tokens into cacheReadTokens', usageResult.usage.cacheReadTokens === 800);

    // 7. Static fallback catalog used when discovery returns nothing
    QwenProvider.resetModelCache();

    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === `${BASE}/models`) {
        return new Response(JSON.stringify({ data: [] }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      if (url === `${BASE}/chat/completions`) {
        const body = JSON.parse(String((init as any)?.body ?? '{}'));
        if (body.model === 'qwen3.8-flash') {
          return chatOk('Fallback catalog ok.');
        }
      }
      return new Response('Not Found', { status: 404 });
    }) as typeof fetch;

    const fallbackProvider = new QwenProvider('test-qwen-key-fallback');
    const fallbackResult = await fallbackProvider.complete({
      messages: [{ role: 'user', content: 'Test prompt' }],
      tier: 'routine',
    });
    check('completes via static fallback catalog when discovery is empty', fallbackResult.text.includes('Fallback catalog ok.'));
    check('fallback catalog excludes retired qwen3-coder-plus', !QwenProvider.fallbackCatalog().includes('qwen3-coder-plus'));

    // 8. FailoverProvider falls through to Gemini on Qwen 429/timeout
    QwenProvider.resetModelCache();
    GeminiProvider.resetModelCache();

    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url === `${BASE}/models`) {
        return new Response(JSON.stringify({ data: [{ id: 'qwen3.8-flash' }] }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      if (url === `${BASE}/chat/completions`) {
        // Qwen is rate-limited twice (both postWithRetry attempts), then the
        // provider exhausts its candidates and throws.
        return new Response(JSON.stringify({ error: { message: 'Rate limit exceeded' } }), {
          status: 429,
          headers: { 'content-type': 'application/json' },
        });
      }
      if (url.includes('generativelanguage.googleapis.com/v1beta/models?key=')) {
        return new Response(
          JSON.stringify({
            models: [
              { name: 'models/gemini-2.0-flash', supportedGenerationMethods: ['generateContent'] },
            ],
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }
      if (url.includes('generativelanguage.googleapis.com') && url.includes('gemini-2.0-flash')) {
        return new Response(
          JSON.stringify({
            candidates: [
              {
                content: { parts: [{ text: 'Gemini failover ok.' }] },
                finishReason: 'STOP',
              },
            ],
            usageMetadata: { promptTokenCount: 70, candidatesTokenCount: 15 },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }
      return new Response('Not Found', { status: 404 });
    }) as typeof fetch;

    const qwen = new QwenProvider('test-qwen-key-failover');
    const gemini = new GeminiProvider('test-gemini-key-failover');
    const failover = new FailoverProvider([qwen, gemini]);
    const failoverResult = await failover.complete({
      messages: [{ role: 'user', content: 'Scan analysis' }],
      tier: 'routine',
    });
    check('failover falls through to Gemini on Qwen 429', failoverResult.text.includes('Gemini failover ok.'));
    check('failover result tracks Gemini tokens', failoverResult.usage.inputTokens === 70);

    // 9. FailoverProvider does NOT fall through on a 400 invalid-request
    let secondProviderCalled = false;
    const badRequestProvider = {
      name: 'bad-request',
      async complete() {
        const err = new Error('Qwen API error 400: invalid request: bad model param');
        (err as any).status = 400;
        throw err;
      },
    };
    const neverCalled = new MockProvider();
    const origMockComplete = neverCalled.complete.bind(neverCalled);
    neverCalled.complete = async (req: any) => {
      secondProviderCalled = true;
      return origMockComplete(req);
    };
    const failover400 = new FailoverProvider([badRequestProvider as any, neverCalled]);
    let threw400 = false;
    try {
      await failover400.complete({ messages: [{ role: 'user', content: 'x' }] });
    } catch (err: any) {
      threw400 = err?.status === 400;
    }
    check('failover does not fall through on 400 invalid-request', threw400 && !secondProviderCalled);
  } finally {
    globalThis.fetch = originalFetch;
  }

  if (failures > 0) {
    console.error(`\nFAILED: ${failures} checks failed in qwen.test.ts`);
    process.exit(1);
  } else {
    console.log('\nALL QWEN PROVIDER TESTS PASSED.');
  }
}

main().catch((err) => {
  console.error('Unhandled test failure:', err);
  process.exit(1);
});
