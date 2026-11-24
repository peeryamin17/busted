import { GeminiProvider, isTextGenerationModel } from '../src/llm/gemini.js';

let failures = 0;
function check(name: string, ok: boolean, extra?: unknown) {
  if (ok) console.log('PASS', name);
  else {
    failures++;
    console.error('FAIL', name, extra ?? '');
  }
}

async function main() {
  const originalFetch = globalThis.fetch;

  try {
    // 0. Model name filtering tests
    check('identifies standard text model', isTextGenerationModel('gemini-2.0-flash'));
    check('identifies gemini-2.5-flash as text model', isTextGenerationModel('gemini-2.5-flash'));
    check('filters out tts models', !isTextGenerationModel('gemini-2.5-flash-preview-tts'));
    check('filters out audio models', !isTextGenerationModel('gemini-1.5-flash-audio'));
    check('filters out embedding models', !isTextGenerationModel('text-embedding-004'));
    check('filters out imagen models', !isTextGenerationModel('imagen-3.0-generate-002'));

    // 1. Discovery and caching test
    GeminiProvider.resetModelCache();
    let fetchCalls: Array<{ url: string; options: any }> = [];

    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      fetchCalls.push({ url, options: init });
      if (url.endsWith('/v1beta/models')) {
        return new Response(
          JSON.stringify({
            models: [
              {
                name: 'models/gemini-2.5-flash-preview-tts',
                supportedGenerationMethods: ['generateContent'],
              },
              {
                name: 'models/gemini-2.0-flash',
                supportedGenerationMethods: ['generateContent', 'countTokens'],
              },
              {
                name: 'models/gemini-1.5-pro-latest',
                supportedGenerationMethods: ['generateContent'],
              },
              {
                name: 'models/text-embedding-004',
                supportedGenerationMethods: ['embedContent'],
              },
            ],
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }
      return new Response('Not Found', { status: 404 });
    }) as typeof fetch;

    const provider = new GeminiProvider('test-api-key-12345');
    const available = await provider.getAvailableModels();
    check('discovers models supporting generateContent', available.length === 2);
    check('strips models/ prefix', available.includes('gemini-2.0-flash'));
    check('discovery sends the key in a header, never in the URL', !fetchCalls[0].url.includes('key=') && (fetchCalls[0].options?.headers as Record<string, string>)?.['x-goog-api-key'] === 'test-api-key-12345', fetchCalls[0]);
    check('filters out tts model despite generateContent capability', !available.includes('gemini-2.5-flash-preview-tts'));
    check('filters out models without generateContent', !available.includes('text-embedding-004'));

    // Verify caching (second call shouldn't call fetch again)
    const callCountBefore = fetchCalls.length;
    const cached = await provider.getAvailableModels();
    check('uses cached models without repeating network fetch', fetchCalls.length === callCountBefore && cached.length === 2);

    // 2. Candidate resolution
    const routineCandidates = provider.getCandidateModels('routine', available);
    check('selects gemini-2.0-flash as top candidate for routine', routineCandidates[0] === 'gemini-2.0-flash');

    const reasoningCandidates = provider.getCandidateModels('reasoning', available);
    check('candidates contain gemini-1.5-pro-latest for reasoning', reasoningCandidates.includes('gemini-1.5-pro-latest'));

    // 3. Fallback on 404 simulation
    GeminiProvider.resetModelCache();
    fetchCalls = [];

    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      fetchCalls.push({ url, options: init });

      if (url.endsWith('/v1beta/models')) {
        return new Response('{}', { status: 200 });
      }

      // Simulate 404 on gemini-1.5-flash
      if (url.includes('gemini-1.5-flash')) {
        return new Response(
          JSON.stringify({
            error: {
              code: 404,
              message:
                'models/gemini-1.5-flash is not found for API version v1beta, or is not supported for generateContent.',
              status: 'NOT_FOUND',
            },
          }),
          { status: 404, headers: { 'content-type': 'application/json' } }
        );
      }

      // Simulate 200 on gemini-2.0-flash
      if (url.includes('gemini-2.0-flash')) {
        return new Response(
          JSON.stringify({
            candidates: [
              {
                content: {
                  parts: [{ text: 'Vulnerability analysis complete: 0 findings.' }],
                },
                finishReason: 'STOP',
              },
            ],
            usageMetadata: {
              promptTokenCount: 120,
              candidatesTokenCount: 45,
            },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }

      return new Response('Not Found', { status: 404 });
    }) as typeof fetch;

    const fallbackProvider = new GeminiProvider('test-api-key-12345', 'gemini-1.5-flash');
    const result = await fallbackProvider.complete({
      messages: [{ role: 'user', content: 'Test prompt' }],
      tier: 'routine',
    });

    check('successfully completes despite primary model 404', result.text.includes('Vulnerability analysis complete'));
    check('tracks input tokens correctly', result.usage.inputTokens === 120);
    check('tracks output tokens correctly', result.usage.outputTokens === 45);

    // 4. Modality 400 error auto-cascade test (exact error user encountered)
    GeminiProvider.resetModelCache();
    fetchCalls = [];

    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      fetchCalls.push({ url, options: init });

      if (url.includes('gemini-2.5-flash-preview-tts')) {
        return new Response(
          JSON.stringify({
            error: {
              code: 400,
              message:
                'The requested combination of response modalities (TEXT) is not supported by the model. models/gemini-2.5-flash-preview-tts accepts the following combination of response modalities:\n* AUDIO\n',
              status: 'INVALID_ARGUMENT',
            },
          }),
          { status: 400, headers: { 'content-type': 'application/json' } }
        );
      }

      if (url.includes('gemini-2.0-flash')) {
        return new Response(
          JSON.stringify({
            candidates: [
              {
                content: {
                  parts: [{ text: 'Taint engine verification ok.' }],
                },
                finishReason: 'STOP',
              },
            ],
            usageMetadata: {
              promptTokenCount: 200,
              candidatesTokenCount: 50,
            },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }

      return new Response('Not Found', { status: 404 });
    }) as typeof fetch;

    const ttsProvider = new GeminiProvider('test-api-key-12345', 'gemini-2.5-flash-preview-tts');
    const ttsResult = await ttsProvider.complete({
      messages: [{ role: 'user', content: 'Scan analysis' }],
      tier: 'routine',
    });
    check('auto-cascades past 400 audio-only modality error to working text model', ttsResult.text.includes('Taint engine verification ok.'));

    // 5. Non-modality 401 Unauthorized fails fast
    globalThis.fetch = (async () => {
      return new Response(
        JSON.stringify({
          error: {
            code: 401,
            message: 'API key not valid. Please pass a valid API key.',
            status: 'UNAUTHENTICATED',
          },
        }),
        { status: 401, headers: { 'content-type': 'application/json' } }
      );
    }) as typeof fetch;

    let failedFast = false;
    try {
      const failingProvider = new GeminiProvider('invalid-key');
      await failingProvider.complete({
        messages: [{ role: 'user', content: 'Test prompt' }],
      });
    } catch (err: any) {
      if (err.message.includes('401') && err.message.includes('API key not valid')) {
        failedFast = true;
      }
    }
    check('fails fast on 401 error without cycling models', failedFast);

    // 6. Timeout on the first candidate cascades to the next model instead of failing the call
    GeminiProvider.resetModelCache();
    fetchCalls = [];
    let sawTimeoutModel = false;
    let sawFallbackModel = false;

    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      fetchCalls.push({ url, options: init });

      if (url.includes('/models?key=')) {
        return new Response(
          JSON.stringify({
            models: [
              { name: 'models/gemini-2.0-flash', supportedGenerationMethods: ['generateContent'] },
              { name: 'models/gemini-1.5-pro-latest', supportedGenerationMethods: ['generateContent'] },
            ],
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }

      // First candidate hangs: AbortSignal.timeout fires a TimeoutError
      if (url.includes('gemini-2.0-flash')) {
        sawTimeoutModel = true;
        throw new DOMException('The operation timed out.', 'TimeoutError');
      }

      if (url.includes('gemini-1.5-pro-latest')) {
        sawFallbackModel = true;
        return new Response(
          JSON.stringify({
            candidates: [
              {
                content: { parts: [{ text: 'Cascade after timeout ok.' }] },
                finishReason: 'STOP',
              },
            ],
            usageMetadata: { promptTokenCount: 90, candidatesTokenCount: 20 },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } }
        );
      }

      return new Response('Not Found', { status: 404 });
    }) as typeof fetch;

    const timeoutProvider = new GeminiProvider('test-api-key-timeout');
    const timeoutResult = await timeoutProvider.complete({
      messages: [{ role: 'user', content: 'Scan analysis' }],
      tier: 'routine',
    });
    check('cascades past a timed-out model to the next candidate', timeoutResult.text.includes('Cascade after timeout ok.'));
    check('tried the timed-out model first', sawTimeoutModel);
    check('reached the fallback model', sawFallbackModel);

    // 7. 503 on the reasoning model falls back to the worker (flash) model
    // in the same call instead of hard-failing Recon planning.
    GeminiProvider.resetModelCache();
    const downgradeUrls: string[] = [];
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      downgradeUrls.push(url);
      if (url.endsWith('/v1beta/models')) {
        return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
      }
      if (url.includes('gemini-2.5-pro')) {
        return new Response(
          JSON.stringify({ error: { code: 503, message: 'The model is overloaded. Please try again later.', status: 'UNAVAILABLE' } }),
          { status: 503, headers: { 'content-type': 'application/json' } },
        );
      }
      if (url.includes('gemini-2.5-flash')) {
        return new Response(
          JSON.stringify({
            candidates: [{ content: { parts: [{ text: 'Flash fallback ok.' }] }, finishReason: 'STOP' }],
            usageMetadata: { promptTokenCount: 40, candidatesTokenCount: 9 },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      return new Response('Not Found', { status: 404 });
    }) as typeof fetch;
    const downgradeProvider = new GeminiProvider('test-' + 'x'.repeat(20), 'gemini-2.5-flash', 'gemini-2.5-pro');
    const downgradeResult = await downgradeProvider.complete({
      messages: [{ role: 'user', content: 'Reasoning task' }],
      tier: 'reasoning',
    });
    check('503 on pro falls back to flash in the same call', downgradeResult.text.includes('Flash fallback ok.'));
    check('downgrade tried the pro model first', downgradeUrls.some((u) => u.includes('gemini-2.5-pro')), downgradeUrls);
    check('downgrade reached the flash model', downgradeUrls.some((u) => u.includes('gemini-2.5-flash')), downgradeUrls);
    check('downgrade tags the completion with the flash model', downgradeResult.model === 'gemini-2.5-flash', downgradeResult.model);

    // 7b. 429 on the reasoning model is downgrade-eligible too.
    GeminiProvider.resetModelCache();
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith('/v1beta/models')) {
        return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
      }
      if (url.includes('gemini-2.5-pro')) {
        return new Response(
          JSON.stringify({ error: { code: 429, message: 'Resource exhausted.', status: 'RESOURCE_EXHAUSTED' } }),
          { status: 429, headers: { 'content-type': 'application/json' } },
        );
      }
      if (url.includes('gemini-2.5-flash')) {
        return new Response(
          JSON.stringify({
            candidates: [{ content: { parts: [{ text: 'Flash after 429 ok.' }] }, finishReason: 'STOP' }],
            usageMetadata: { promptTokenCount: 40, candidatesTokenCount: 9 },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      return new Response('Not Found', { status: 404 });
    }) as typeof fetch;
    const downgrade429Provider = new GeminiProvider('test-' + 'y'.repeat(20), 'gemini-2.5-flash', 'gemini-2.5-pro');
    const downgrade429Result = await downgrade429Provider.complete({
      messages: [{ role: 'user', content: 'Reasoning task' }],
      tier: 'reasoning',
    });
    check('429 on pro falls back to flash in the same call', downgrade429Result.text.includes('Flash after 429 ok.'));

    // 8. 503 on every model fails loudly, never a fake success.
    GeminiProvider.resetModelCache();
    const all503Urls: string[] = [];
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      all503Urls.push(url);
      if (url.endsWith('/v1beta/models')) {
        return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
      }
      return new Response(
        JSON.stringify({ error: { code: 503, message: 'The model is overloaded. Please try again later.', status: 'UNAVAILABLE' } }),
        { status: 503, headers: { 'content-type': 'application/json' } },
      );
    }) as typeof fetch;
    const all503Provider = new GeminiProvider('test-' + 'z'.repeat(20), 'gemini-2.5-flash', 'gemini-2.5-pro');
    let loud503 = '';
    try {
      await all503Provider.complete({
        messages: [{ role: 'user', content: 'Reasoning task' }],
        tier: 'reasoning',
      });
    } catch (err) {
      loud503 = (err as Error).message;
    }
    check('503 on all models fails loudly', loud503.includes('503'), loud503);
    check('503 on all models still tried the flash fallback', all503Urls.some((u) => u.includes('gemini-2.5-flash')), all503Urls);

    // 9. Worker tier 503 does not escalate flash back up to pro.
    GeminiProvider.resetModelCache();
    const worker503Urls: string[] = [];
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      const url = String(input);
      worker503Urls.push(url);
      if (url.endsWith('/v1beta/models')) {
        return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
      }
      if (url.includes('gemini-2.5-flash')) {
        return new Response(
          JSON.stringify({ error: { code: 503, message: 'The model is overloaded.', status: 'UNAVAILABLE' } }),
          { status: 503, headers: { 'content-type': 'application/json' } },
        );
      }
      if (url.includes('gemini-2.5-pro')) {
        return new Response(
          JSON.stringify({
            candidates: [{ content: { parts: [{ text: 'Pro trap — must not be reached.' }] }, finishReason: 'STOP' }],
            usageMetadata: { promptTokenCount: 1, candidatesTokenCount: 1 },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      return new Response('Not Found', { status: 404 });
    }) as typeof fetch;
    const worker503Provider = new GeminiProvider('test-' + 'w'.repeat(20), 'gemini-2.5-flash', 'gemini-2.5-pro');
    let worker503Err = '';
    try {
      await worker503Provider.complete({
        messages: [{ role: 'user', content: 'Routine task' }],
        tier: 'routine',
      });
    } catch (err) {
      worker503Err = (err as Error).message;
    }
    check('worker tier 503 fails loudly', worker503Err.includes('503'), worker503Err);
    check('worker tier 503 never escalates flash to pro', !worker503Urls.some((u) => u.includes('gemini-2.5-pro')), worker503Urls);

  } finally {
    globalThis.fetch = originalFetch;
  }

  if (failures > 0) {
    console.error(`\nFAILED: ${failures} checks failed in gemini.test.ts`);
    process.exit(1);
  } else {
    console.log('\nALL GEMINI PROVIDER TESTS PASSED.');
  }
}

main().catch((err) => {
  console.error('Unhandled test failure:', err);
  process.exit(1);
});
