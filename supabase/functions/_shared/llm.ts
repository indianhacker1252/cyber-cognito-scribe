// Centralized LLM call with concurrency limit (semaphore=5),
// automatic fallback chain (Lovable → OpenAI → Gemini → Anthropic),
// exponential backoff on rate-limit/quota/bllmerror, and output sanitization.
import { AiCreditsExhaustedError, isCreditExhaustionResponse, markCreditsExhausted, areCreditsRecentlyExhausted, checkCreditsAndFailFast } from "./ai-credits.ts";
import { sanitizeAiOutput } from "./exploit-guards.ts";

export interface LlmMessage { role: "system" | "user" | "assistant"; content: string }
export interface LlmCallOptions {
  messages: LlmMessage[];
  temperature?: number;
  maxTokens?: number;
  model?: string;
  json?: boolean;
  /**
 * Run the fallback chain under a global semaphore.
 * On throttle (429 / 503) backs off 1s,2s,4s before next provider.
 * On credit exhaustion (402 / bllmerror) marks DB and fails fast.
 */
export async function llmCall(opts: LlmCallOptions): Promise<LlmResult> {
  // Check if we are already out of credits
  if (opts.db && opts.targetId) {
    if (await areCreditsRecentlyExhausted(opts.db, opts.targetId, 10)) {
      return { ok: false, text: "", provider: "none", error: "AI credits exhausted (cached sentinel)" };
    }
  }

  // WAF hint is injected into system prompt
  const messages = opts.wafHint
    ? [{ role: "system" as const, content: opts.wafHint }, ...opts.messages]
    : opts.messages;
  const reqOpts: LlmCallOptions = { ...opts, messages };

  await acquire();
  try {
    const errors: string[] = [];
    const providers = [callLovable, callOpenAI, callGeminiDirect, callAnthropic];
    for (let i = 0; i < providers.length; i++) {
      let backoff = 1000;
      for (let attempt = 0; attempt < 3; attempt++) {
        const out = await providers[i](reqOpts);
        if (out.ok && out.text) {
          const cleaned = opts.json ? out.text : sanitizeAiOutput(out.text);
          return { ...out, text: cleaned };
        }
        
        // Detect credit exhaustion (402 or explicit bllmerror)
        const status = parseInt(out.error?.match(/\d+/)?.[0] || "0");
        const isCreditExhausted = isCreditExhaustionResponse(status, out.text) || /bllmerror/i.test(out.error || "");

        if (isCreditExhausted) {
          if (opts.db && opts.targetId) {
            await markCreditsExhausted(opts.db, { 
              targetId: opts.targetId, 
              runId: opts.runId, 
              phase: opts.phase || "llm-call",
              reason: out.error
            });
          }
          return { ok: false, text: "", provider: out.provider, error: `AI credits exhausted: ${out.error}` };
        }

        errors.push(`${out.provider}:${out.error || "empty"}`);
        if (isThrottle(out.error || "")) {
          await sleep(backoff);
          backoff *= 2;
          continue; // retry same provider
        }
        break; // non-throttle error → next provider
      }
    }
    return { ok: false, text: "", provider: "none", error: errors.join(" | ") };
  } finally {
    release();
  }
}


/** Batch helper — runs N concurrently (default 5, same as global limit). */
export async function llmCallBatch(
  items: LlmCallOptions[],
  concurrency = MAX_CONCURRENT,
): Promise<LlmResult[]> {
  const out: LlmResult[] = new Array(items.length);
  let idx = 0;
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (true) {
      const i = idx++;
      if (i >= items.length) return;
      out[i] = await llmCall(items[i]);
    }
  });
  await Promise.all(workers);
  return out;
}

/** Convenience: parse JSON from llm response. */
export function tryParseJson<T = any>(text: string): T | null {
  if (!text) return null;
  const cleaned = text.replace(/^```(?:json)?\s*/i, "").replace(/```\s*$/i, "").trim();
  try { return JSON.parse(cleaned) as T; } catch { /* ignore */ }
  const m = cleaned.match(/\{[\s\S]*\}/);
  if (m) { try { return JSON.parse(m[0]) as T; } catch { /* ignore */ } }
  return null;
}
