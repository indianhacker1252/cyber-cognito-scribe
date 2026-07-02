// Centralized LLM call with concurrency limit (semaphore=5),
// automatic fallback chain (Lovable → OpenAI → Gemini → Anthropic),
// exponential backoff on rate-limit/quota/bllmerror, and output sanitization.
import { sanitizeAiOutput } from "./exploit-guards.ts";
import {
  AiCreditsExhaustedError,
  isCreditExhaustionResponse,
  markCreditsExhausted,
  areCreditsRecentlyExhausted,
  checkCreditsAndFailFast,
} from "./ai-credits.ts";

export interface LlmMessage {
  role: "system" | "user" | "assistant";
  content: string;
}
export interface LlmCallOptions {
  messages: LlmMessage[];
  temperature?: number;
  maxTokens?: number;
  model?: string;
  json?: boolean;
  /** Hint for WAF-aware retry — appended to system prompt automatically. */
  wafHint?: string;
  db?: any;
  targetId?: string;
  runId?: string;
  phase?: string;
  scanAiProvider?: string;
}
export interface LlmResult {
  ok: boolean;
  text: string;
  provider: string;
  error?: string;
}

const LOVABLE_KEY = Deno.env.get("LOVABLE_API_KEY");
const OPENAI_KEY = Deno.env.get("OPENAI_API_KEY");
const GEMINI_KEY = Deno.env.get("GEMINI_API_KEY");
const ANTHROPIC_KEY = Deno.env.get("ANTHROPIC_API_KEY");
const OLLAMA_BASE_URL = Deno.env.get("OLLAMA_BASE_URL");

// ───── Concurrency limiter (Part B) ─────
const MAX_CONCURRENT = 5;
let inflight = 0;
const queue: Array<() => void> = [];
async function acquire(): Promise<void> {
  if (inflight < MAX_CONCURRENT) {
    inflight++;
    return;
  }
  await new Promise<void>((res) => queue.push(res));
  inflight++;
}
function release() {
  inflight--;
  const next = queue.shift();
  if (next) next();
}

function isThrottle(s: string): boolean {
  return /rate.?limit|HTTP\s*(429|503)/i.test(s);
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function callLovable(opts: LlmCallOptions): Promise<LlmResult> {
  if (!LOVABLE_KEY) return { ok: false, text: "", provider: "lovable", error: "no key" };
  try {
    const r = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${LOVABLE_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model: opts.model || "google/gemini-2.5-flash",
        messages: opts.messages,
        temperature: opts.temperature ?? 0.4,
        ...(opts.json ? { response_format: { type: "json_object" } } : {}),
      }),
      signal: AbortSignal.timeout(30000),
    });
    if (!r.ok) {
      let b = "";
      try {
        b = await r.text();
      } catch {}
      return { ok: false, text: b, provider: "lovable", error: `HTTP ${r.status}` };
    }
    const j = await r.json();
    return { ok: true, text: j.choices?.[0]?.message?.content || "", provider: "lovable" };
  } catch (e) {
    const msg = e instanceof Error ? e.message : "err";
    return { ok: false, text: "", provider: "lovable", error: msg };
  }
}

async function callOpenAI(opts: LlmCallOptions): Promise<LlmResult> {
  if (!OPENAI_KEY) return { ok: false, text: "", provider: "openai", error: "no key" };
  try {
    const r = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${OPENAI_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "gpt-4o-mini",
        messages: opts.messages,
        temperature: opts.temperature ?? 0.4,
        max_tokens: opts.maxTokens ?? 2048,
        ...(opts.json ? { response_format: { type: "json_object" } } : {}),
      }),
      signal: AbortSignal.timeout(30000),
    });
    if (!r.ok) {
      let b = "";
      try {
        b = await r.text();
      } catch {}
      return { ok: false, text: b, provider: "openai", error: `HTTP ${r.status}` };
    }
    const j = await r.json();
    return { ok: true, text: j.choices?.[0]?.message?.content || "", provider: "openai" };
  } catch (e) {
    return { ok: false, text: "", provider: "openai", error: e instanceof Error ? e.message : "err" };
  }
}

async function callGeminiDirect(opts: LlmCallOptions): Promise<LlmResult> {
  if (!GEMINI_KEY) return { ok: false, text: "", provider: "gemini", error: "no key" };
  try {
    const sys = opts.messages
      .filter((m) => m.role === "system")
      .map((m) => m.content)
      .join("\n");
    const userParts = opts.messages
      .filter((m) => m.role !== "system")
      .map((m) => ({ role: m.role === "assistant" ? "model" : "user", parts: [{ text: m.content }] }));
    const r = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${GEMINI_KEY}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents: userParts,
          ...(sys ? { systemInstruction: { parts: [{ text: sys }] } } : {}),
          generationConfig: {
            temperature: opts.temperature ?? 0.4,
            maxOutputTokens: opts.maxTokens ?? 2048,
            ...(opts.json ? { responseMimeType: "application/json" } : {}),
          },
        }),
        signal: AbortSignal.timeout(30000),
      },
    );
    if (!r.ok) {
      let b = "";
      try {
        b = await r.text();
      } catch {}
      return { ok: false, text: b, provider: "gemini", error: `HTTP ${r.status}` };
    }
    const j = await r.json();
    const text = j.candidates?.[0]?.content?.parts?.map((p: any) => p.text).join("") || "";
    return { ok: true, text, provider: "gemini" };
  } catch (e) {
    return { ok: false, text: "", provider: "gemini", error: e instanceof Error ? e.message : "err" };
  }
}

async function callAnthropic(opts: LlmCallOptions): Promise<LlmResult> {
  if (!ANTHROPIC_KEY) return { ok: false, text: "", provider: "anthropic", error: "no key" };
  try {
    const sys = opts.messages
      .filter((m) => m.role === "system")
      .map((m) => m.content)
      .join("\n");
    const msgs = opts.messages.filter((m) => m.role !== "system");
    const r = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "x-api-key": ANTHROPIC_KEY, "anthropic-version": "2023-06-01", "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "claude-3-5-sonnet-latest",
        max_tokens: opts.maxTokens ?? 2048,
        temperature: opts.temperature ?? 0.4,
        ...(sys ? { system: sys } : {}),
        messages: msgs.map((m) => ({ role: m.role, content: m.content })),
      }),
      signal: AbortSignal.timeout(30000),
    });
    if (!r.ok) {
      let b = "";
      try {
        b = await r.text();
      } catch {}
      return { ok: false, text: b, provider: "anthropic", error: `HTTP ${r.status}` };
    }
    const j = await r.json();
    return { ok: true, text: j.content?.[0]?.text || "", provider: "anthropic" };
  } catch (e) {
    return { ok: false, text: "", provider: "anthropic", error: e instanceof Error ? e.message : "err" };
  }
}

async function loadScanAiPreference(opts: LlmCallOptions): Promise<{ provider: string; ollamaUrl?: string }> {
  const explicit = opts.scanAiProvider;
  if (explicit && explicit !== "auto") return { provider: explicit };
  if (!opts.db || !opts.targetId) return { provider: "auto" };
  try {
    const [{ data: target }, { data: ollama }] = await Promise.all([
      opts.db.from("target_workspaces").select("scan_ai_provider").eq("id", opts.targetId).maybeSingle(),
      opts.db.from("ai_provider_config").select("api_key,is_active").eq("provider", "ollama").eq("is_active", true).maybeSingle(),
    ]);
    return { provider: target?.scan_ai_provider || "auto", ollamaUrl: ollama?.api_key || OLLAMA_BASE_URL || undefined };
  } catch {
    return { provider: explicit || "auto", ollamaUrl: OLLAMA_BASE_URL || undefined };
  }
}

async function callOllama(opts: LlmCallOptions & { ollamaUrl?: string }): Promise<LlmResult> {
  const base = (opts.ollamaUrl || OLLAMA_BASE_URL || "").replace(/\/+$/, "");
  if (!base) return { ok: false, text: "", provider: "ollama", error: "no local url" };
  try {
    const r = await fetch(`${base}/chat/completions`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: opts.model || "llama3.1:8b",
        messages: opts.messages,
        temperature: opts.temperature ?? 0.4,
        max_tokens: opts.maxTokens ?? 2048,
      }),
      signal: AbortSignal.timeout(45000),
    });
    if (!r.ok) return { ok: false, text: await r.text().catch(() => ""), provider: "ollama", error: `HTTP ${r.status}` };
    const j = await r.json();
    return { ok: true, text: j.choices?.[0]?.message?.content || "", provider: "ollama" };
  } catch (e) {
    return { ok: false, text: "", provider: "ollama", error: e instanceof Error ? e.message : "err" };
  }
}

/**
 * Run the fallback chain under a global semaphore.
 * On throttle (429 / 503) backs off 1s,2s,4s before next provider.
 * On credit exhaustion (402 / bllmerror) marks DB and fails fast.
 */
export async function llmCall(opts: LlmCallOptions): Promise<LlmResult> {
  // Check if we are already out of credits
  if (opts.db && opts.targetId) {
    if (isGlobalCreditExhausted()) {
      return { ok: false, text: "", provider: "none", error: "AI credits exhausted (in-memory sentinel)" };
    }
    if (await areCreditsRecentlyExhausted(opts.db, opts.targetId, 10)) {
      setGlobalCreditExhausted(); // sync in-memory too
      return { ok: false, text: "", provider: "none", error: "AI credits exhausted (cached sentinel)" };
    }
  }

  // WAF hint is injected into system prompt
  const messages = opts.wafHint
    ? [{ role: "system" as const, content: opts.wafHint }, ...opts.messages]
    : opts.messages;
  const reqOpts: LlmCallOptions = { ...opts, messages };
  const pref = await loadScanAiPreference(reqOpts);
  if (pref.provider === "none" || pref.provider === "disabled") {
    return { ok: false, text: "", provider: "none", error: "AI disabled for this scan" };
  }

  await acquire();
  try {
    const errors: string[] = [];
    const providerMap: Record<string, (o: LlmCallOptions) => Promise<LlmResult>> = {
      auto: callLovable,
      cloud: callLovable,
      lovable: callLovable,
      openai: callOpenAI,
      gemini: callGeminiDirect,
      anthropic: callAnthropic,
      ollama: (o) => callOllama({ ...o, ollamaUrl: pref.ollamaUrl }),
      local: (o) => callOllama({ ...o, ollamaUrl: pref.ollamaUrl }),
    };
    const providers = pref.provider === "auto"
      ? [callLovable, callOpenAI, callGeminiDirect, callAnthropic, (o: LlmCallOptions) => callOllama({ ...o, ollamaUrl: pref.ollamaUrl })]
      : [providerMap[pref.provider] || callLovable];
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
        const isCreditExhausted =
          isCreditExhaustionResponse(status, out.text) ||
          /bllmerror/i.test(out.error || "") ||
          /bllmerror/i.test(out.text || "");

        if (isCreditExhausted) {
          if (opts.db && opts.targetId) {
            await markCreditsExhausted(opts.db, {
              targetId: opts.targetId,
              runId: opts.runId,
              phase: opts.phase || "llm-call",
              reason: out.error,
            });
            setGlobalCreditExhausted();
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
export async function llmCallBatch(items: LlmCallOptions[], concurrency = MAX_CONCURRENT): Promise<LlmResult[]> {
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
  const cleaned = text
    .replace(/^```(?:json)?\s*/i, "")
    .replace(/```\s*$/i, "")
    .trim();
  try {
    return JSON.parse(cleaned) as T;
  } catch {
    /* ignore */
  }
  const m = cleaned.match(/\{[\s\S]*\}/);
  if (m) {
    try {
      return JSON.parse(m[0]) as T;
    } catch {
      /* ignore */
    }
  }
  return null;
}
