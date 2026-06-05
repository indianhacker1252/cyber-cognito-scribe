// Centralized LLM call with automatic fallback chain.
// Order: Lovable AI Gateway → OpenAI → Gemini direct → null (caller falls back to heuristic).
// Catches 402 (credits exhausted) and 429 (rate limit) and tries the next provider.
// All successful outputs are run through `sanitizeAiOutput` so downstream
// fuzzers never see stray ```fences or leading prose (Tier 1 #3).
import { sanitizeAiOutput } from "./exploit-guards.ts";


export interface LlmMessage { role: "system" | "user" | "assistant"; content: string }

export interface LlmCallOptions {
  messages: LlmMessage[];
  temperature?: number;
  maxTokens?: number;
  /** preferred Lovable model id, e.g. "google/gemini-2.5-flash" */
  model?: string;
  /** if true, request JSON object response */
  json?: boolean;
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
    if (r.status === 402 || r.status === 429) return { ok: false, text: "", provider: "lovable", error: `HTTP ${r.status}` };
    if (!r.ok) return { ok: false, text: "", provider: "lovable", error: `HTTP ${r.status}` };
    const j = await r.json();
    return { ok: true, text: j.choices?.[0]?.message?.content || "", provider: "lovable" };
  } catch (e) { return { ok: false, text: "", provider: "lovable", error: e instanceof Error ? e.message : "err" }; }
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
    if (!r.ok) return { ok: false, text: "", provider: "openai", error: `HTTP ${r.status}` };
    const j = await r.json();
    return { ok: true, text: j.choices?.[0]?.message?.content || "", provider: "openai" };
  } catch (e) { return { ok: false, text: "", provider: "openai", error: e instanceof Error ? e.message : "err" }; }
}

async function callGeminiDirect(opts: LlmCallOptions): Promise<LlmResult> {
  if (!GEMINI_KEY) return { ok: false, text: "", provider: "gemini", error: "no key" };
  try {
    const sys = opts.messages.filter(m => m.role === "system").map(m => m.content).join("\n");
    const userParts = opts.messages.filter(m => m.role !== "system")
      .map(m => ({ role: m.role === "assistant" ? "model" : "user", parts: [{ text: m.content }] }));
    const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${GEMINI_KEY}`, {
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
    });
    if (!r.ok) return { ok: false, text: "", provider: "gemini", error: `HTTP ${r.status}` };
    const j = await r.json();
    const text = j.candidates?.[0]?.content?.parts?.map((p: any) => p.text).join("") || "";
    return { ok: true, text, provider: "gemini" };
  } catch (e) { return { ok: false, text: "", provider: "gemini", error: e instanceof Error ? e.message : "err" }; }
}

async function callAnthropic(opts: LlmCallOptions): Promise<LlmResult> {
  if (!ANTHROPIC_KEY) return { ok: false, text: "", provider: "anthropic", error: "no key" };
  try {
    const sys = opts.messages.filter(m => m.role === "system").map(m => m.content).join("\n");
    const msgs = opts.messages.filter(m => m.role !== "system");
    const r = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "x-api-key": ANTHROPIC_KEY, "anthropic-version": "2023-06-01", "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "claude-3-5-sonnet-latest",
        max_tokens: opts.maxTokens ?? 2048,
        temperature: opts.temperature ?? 0.4,
        ...(sys ? { system: sys } : {}),
        messages: msgs.map(m => ({ role: m.role, content: m.content })),
      }),
      signal: AbortSignal.timeout(30000),
    });
    if (!r.ok) return { ok: false, text: "", provider: "anthropic", error: `HTTP ${r.status}` };
    const j = await r.json();
    return { ok: true, text: j.content?.[0]?.text || "", provider: "anthropic" };
  } catch (e) { return { ok: false, text: "", provider: "anthropic", error: e instanceof Error ? e.message : "err" }; }
}

/**
 * Run the fallback chain. Returns the first successful provider's response.
 * Caller must handle ok=false (heuristic fallback).
 */
export async function llmCall(opts: LlmCallOptions): Promise<LlmResult> {
  const errors: string[] = [];
  for (const fn of [callLovable, callOpenAI, callGeminiDirect, callAnthropic]) {
    const out = await fn(opts);
    if (out.ok && out.text) {
      // T1 #3 — sanitize markdown fences / prose before returning.
      const cleaned = opts.json ? out.text : sanitizeAiOutput(out.text);
      return { ...out, text: cleaned };
    }
    errors.push(`${out.provider}:${out.error || "empty"}`);
  }
  return { ok: false, text: "", provider: "none", error: errors.join(" | ") };
}


/** Convenience: parse JSON from llm response, returns null on failure. */
export function tryParseJson<T = any>(text: string): T | null {
  if (!text) return null;
  // strip markdown code fences if present
  const cleaned = text.replace(/^```(?:json)?\s*/i, "").replace(/```\s*$/i, "").trim();
  try { return JSON.parse(cleaned) as T; } catch { /* ignore */ }
  // try extracting first {...} block
  const m = cleaned.match(/\{[\s\S]*\}/);
  if (m) { try { return JSON.parse(m[0]) as T; } catch { /* ignore */ } }
  return null;
}
