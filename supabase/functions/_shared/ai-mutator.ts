// AI-driven contextual payload mutation.
//
// Contract: given a target endpoint context (URL, param, method, baseline
// response snippet, tech stack, WAF hint) and a vuln class, ask the LLM to
// reason about which payload family fits and produce N novel, contextual
// mutations. The LLM is seeded with PayloadsAllTheThings entries so it
// mutates from real-world operator payloads, not from thin air.
//
// This is the "AI-as-mutator" that replaces the alternative-payload-list
// pattern the user called out: the LLM sees the actual response bytes and
// crafts mutations targeted to that context.

import { llmCall, tryParseJson } from "./llm.ts";
import { getSeedPayloads } from "./payloads-att.ts";

export interface MutationContext {
  url: string;
  method: string;
  param: string;
  vulnClass: string;                 // xss|sqli|ssti|ssrf|cmdi|lfi|xxe|nosql|openredirect|ldap|crlf
  baselineBody?: string;             // truncated body of unmodified request
  baselineStatus?: number;
  baselineHeaders?: Record<string, string>;
  reflectionContext?: string;        // where the param echoes: attr|body|script|json|none
  techStack?: string[];              // ["nginx","php","laravel"]
  wafHint?: string;                  // "cloudflare"|"akamai"|""
  previousAttempts?: { payload: string; status: number; delta: number }[];
}

export interface MutatedPayload {
  payload: string;
  rationale: string;
  expectedSignal: string;            // e.g. "500 error", "reflected literal", "delay >5s"
  confidence: number;                // LLM's own 0-1 confidence that this will fire
}

export interface MutationResult {
  ok: boolean;
  payloads: MutatedPayload[];
  provider: string;
  error?: string;
}

const MAX_SEEDS = 20;
const REQUEST_COUNT = 8;              // ask for 8 mutations per call

/** Load the top winning payload hashes for a vuln class from past runs. */
async function loadAdaptiveLessons(db: any, vulnClass: string, limit = 5): Promise<Array<{ strategy: string; notes: string }>> {
  if (!db) return [];
  try {
    const { data } = await db.from("adaptive_lessons")
      .select("strategy,notes")
      .eq("vuln_class", vulnClass)
      .eq("succeeded", true)
      .order("created_at", { ascending: false })
      .limit(limit);
    return (data || []).filter((l: any) => l.strategy || l.notes);
  } catch { return []; }
}

/** Record a mutation outcome so future runs bias toward what actually fired. */
export async function recordMutationOutcome(
  db: any,
  targetId: string,
  vulnClass: string,
  payload: string,
  succeeded: boolean,
  notes: string,
): Promise<void> {
  if (!db) return;
  try {
    const enc = new TextEncoder().encode(payload);
    const hashBuf = await crypto.subtle.digest("SHA-1", enc);
    const hash = Array.from(new Uint8Array(hashBuf)).map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 16);
    await db.from("adaptive_lessons").insert({
      target_id: targetId,
      vuln_class: vulnClass,
      strategy: payload.slice(0, 400),
      payload_hash: hash,
      succeeded,
      notes: notes.slice(0, 800),
    });
  } catch { /* non-fatal */ }
}

export async function mutateWithAi(
  ctx: MutationContext,
  db: any,
  targetId?: string,
): Promise<MutationResult> {
  const seeds = await getSeedPayloads(ctx.vulnClass, MAX_SEEDS);
  const lessons = await loadAdaptiveLessons(db, ctx.vulnClass, 5);



  const systemPrompt = `You are an elite offensive security researcher specialized in ${ctx.vulnClass.toUpperCase()} exploitation.
Your job: reason about the target's exact context, then propose ${REQUEST_COUNT} NOVEL payload mutations tailored to it.

Rules:
1. THINK about the reflection context, tech stack, and WAF BEFORE proposing payloads.
2. Do NOT copy seed payloads verbatim — mutate them for the target's exact context.
3. Every payload MUST include an "expectedSignal" the runner can automatically verify (status code, delay, literal reflection, DOM event, out-of-band callback).
4. If a WAF is present, propose evasions (case, encoding, comment injection, alternative syntax).
5. Return STRICT JSON only, matching the schema.`;

  const userPrompt = JSON.stringify({
    context: {
      url: ctx.url,
      method: ctx.method,
      param: ctx.param,
      vulnClass: ctx.vulnClass,
      reflectionContext: ctx.reflectionContext || "unknown",
      techStack: ctx.techStack || [],
      wafHint: ctx.wafHint || "",
      baselineStatus: ctx.baselineStatus,
      baselineBodySnippet: (ctx.baselineBody || "").slice(0, 1200),
      baselineHeaders: ctx.baselineHeaders || {},
      previousAttempts: (ctx.previousAttempts || []).slice(-6),
    },
    seedPayloadsFromPayloadsAllTheThings: seeds.slice(0, MAX_SEEDS),
    outputSchema: {
      payloads: [
        {
          payload: "string — the actual payload to send",
          rationale: "string — why this fits the target context",
          expectedSignal: "string — automatic verification signal",
          confidence: "number 0-1",
        },
      ],
    },
  });

  const res = await llmCall({
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: userPrompt },
    ],
    json: true,
    temperature: 0.7,
    maxTokens: 1500,
    db,
    targetId,
    phase: `ai-mutate:${ctx.vulnClass}`,
    wafHint: ctx.wafHint,
  });

  if (!res.ok) return { ok: false, payloads: [], provider: res.provider, error: res.error };
  const parsed = tryParseJson<{ payloads: MutatedPayload[] }>(res.text);
  const list = (parsed?.payloads || []).filter(
    (p) => p && typeof p.payload === "string" && p.payload.length > 0 && p.payload.length < 4096,
  );
  return { ok: true, payloads: list.slice(0, REQUEST_COUNT), provider: res.provider };
}
