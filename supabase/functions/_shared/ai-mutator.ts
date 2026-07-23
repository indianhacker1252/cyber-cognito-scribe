// AI-driven contextual payload mutation with UCB1 lesson selection.
//
// Pass E upgrades:
//  - Lessons keyed by (vuln_class, context_hash) so we don't blindly re-use
//    an XSS bypass from a Cloudflare-fronted PHP app on a static Nginx site.
//  - UCB1 scoring balances exploration (untested contexts) vs exploitation
//    (proven-winner payload strategies).
//  - FAILED mutations are also recorded so the prompt shrinks its search
//    space instead of re-proposing dead payloads.

import { llmCall, tryParseJson } from "./llm.ts";
import { getSeedPayloads } from "./payloads-att.ts";

export interface MutationContext {
  url: string;
  method: string;
  param: string;
  vulnClass: string;
  baselineBody?: string;
  baselineStatus?: number;
  baselineHeaders?: Record<string, string>;
  reflectionContext?: string;
  techStack?: string[];
  wafHint?: string;
  previousAttempts?: { payload: string; status: number; delta: number }[];
}

export interface MutatedPayload {
  payload: string;
  rationale: string;
  expectedSignal: string;
  confidence: number;
}

export interface MutationResult {
  ok: boolean;
  payloads: MutatedPayload[];
  provider: string;
  contextHash: string;
  error?: string;
}

const MAX_SEEDS = 20;
const REQUEST_COUNT = 8;

/** Stable context hash: waf + top tech + param class. Small enough to bucket well. */
export function contextHashFor(ctx: MutationContext): string {
  const waf = (ctx.wafHint || "none").toLowerCase();
  const tech = (ctx.techStack || []).slice(0, 3).join(",").toLowerCase() || "unknown";
  const paramKind = /id$|_id$|uuid/i.test(ctx.param) ? "id"
    : /email|mail/i.test(ctx.param) ? "email"
    : /url|redirect|next|return/i.test(ctx.param) ? "url"
    : /file|path|dir/i.test(ctx.param) ? "path"
    : /q|query|search|s$/i.test(ctx.param) ? "search"
    : "generic";
  return `${waf}|${tech}|${paramKind}`;
}

interface Lesson {
  strategy: string;
  notes: string;
  succeeded_count: number;
  attempt_count: number;
}

/** UCB1: score = win_rate + sqrt(2 * ln(totalTrials) / thisTrials).
 *  Balances proven winners with exploration of under-tried strategies. */
function ucb1Pick(lessons: Lesson[], k: number): Lesson[] {
  if (lessons.length === 0) return [];
  const totalTrials = lessons.reduce((s, l) => s + Math.max(1, l.attempt_count), 0);
  const scored = lessons.map((l) => {
    const trials = Math.max(1, l.attempt_count);
    const wins = Math.max(0, l.succeeded_count);
    const winRate = wins / trials;
    const explore = Math.sqrt((2 * Math.log(Math.max(2, totalTrials))) / trials);
    return { l, score: winRate + explore };
  });
  scored.sort((a, b) => b.score - a.score);
  return scored.slice(0, k).map((s) => s.l);
}

async function loadContextualLessons(
  db: any, vulnClass: string, contextHash: string, limit = 8,
): Promise<{ winners: Lesson[]; losers: Lesson[] }> {
  if (!db) return { winners: [], losers: [] };
  try {
    // Prefer exact context matches; fall back to class-wide.
    const { data: exact } = await db.from("adaptive_lessons")
      .select("strategy,notes,succeeded_count,attempt_count,succeeded")
      .eq("vuln_class", vulnClass)
      .eq("context_hash", contextHash)
      .order("created_at", { ascending: false })
      .limit(40);
    let rows = exact || [];
    if (rows.length < 4) {
      const { data: fallback } = await db.from("adaptive_lessons")
        .select("strategy,notes,succeeded_count,attempt_count,succeeded")
        .eq("vuln_class", vulnClass)
        .order("created_at", { ascending: false })
        .limit(40);
      rows = [...rows, ...(fallback || [])];
    }
    const winners = ucb1Pick(rows.filter((r: any) => (r.succeeded_count ?? (r.succeeded ? 1 : 0)) > 0), limit);
    const losers = rows.filter((r: any) => (r.succeeded_count ?? (r.succeeded ? 1 : 0)) === 0 && (r.attempt_count ?? 1) >= 2)
      .slice(0, 5);
    return { winners, losers };
  } catch { return { winners: [], losers: [] }; }
}

/** Record mutation outcome. Aggregates succeeded_count/attempt_count on the
 *  same (target, class, context, payload_hash) tuple for UCB1 stats. */
export async function recordMutationOutcome(
  db: any,
  targetId: string,
  vulnClass: string,
  payload: string,
  succeeded: boolean,
  notes: string,
  contextHash?: string,
): Promise<void> {
  if (!db) return;
  try {
    const enc = new TextEncoder().encode(payload);
    const hashBuf = await crypto.subtle.digest("SHA-1", enc);
    const hash = Array.from(new Uint8Array(hashBuf)).map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 16);
    // Try to update an existing row for this exact tuple, else insert.
    const { data: existing } = await db.from("adaptive_lessons")
      .select("id,attempt_count,succeeded_count")
      .eq("target_id", targetId).eq("vuln_class", vulnClass).eq("payload_hash", hash)
      .maybeSingle();
    if (existing?.id) {
      await db.from("adaptive_lessons").update({
        attempt_count: (existing.attempt_count || 0) + 1,
        succeeded_count: (existing.succeeded_count || 0) + (succeeded ? 1 : 0),
        succeeded: succeeded || (existing.succeeded_count > 0),
        context_hash: contextHash || null,
        notes: notes.slice(0, 800),
      }).eq("id", existing.id);
    } else {
      await db.from("adaptive_lessons").insert({
        target_id: targetId, vuln_class: vulnClass,
        strategy: payload.slice(0, 400), payload_hash: hash,
        succeeded, notes: notes.slice(0, 800),
        context_hash: contextHash || null,
        attempt_count: 1, succeeded_count: succeeded ? 1 : 0,
      });
    }
  } catch { /* non-fatal */ }
}

export async function mutateWithAi(
  ctx: MutationContext, db: any, targetId?: string,
): Promise<MutationResult> {
  const contextHash = contextHashFor(ctx);
  const seeds = await getSeedPayloads(ctx.vulnClass, MAX_SEEDS);
  const { winners, losers } = await loadContextualLessons(db, ctx.vulnClass, contextHash, 6);

  const systemPrompt = `You are an elite offensive security researcher specialized in ${ctx.vulnClass.toUpperCase()} exploitation.
Your job: reason about the target's exact context, then propose ${REQUEST_COUNT} NOVEL payload mutations tailored to it.

Rules:
1. THINK about the reflection context, tech stack, and WAF BEFORE proposing payloads.
2. Do NOT copy seed payloads verbatim — mutate them for the target's exact context.
3. Every payload MUST include an "expectedSignal" the runner can automatically verify.
4. If a WAF is present, propose evasions (case, encoding, comment injection, alternative syntax).
5. AVOID any payload that resembles the "knownFailedStrategies" — they've already been tried and failed on THIS context.
6. PREFER structural variations of "provenWinnerStrategies" that fit this context.
7. Return STRICT JSON only.`;

  const userPrompt = JSON.stringify({
    context: {
      url: ctx.url, method: ctx.method, param: ctx.param,
      vulnClass: ctx.vulnClass, contextHash,
      reflectionContext: ctx.reflectionContext || "unknown",
      techStack: ctx.techStack || [], wafHint: ctx.wafHint || "",
      baselineStatus: ctx.baselineStatus,
      baselineBodySnippet: (ctx.baselineBody || "").slice(0, 1200),
      baselineHeaders: ctx.baselineHeaders || {},
      previousAttempts: (ctx.previousAttempts || []).slice(-6),
    },
    seedPayloadsFromPayloadsAllTheThings: seeds.slice(0, MAX_SEEDS),
    provenWinnerStrategies: winners.map((w) => ({ strategy: w.strategy, notes: w.notes, winRate: w.attempt_count > 0 ? w.succeeded_count / w.attempt_count : 0 })),
    knownFailedStrategies: losers.map((l) => l.strategy),
    outputSchema: {
      payloads: [{ payload: "string", rationale: "string", expectedSignal: "string", confidence: "0-1 number" }],
    },
  });

  const res = await llmCall({
    messages: [{ role: "system", content: systemPrompt }, { role: "user", content: userPrompt }],
    json: true, temperature: 0.7, maxTokens: 1500,
    db, targetId, phase: `ai-mutate:${ctx.vulnClass}`, wafHint: ctx.wafHint,
  });

  if (!res.ok) return { ok: false, payloads: [], provider: res.provider, contextHash, error: res.error };
  const parsed = tryParseJson<{ payloads: MutatedPayload[] }>(res.text);
  const list = (parsed?.payloads || []).filter(
    (p) => p && typeof p.payload === "string" && p.payload.length > 0 && p.payload.length < 4096,
  );
  return { ok: true, payloads: list.slice(0, REQUEST_COUNT), provider: res.provider, contextHash };
}
