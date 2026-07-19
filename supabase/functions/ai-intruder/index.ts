// AI Intruder — Burp-Intruder style, but the payload generator is the LLM.
//
// Flow per endpoint × param × vuln class:
//   1. GET/POST baseline (unmodified param).
//   2. Ask ai-mutator for N contextual payloads (seeded from PayloadsAllTheThings,
//      informed by baseline body + tech stack + WAF).
//   3. Fire each payload; capture status/length/snippet + heuristic exec signals.
//   4. Feed baseline + mutated + exec evidence into scoreConfidence.
//   5. Only findings that reach mayPromote() (score >= 85 with real execution
//      evidence) are written via recordFinding — the writer will re-score, but
//      pre-filtering saves credits and log noise.
//
// This is the module that operationalizes: AI mutation, AI confidence gating,
// PayloadsAllTheThings seeds, request/response tampering.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { safeFetch } from "../_shared/safe-fetch.ts";
import { mutateWithAi, type MutationContext } from "../_shared/ai-mutator.ts";
import { scoreConfidence, mayPromote } from "../_shared/ai-confidence.ts";
import { recordFinding } from "../_shared/findings-writer.ts";
import { detectWaf } from "../_shared/waf-detect.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

interface Body {
  targetId: string;
  url: string;
  method?: string;
  params?: string[]; // if omitted, auto-derive from URL query
  vulnClasses?: string[]; // defaults to a curated set
  maxPayloadsPerClass?: number;
}

const DEFAULT_CLASSES = ["xss", "sqli", "ssti", "ssrf", "cmdi", "openredirect"];

function buildMutatedUrl(url: string, param: string, payload: string): string {
  const u = new URL(url);
  u.searchParams.set(param, payload);
  return u.toString();
}

async function fire(url: string, method: string) {
  const t0 = Date.now();
  const r = await safeFetch(url, { method, timeoutMs: 8000 });
  if (!r) return null;
  const body = (await r.text().catch(() => "")) || "";
  const hdrs: Record<string, string> = {};
  r.headers.forEach((v, k) => { hdrs[k] = v; });
  return {
    status: r.status,
    length: body.length,
    snippet: body.slice(0, 2000),
    headers: hdrs,
    elapsedMs: Date.now() - t0,
  };
}

function detectReflectionContext(body: string, payload: string): string {
  if (!body || !payload) return "none";
  const marker = payload.slice(0, Math.min(payload.length, 20));
  if (!body.includes(marker)) return "none";
  const idx = body.indexOf(marker);
  const before = body.slice(Math.max(0, idx - 60), idx).toLowerCase();
  if (before.includes("<script")) return "script";
  if (/=\s*["']?$/.test(before)) return "attr";
  if (before.includes("{") && before.includes(":")) return "json";
  return "body";
}

function execEvidence(baseline: any, mutated: any, payload: string) {
  const ev: any = {};
  // Timing (blind SQLi/SSRF)
  if (mutated.elapsedMs > baseline.elapsedMs + 4500) ev.timeDelayMs = mutated.elapsedMs - baseline.elapsedMs;
  // DB error strings
  const dbErr = /sql syntax|mysql_fetch|ora-\d{5}|pg_query|sqlite_error|syntax error at or near/i.exec(mutated.snippet);
  if (dbErr) ev.dbError = dbErr[0];
  // Open redirect via Location header
  const loc = mutated.headers["location"] || mutated.headers["Location"];
  if (loc && /^(https?:)?\/\/(evil|attacker|127\.0\.0\.1|localhost)/i.test(loc)) ev.openRedirect = loc;
  // Reflection (needed but not sufficient for XSS)
  if (mutated.snippet.includes(payload.slice(0, 20))) ev.reflected = true;
  return ev;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  const ok = (b: any) => new Response(JSON.stringify(b), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });

  try {
    const body = await req.json() as Body;
    if (!body?.targetId || !body?.url) return ok({ ok: false, error: "targetId+url required" });

    const supa = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
    const method = (body.method || "GET").toUpperCase();
    const classes = body.vulnClasses?.length ? body.vulnClasses : DEFAULT_CLASSES;
    const maxN = Math.min(body.maxPayloadsPerClass ?? 6, 12);

    // Derive params
    const u = new URL(body.url);
    const params = body.params?.length ? body.params : Array.from(u.searchParams.keys());
    if (!params.length) return ok({ ok: true, note: "no params to test", url: body.url });

    // Target tech + WAF
    const { data: tw } = await supa.from("target_workspaces").select("detected_tech").eq("id", body.targetId).maybeSingle();
    const techStack = tw?.detected_tech ? (Array.isArray(tw.detected_tech) ? tw.detected_tech : Object.keys(tw.detected_tech as any)) : [];
    const wafInfo = await detectWaf(body.url).catch(() => ({ vendor: null as string | null }));
    const wafHint = ((wafInfo as any)?.vendor || "").toString();

    await supa.from("scan_logs").insert({
      target_id: body.targetId, log_type: "action",
      message: `🤖 AI Intruder started: ${method} ${u.pathname} params=[${params.join(",")}] classes=[${classes.join(",")}]`,
      metadata: { tech: techStack, waf: wafHint },
    });

    let promoted = 0, rejected = 0, tested = 0;

    for (const param of params) {
      // Baseline once per param
      const baseUrl = buildMutatedUrl(body.url, param, "canary_" + Math.random().toString(36).slice(2, 8));
      const baseline = await fire(baseUrl, method);
      if (!baseline) continue;

      for (const vulnClass of classes) {
        const mctx: MutationContext = {
          url: body.url, method, param, vulnClass,
          baselineBody: baseline.snippet, baselineStatus: baseline.status,
          baselineHeaders: baseline.headers,
          reflectionContext: detectReflectionContext(baseline.snippet, "canary_"),
          techStack, wafHint,
        };
        const mut = await mutateWithAi(mctx, supa, body.targetId);
        if (!mut.ok || !mut.payloads.length) {
          await supa.from("scan_logs").insert({
            target_id: body.targetId, log_type: "info",
            message: `🤖 AI mutator returned 0 payloads for ${vulnClass} on ${param} (${mut.error || mut.provider})`,
          });
          continue;
        }

        for (const p of mut.payloads.slice(0, maxN)) {
          tested++;
          const mutUrl = buildMutatedUrl(body.url, param, p.payload);
          const mutated = await fire(mutUrl, method);
          if (!mutated) continue;

          const execEv = execEvidence(baseline, mutated, p.payload);
          const conf = await scoreConfidence({
            vulnClass, payload: p.payload,
            baseline: { status: baseline.status, length: baseline.length, snippet: baseline.snippet, headers: baseline.headers },
            mutated: { status: mutated.status, length: mutated.length, snippet: mutated.snippet, headers: mutated.headers },
            executionEvidence: execEv,
            differentialContext: `expected=${p.expectedSignal}; rationale=${p.rationale}`,
          }, supa, body.targetId);

          if (!mayPromote(conf)) {
            rejected++;
            continue;
          }

          const sev = conf.confidenceScore >= 95 ? "high" : conf.confidenceScore >= 90 ? "medium" : "low";
          const res = await recordFinding({
            targetId: body.targetId,
            source: "ai-intruder",
            vulnClass,
            severity: sev as any,
            title: `${vulnClass.toUpperCase()} confirmed by AI Intruder on ${param}`,
            description: `${p.rationale}\nExpected: ${p.expectedSignal}\nAI verdict: ${conf.verdict} (${conf.confidenceScore})\n${conf.reasoning}`,
            payload: p.payload,
            proofTier: conf.confidenceScore >= 90 ? "exploited" : "reflected",
            evidence: { execution: execEv, baseline, mutated, ai_confidence: conf },
            request: { method, url: mutUrl },
            response: { status: mutated.status, headers: mutated.headers, body: mutated.snippet },
          });
          if (res.ok && !res.duplicate) promoted++;
        }
      }
    }

    await supa.from("scan_logs").insert({
      target_id: body.targetId, log_type: promoted ? "result" : "info",
      message: `🤖 AI Intruder finished: tested=${tested} promoted=${promoted} rejected_low_confidence=${rejected}`,
      metadata: { url: body.url, params, classes, waf: wafHint },
    });

    return ok({ ok: true, tested, promoted, rejected });
  } catch (e) {
    return ok({ ok: false, error: e instanceof Error ? e.message : "err" });
  }
});
