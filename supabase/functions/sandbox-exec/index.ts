// Sandbox Exec — runs an exploit/validation payload in isolation.
// Strategy: try user's docker worker (if active) → fall back to edge-function
// simulated sandbox (safeFetch with strict allowlist + recorded evidence).
//
// Every edge-mode run loads the per-target SESSION JAR (cookies, JWT, CSRF,
// sticky headers) and replays it on the outbound request — and harvests
// fresh Set-Cookie / Bearer / CSRF tokens from the response so the NEXT
// attempt continues the same session. This makes multi-step exploit chains
// (login → IDOR → admin) work without re-authenticating each time.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { safeFetch } from "../_shared/safe-fetch.ts";
import { applyJar, harvestAndPersist, loadJar } from "../_shared/session-jar.ts";
import {
  sanitizeAiOutput,
  getBaseline,
  isGhostBaseline,
  hostOf,
  isDeadHost,
  noteStatusZero,
  noteStatusOk,
  calculateVerdict,
} from "../_shared/exploit-guards.ts";


const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};
function db() { return createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!); }

interface Body {
  findingId?: string;
  targetId: string;
  script: string;
  language?: "curl" | "python" | "bash";
  mode?: "auto" | "worker" | "edge";
  targetUrl?: string;        // explicit fallback when script lacks a URL
}

async function runViaWorker(cfg: any, payload: any, timeoutMs = 45000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    // T2 #8 — pass TARGET_URL + outbound flag so the container script can fire at the real host.
    const enriched = {
      ...payload,
      env: { ...(payload.env || {}), TARGET_URL: payload.targetUrl || "", CYBERSCOPE_ALLOW_NET: "1" },
      network: "host",
      allow_outbound: true,
    };
    const r = await fetch(`${(cfg.endpoint_url as string).replace(/\/$/,"")}/sandbox`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(cfg.auth_token ? { "Authorization": `Bearer ${cfg.auth_token}` } : {}),
      },
      body: JSON.stringify(enriched),
      signal: ctrl.signal,
    });
    const text = await r.text();
    let data: any = text; try { data = JSON.parse(text); } catch {}
    return { ok: r.ok, status: r.status, data };
  } catch (e) {
    return { ok: false, status: 0, data: { error: e instanceof Error ? e.message : "err" } };
  } finally { clearTimeout(t); }
}


async function runViaEdge(
  script: string,
  language: string,
  fallbackUrl: string | undefined,
  supa: any,
  targetId: string,
) {
  // Edge fallback can't exec arbitrary code. We parse the script to extract a
  // single curl/HTTP call and execute it via safeFetch, recording the response.
  const lines = script.split(/\r?\n/);
  const evidence: any = { method: "GET", url: null, status: null, length: null, snippet: "" };
  let url: string | null = null;
  let method = "GET";
  let body: string | undefined;
  const headers: Record<string, string> = {};

  for (const line of lines) {
    const m = line.match(/curl\s+(?:-X\s+(\w+)\s+)?["']?(https?:\/\/[^"'\s]+)["']?/);
    if (m) { method = m[1] || "GET"; url = m[2]; }
    const h = line.match(/-H\s+["']([^:]+):\s*([^"']+)["']/);
    if (h) headers[h[1]] = h[2];
    const d = line.match(/-d\s+["']([^"']+)["']/);
    if (d) { body = d[1]; if (method === "GET") method = "POST"; }
    if (!url) {
      const u = line.match(/(https?:\/\/[^\s"'<>]+)/);
      if (u) url = u[1];
    }
  }

  if (!url && fallbackUrl) {
    url = fallbackUrl;
    evidence.urlSource = "target_fallback";
  }

  if (!url) {
    return { ok: false, exitCode: 2, output: "edge-sandbox: could not extract a target URL from the script", evidence };
  }

  // T2 #6 — abort early if host is in the dead_targets blacklist
  const host = hostOf(url);
  if (await isDeadHost(supa, host)) {
    return {
      ok: false, exitCode: 7,
      output: `[edge-sandbox] aborted: host ${host} is on dead_targets (WAF kill-switch active)`,
      evidence: { ...evidence, url, dead_host: host },
    };
  }

  // T1 #2 — skip 404 ghost-towns BEFORE wasting payload on them
  const baseline = await getBaseline(supa, url);
  if (isGhostBaseline(baseline)) {
    return {
      ok: false, exitCode: 6,
      output: `[edge-sandbox] skipped 404 ghost endpoint ${url} (baseline status=${baseline?.status})`,
      evidence: { ...evidence, url, baseline_skipped: true, baseline_status: baseline?.status },
    };
  }

  // ── SESSION JAR: load + inject cookies/JWT/CSRF/sticky headers ──
  const jar = await loadJar(supa, targetId);
  const mergedHeaders = applyJar(jar, headers);
  evidence.jar_applied = {
    cookies: Object.keys(jar.cookies).length,
    jwt: jar.jwt ? "present" : null,
    csrf: jar.csrf_token ? "present" : null,
    hit_count: jar.hit_count,
  };

  let r: Response | null = null;
  try {
    r = await safeFetch(url, { method, headers: mergedHeaders, body, redirect: "follow" }, 8000);
  } catch (e) {
    // T2 #6 — track WAF Status-0 streak
    const ks = await noteStatusZero(supa, host, targetId);
    return { ok: false, exitCode: 1, output: `edge-sandbox: fetch threw ${e instanceof Error ? e.message : "err"} (status-0 streak=${ks.streak}${ks.killed ? " → HOST BANNED" : ""})`, evidence: { ...evidence, url, dead_streak: ks.streak, host_killed: ks.killed } };
  }
  if (!r) {
    const ks = await noteStatusZero(supa, host, targetId);
    return { ok: false, exitCode: 1, output: `edge-sandbox: fetch failed (status-0 streak=${ks.streak})`, evidence: { ...evidence, url, dead_streak: ks.streak, host_killed: ks.killed } };
  }
  noteStatusOk(host);
  const text = (await r.text().catch(() => "")) || "";
  evidence.method = method; evidence.url = url;
  evidence.status = r.status; evidence.length = text.length;
  evidence.snippet = text.slice(0, 400);
  evidence.baseline_status = baseline?.status;
  evidence.baseline_len = baseline?.len;

  // T2 #7 — smart verdict (not just byte deltas)
  const verdict = calculateVerdict({
    baselineStatus: baseline?.status, baselineLen: baseline?.len,
    mutatedStatus: r.status, mutatedLen: text.length,
    mutatedBody: text,
    payload: body,
  });
  evidence.verdict = verdict;

  // ── SESSION JAR: harvest fresh cookies/JWT/CSRF for the next attempt ──
  try {
    await harvestAndPersist(supa, targetId, "default", jar, {
      headers: r.headers, bodyText: text, url,
    });
  } catch { /* ignore */ }

  return {
    ok: true,
    exitCode: 0,
    output: `[edge-sandbox] ${method} ${url}\nstatus=${r.status} length=${text.length} verdict=${verdict.proven ? `PROVEN(${verdict.reason})` : verdict.reason}\n--- response (first 400b) ---\n${text.slice(0,400)}${verdict.proven ? "\n[PROVEN] CYBERSCOPE_PROVEN verdict=" + verdict.reason : ""}`,
    evidence,

  };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  const started = Date.now();
  try {
    const supa = db();
    const auth = req.headers.get("Authorization") || "";
    const token = auth.replace(/^Bearer\s+/i, "");
    const isServiceRole = token && token === Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    const { data: ud } = await supa.auth.getUser(token);
    const userId = ud?.user?.id;
    if (!isServiceRole && !userId) {
      return new Response(JSON.stringify({ ok: false, error: "unauthorized" }),
        { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const body = await req.json() as Body;
    if (!body.targetId || !body.script) {
      return new Response(JSON.stringify({ ok: false, error: "targetId and script required" }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const language = body.language || "curl";
    const mode = body.mode || "auto";

    // T1 #3 — sanitise any markdown leakage the AI may have slipped through.
    const cleanScript = sanitizeAiOutput(body.script);

    // T2 #6 — abort immediately if the target host is already on the kill-list.
    if (body.targetUrl) {
      const h = hostOf(body.targetUrl);
      if (await isDeadHost(supa, h)) {
        return new Response(JSON.stringify({
          ok: false, executor: "n/a", proven: false,
          output: `[sandbox] aborted: host ${h} is on dead_targets`,
          evidence: { dead_host: h },
        }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
    }

    // Insert pending row
    const { data: row } = await supa.from("sandbox_executions").insert({
      user_id: userId, finding_id: body.findingId, target_id: body.targetId,
      mode, language, script: cleanScript, status: "running",
    } as any).select().single();

    let executor = "edge_function";
    let runResult: any = null;

    // Try docker worker first (unless edge-only)
    if (mode !== "edge") {
      const { data: cfg } = await supa.from("external_infra_config")
        .select("*").eq("service", "docker_worker").maybeSingle();
      if (cfg && (cfg as any).is_active && (cfg as any).endpoint_url) {
        // T2 #8 — pass targetUrl so the container can inject TARGET_URL env + outbound.
        const r = await runViaWorker(cfg, {
          script: cleanScript, language, findingId: body.findingId,
          targetUrl: body.targetUrl,
        });
        if (r.ok) {
          executor = "docker_worker";
          runResult = {
            ok: true,
            exitCode: r.data?.exitCode ?? 0,
            output: r.data?.output || r.data?.stdout || JSON.stringify(r.data).slice(0, 4000),
            evidence: r.data?.evidence || {},
          };
        }
      }
    }



    // Fall back to edge sandbox
    if (!runResult && mode !== "worker") {
      // Resolve a fallback target URL when the synthesised script omits one
      let fallbackUrl: string | undefined = body.targetUrl;
      if (!fallbackUrl) {
        const { data: tgt } = await supa.from("target_workspaces")
          .select("domain,ip_range").eq("id", body.targetId).maybeSingle();
        const raw = (tgt as any)?.domain || (tgt as any)?.ip_range;
        if (raw) fallbackUrl = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
      }
      runResult = await runViaEdge(cleanScript, language, fallbackUrl, supa, body.targetId);
      executor = "edge_function";
    }

    if (!runResult) {
      runResult = { ok: false, exitCode: 1, output: "no executor available", evidence: {} };
    }

    // Combine sandbox PROVEN markers with verdict-based proof.
    const verdictProven = !!(runResult.evidence?.verdict?.proven);
    const proven = (runResult.ok && /\[PROVEN\]|CYBERSCOPE_PROVEN|root:x:0:0:|\[boot loader\]|<\?php|sql syntax|mysql_|pg_query|SQLSTATE|ORA-\d{4,}|unclosed quotation|System\.Data\.SqlClient/i.test(runResult.output || "")) || verdictProven;


    await supa.from("sandbox_executions").update({
      status: runResult.ok ? "done" : "failed",
      executor,
      exit_code: runResult.exitCode ?? null,
      output: (runResult.output || "").slice(0, 50000),
      evidence: runResult.evidence || {},
      proven,
      duration_ms: Date.now() - started,
    } as any).eq("id", row!.id);

    return new Response(JSON.stringify({
      ok: runResult.ok, executor, executionId: row!.id, proven,
      output: runResult.output, evidence: runResult.evidence,
    }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: e instanceof Error ? e.message : "err" }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
