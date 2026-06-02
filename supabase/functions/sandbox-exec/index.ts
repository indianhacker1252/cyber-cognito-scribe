// Sandbox Exec — runs an exploit/validation payload in isolation.
// Strategy: try user's docker worker (if active) → fall back to edge-function
// simulated sandbox (safeFetch with strict allowlist + recorded evidence).
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { safeFetch } from "../_shared/safe-fetch.ts";

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
    const r = await fetch(`${(cfg.endpoint_url as string).replace(/\/$/,"")}/sandbox`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(cfg.auth_token ? { "Authorization": `Bearer ${cfg.auth_token}` } : {}),
      },
      body: JSON.stringify(payload),
      signal: ctrl.signal,
    });
    const text = await r.text();
    let data: any = text; try { data = JSON.parse(text); } catch {}
    return { ok: r.ok, status: r.status, data };
  } catch (e) {
    return { ok: false, status: 0, data: { error: e instanceof Error ? e.message : "err" } };
  } finally { clearTimeout(t); }
}

async function runViaEdge(script: string, language: string, fallbackUrl?: string) {
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

  // NEW: fall back to the finding's bound target URL when the script omits one
  if (!url && fallbackUrl) {
    url = fallbackUrl;
    evidence.urlSource = "target_fallback";
  }

  if (!url) {
    return { ok: false, exitCode: 2, output: "edge-sandbox: could not extract a target URL from the script", evidence };
  }
  let r: Response | null = null;
  try {
    r = await safeFetch(url, { method, headers, body, redirect: "follow" }, 8000);
  } catch (e) {
    return { ok: false, exitCode: 1, output: `edge-sandbox: fetch threw ${e instanceof Error ? e.message : "err"}`, evidence: { ...evidence, url } };
  }
  if (!r) return { ok: false, exitCode: 1, output: `edge-sandbox: fetch failed`, evidence: { ...evidence, url } };
  const text = (await r.text().catch(() => "")) || "";
  evidence.method = method; evidence.url = url;
  evidence.status = r.status; evidence.length = text.length;
  evidence.snippet = text.slice(0, 400);
  return {
    ok: true,
    exitCode: 0,
    output: `[edge-sandbox] ${method} ${url}\nstatus=${r.status} length=${text.length}\n--- response (first 400b) ---\n${text.slice(0,400)}`,
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

    // Insert pending row
    const { data: row } = await supa.from("sandbox_executions").insert({
      user_id: userId, finding_id: body.findingId, target_id: body.targetId,
      mode, language, script: body.script, status: "running",
    } as any).select().single();

    let executor = "edge_function";
    let runResult: any = null;

    // Try docker worker first (unless edge-only)
    if (mode !== "edge") {
      const { data: cfg } = await supa.from("external_infra_config")
        .select("*").eq("service", "docker_worker").maybeSingle();
      if (cfg && (cfg as any).is_active && (cfg as any).endpoint_url) {
        const r = await runViaWorker(cfg, {
          script: body.script, language, findingId: body.findingId,
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
      runResult = await runViaEdge(body.script, language, fallbackUrl);
      executor = "edge_function";
    }

    if (!runResult) {
      runResult = { ok: false, exitCode: 1, output: "no executor available", evidence: {} };
    }

    const proven = runResult.ok && /\[PROVEN\]|CYBERSCOPE_PROVEN|root:x:0:0:|\[boot loader\]|<\?php|sql syntax|mysql_|pg_query|SQLSTATE|ORA-\d{4,}|unclosed quotation|System\.Data\.SqlClient/i.test(runResult.output || "");

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
