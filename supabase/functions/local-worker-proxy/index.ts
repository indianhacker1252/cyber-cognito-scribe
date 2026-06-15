// Local worker proxy — forwards safe tool/AI jobs to a user-controlled worker.
// Uses external_infra_config(service='local_worker' or legacy 'docker_worker').
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

const TOOL_ALLOWLIST = new Set([
  "nuclei", "sqlmap", "dalfox", "katana", "nikto", "wpscan", "gobuster",
  "dirsearch", "wafw00f", "whatweb", "sslscan", "sslyze", "testssl",
  "ffuf", "amass", "subfinder", "httpx", "naabu", "masscan", "nmap",
]);

function db() {
  return createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, { auth: { persistSession: false } });
}

async function readCfg(supa: any) {
  const { data: local } = await supa.from("external_infra_config")
    .select("*").eq("service", "local_worker").eq("is_active", true).maybeSingle();
  if (local?.endpoint_url) return local;
  const { data: docker } = await supa.from("external_infra_config")
    .select("*").eq("service", "docker_worker").eq("is_active", true).maybeSingle();
  return docker?.endpoint_url ? docker : null;
}

async function forward(cfg: any, path: string, body: unknown, timeoutMs: number) {
  const endpoint = String(cfg.endpoint_url).replace(/\/$/, "") + path;
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (cfg.auth_token) headers.Authorization = `Bearer ${cfg.auth_token}`;
  const r = await fetch(endpoint, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(Math.min(timeoutMs, 45000)),
  });
  const text = await r.text();
  let data: unknown = text;
  try { data = JSON.parse(text); } catch { /* keep text */ }
  return { ok: r.ok, status: r.status, data };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  const respond = (body: unknown) => new Response(JSON.stringify(body), {
    status: 200,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });

  try {
    const body = await req.json().catch(() => ({}));
    const { targetId, mode = "tool", tool, target, args = [], prompt, model = "llama3.1", timeoutMs = 30000 } = body;
    if (!targetId) return respond({ ok: false, error: "targetId required" });

    const supa = db();
    const cfg = await readCfg(supa);
    if (!cfg) {
      await supa.from("scan_logs").insert({
        target_id: targetId,
        log_type: "warning",
        message: "🧰 Local worker not configured — skipping external tool job",
        metadata: { mode, tool },
      });
      return respond({ ok: false, error: "local worker not configured" });
    }

    if (mode === "ai") {
      if (!prompt || typeof prompt !== "string") return respond({ ok: false, error: "prompt required" });
      const out = await forward(cfg, "/ai/chat", { prompt, model }, timeoutMs);
      await supa.from("scan_logs").insert({
        target_id: targetId,
        log_type: out.ok ? "info" : "error",
        message: out.ok ? "🧠 Ollama worker returned mutation output" : `🧠 Ollama worker failed: HTTP ${out.status}`,
        metadata: { source: "ollama", model, status: out.status },
      });
      return respond(out);
    }

    if (!TOOL_ALLOWLIST.has(String(tool))) return respond({ ok: false, error: "unsupported tool" });
    if (!target || typeof target !== "string") return respond({ ok: false, error: "target required" });

    await supa.from("scan_logs").insert({
      target_id: targetId,
      log_type: "info",
      message: `🧰 Local worker dispatch: ${tool} → ${target}`,
      metadata: { source: "local-worker", tool, args },
    });
    const out = await forward(cfg, "/run", { tool, target, args }, timeoutMs);
    await supa.from("scan_logs").insert({
      target_id: targetId,
      log_type: out.ok ? "info" : "error",
      message: out.ok ? `🧰 ${tool} completed on local worker` : `🧰 ${tool} failed on local worker: HTTP ${out.status}`,
      metadata: { source: "local-worker", tool, status: out.status },
    });
    return respond(out);
  } catch (e) {
    return respond({ ok: false, error: e instanceof Error ? e.message : String(e) });
  }
});