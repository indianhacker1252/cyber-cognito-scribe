// Docker worker dispatcher — sends scan jobs to user-hosted container running
// nuclei/ffuf/sqlmap. Streams stdout chunks back into scan_logs as they arrive
// so the Live Neural Log shows real tool output in real time.
//
// Expected docker worker contract (user provides):
//   POST {endpoint_url}/run
//     Headers: Authorization: Bearer {auth_token}
//     Body:   { tool: "nuclei"|"ffuf"|"sqlmap", target: "...", args: [...] }
//     Response: text/event-stream  (or chunked NDJSON: { line: "...", done?: bool })
//
// We ship a reference Dockerfile in /docker-worker-reference for the user to
// deploy on Fly.io / Railway / their VPS.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

function db() {
  return createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
}

const SUPPORTED_TOOLS = ["nuclei", "ffuf", "sqlmap"] as const;
type Tool = typeof SUPPORTED_TOOLS[number];

interface DispatchInput {
  targetId: string;
  tool: Tool;
  target: string;       // URL or host:port for the tool to scan
  args?: string[];      // tool-specific extra flags
  timeoutMs?: number;
}

async function logChunk(targetId: string, tool: Tool, line: string) {
  if (!line.trim()) return;
  await db().from("scan_logs").insert({
    target_id: targetId,
    log_type: "info",
    message: `🐳 [${tool}] ${line.slice(0, 800)}`,
    metadata: { source: "docker-worker", tool },
  } as any);
}

async function streamFromWorker(
  endpoint: string,
  token: string | null,
  body: any,
  targetId: string,
  tool: Tool,
  timeoutMs: number,
): Promise<{ ok: boolean; lines: number; error?: string }> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  let lineCount = 0;
  try {
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (token) headers["Authorization"] = `Bearer ${token}`;
    const r = await fetch(`${endpoint.replace(/\/$/, "")}/run`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });
    if (!r.ok || !r.body) {
      return { ok: false, lines: 0, error: `worker HTTP ${r.status}` };
    }
    const reader = r.body.getReader();
    const decoder = new TextDecoder();
    let buf = "";
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      const parts = buf.split(/\r?\n/);
      buf = parts.pop() || "";
      for (const raw of parts) {
        let line = raw;
        // tolerate NDJSON wrapper
        if (line.startsWith("{")) {
          try {
            const j = JSON.parse(line);
            line = j.line ?? j.message ?? raw;
            if (j.done) continue;
          } catch { /* keep raw */ }
        }
        // SSE wrapper
        if (line.startsWith("data: ")) line = line.slice(6);
        await logChunk(targetId, tool, line);
        lineCount++;
        if (lineCount > 500) break; // safety cap
      }
      if (lineCount > 500) break;
    }
    if (buf.trim()) { await logChunk(targetId, tool, buf); lineCount++; }
    return { ok: true, lines: lineCount };
  } catch (e) {
    return { ok: false, lines: lineCount, error: e instanceof Error ? e.message : "stream err" };
  } finally {
    clearTimeout(timer);
  }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const input = await req.json() as DispatchInput;
    if (!input.targetId || !input.tool || !input.target) {
      return new Response(JSON.stringify({ error: "targetId, tool, target required" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    if (!SUPPORTED_TOOLS.includes(input.tool)) {
      return new Response(JSON.stringify({ error: `tool must be one of ${SUPPORTED_TOOLS.join(",")}` }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const supa = db();
    const { data: cfg } = await supa.from("external_infra_config")
      .select("*").eq("service", "docker_worker").maybeSingle();

    if (!cfg || !(cfg as any).is_active || !(cfg as any).endpoint_url) {
      await supa.from("scan_logs").insert({
        target_id: input.targetId, log_type: "error",
        message: `🐳 Docker worker not configured — cannot run ${input.tool}. Configure under Settings → External Infrastructure.`,
        metadata: { tool: input.tool },
      } as any);
      return new Response(JSON.stringify({
        ok: false, error: "docker worker not configured",
        hint: "Add Docker worker URL + token in Settings → External Infrastructure",
      }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    await supa.from("scan_logs").insert({
      target_id: input.targetId, log_type: "info",
      message: `🐳 Dispatching ${input.tool} on ${input.target} → docker worker`,
      metadata: { tool: input.tool, target: input.target, args: input.args || [] },
    } as any);

    const result = await streamFromWorker(
      (cfg as any).endpoint_url,
      (cfg as any).auth_token,
      { tool: input.tool, target: input.target, args: input.args || [] },
      input.targetId,
      input.tool,
      input.timeoutMs ?? 45000,
    );

    await supa.from("scan_logs").insert({
      target_id: input.targetId,
      log_type: result.ok ? "info" : "error",
      message: result.ok
        ? `🐳 ${input.tool} finished — ${result.lines} output lines streamed`
        : `🐳 ${input.tool} failed: ${result.error}`,
      metadata: { tool: input.tool, lines: result.lines, error: result.error },
    } as any);

    return new Response(JSON.stringify(result),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (e) {
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : "err" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
