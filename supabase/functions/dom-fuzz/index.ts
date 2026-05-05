// DOM-Fuzz — Playwright-based DOM XSS / client-side fuzzing.
// Strategy: prefer docker worker /playwright (real Chromium). Fall back to
// existing headless-browser edge function for lightweight DOM sink analysis.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};
function db() { return createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!); }

interface Body {
  targetId: string;
  url: string;
  payloads?: string[];
  params?: string[];
  hashFuzz?: boolean;
  postMessageFuzz?: boolean;
}

const DEFAULT_PAYLOADS = [
  `"><svg/onload=window.__cs_xss=1>`,
  `<img src=x onerror=window.__cs_xss=1>`,
  `javascript:window.__cs_xss=1`,
  `'-window.__cs_xss-'`,
  `</script><script>window.__cs_xss=1</script>`,
];

async function runViaWorker(cfg: any, payload: any) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 60000);
  try {
    const r = await fetch(`${(cfg.endpoint_url as string).replace(/\/$/, "")}/playwright`, {
      method: "POST",
      headers: { "Content-Type": "application/json",
        ...(cfg.auth_token ? { "Authorization": `Bearer ${cfg.auth_token}` } : {}) },
      body: JSON.stringify(payload),
      signal: ctrl.signal,
    });
    const text = await r.text();
    let data: any = text; try { data = JSON.parse(text); } catch {}
    return { ok: r.ok, data };
  } catch (e) { return { ok: false, data: { error: e instanceof Error ? e.message : "err" } }; }
  finally { clearTimeout(t); }
}

async function runViaEdgeHeadless(supa: any, targetId: string, url: string, payloads: string[]) {
  // Use existing headless-browser / validate-finding dom-watch
  const findings: any[] = [];
  for (const p of payloads.slice(0, 10)) {
    try {
      const r = await supa.functions.invoke("validate-finding", {
        body: { action: "dom-watch", targetUrl: url + (url.includes("?") ? "&" : "?") + "test=" + encodeURIComponent(p), payload: p },
      });
      const d = r.data || {};
      if (d.xssTriggered || (d.consoleMessages || []).some((m: string) => /__cs_xss|alert|xss/i.test(m))) {
        findings.push({ payload: p, evidence: d, proven: true });
      } else if ((d.dangerousEvals || 0) > 0 || (d.postMessageHandlers || 0) > 0) {
        findings.push({ payload: p, evidence: d, proven: false, suspicious: true });
      }
    } catch { /* continue */ }
  }
  return findings;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const supa = db();
    const body = await req.json() as Body;
    if (!body.targetId || !body.url) {
      return new Response(JSON.stringify({ ok: false, error: "targetId and url required" }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const payloads = body.payloads?.length ? body.payloads : DEFAULT_PAYLOADS;

    await supa.from("scan_logs").insert({
      target_id: body.targetId, log_type: "info",
      message: `🎭 DOM-Fuzz starting on ${body.url} with ${payloads.length} payloads`,
      metadata: { url: body.url },
    } as any);

    let executor = "edge_headless";
    let findings: any[] = [];

    const { data: cfg } = await supa.from("external_infra_config")
      .select("*").eq("service", "docker_worker").maybeSingle();
    if (cfg && (cfg as any).is_active && (cfg as any).endpoint_url) {
      const r = await runViaWorker(cfg, {
        url: body.url, payloads, params: body.params || ["q","search","redirect","next","url","return"],
        hashFuzz: body.hashFuzz !== false, postMessageFuzz: body.postMessageFuzz !== false,
      });
      if (r.ok && Array.isArray(r.data?.findings)) {
        executor = "docker_worker_playwright";
        findings = r.data.findings;
      }
    }

    if (findings.length === 0 && executor === "edge_headless") {
      findings = await runViaEdgeHeadless(supa, body.targetId, body.url, payloads);
    }

    // Persist proven findings
    for (const f of findings.filter((x) => x.proven)) {
      await supa.from("vulnerability_findings").insert({
        target_id: body.targetId,
        title: `DOM XSS — ${body.url.split("/").pop() || "endpoint"}`,
        severity: "high", cvss_score: 7.4,
        description: `Client-side XSS proven via DOM-fuzz (${executor}).`,
        payload: f.payload, poc: `Open: ${body.url}\nPayload triggered: ${f.payload}`,
        validation_status: "verified", ai_verified: true,
        confidence_score: 88, confidence_level: "high",
        reachability_status: "reachable",
        triage_reasoning: `DOM-Fuzz module observed XSS execution marker in browser context using ${executor}.`,
        remediation: "Sanitize user-controlled DOM sinks; use safe templating; apply CSP with nonces.",
      } as any);
    }

    await supa.from("scan_logs").insert({
      target_id: body.targetId, log_type: findings.length ? "warn" : "info",
      message: `🎭 DOM-Fuzz finished on ${body.url} via ${executor} — ${findings.length} signals (${findings.filter(f=>f.proven).length} proven)`,
      metadata: { executor, findings: findings.length },
    } as any);

    return new Response(JSON.stringify({ ok: true, executor, findings }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: e instanceof Error ? e.message : "err" }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
