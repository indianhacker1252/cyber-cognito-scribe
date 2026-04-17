import { corsHeaders } from "https://esm.sh/@supabase/supabase-js@2.95.0/cors";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.95.0";

interface RevalidationResult {
  findingId: string;
  title: string;
  oldConfidence: number;
  newConfidence: number;
  status: "confirmed" | "regressed" | "inconclusive" | "error";
  responseStatus?: number;
  responseDelta?: number;
  notes: string;
}

async function safeFetch(url: string, opts: RequestInit = {}, ms = 7000): Promise<Response> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...opts, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

  try {
    const { targetId } = await req.json().catch(() => ({}));
    if (!targetId) {
      return new Response(
        JSON.stringify({ ok: false, error: "targetId required" }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" }, status: 200 }
      );
    }

    const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

    // Pull all pending re-mutated findings for this target
    const { data: pending, error: pErr } = await db
      .from("vulnerability_findings")
      .select("id, title, payload, confidence_score, severity, endpoint_id, triage_reasoning")
      .eq("target_id", targetId)
      .eq("validation_status", "drift_remutation_pending")
      .limit(25);

    if (pErr) throw pErr;
    if (!pending || pending.length === 0) {
      return new Response(
        JSON.stringify({ ok: true, message: "No drift-pending findings", processed: 0, results: [] }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" }, status: 200 }
      );
    }

    // Lookup endpoint URLs in one batch
    const endpointIds = [...new Set(pending.map((f) => f.endpoint_id).filter(Boolean) as string[])];
    const { data: endpoints } = endpointIds.length
      ? await db.from("discovered_endpoints").select("id, url, method").in("id", endpointIds)
      : { data: [] as Array<{ id: string; url: string; method: string }> };
    const epMap = new Map((endpoints || []).map((e) => [e.id, e]));

    const results: RevalidationResult[] = [];

    for (const f of pending) {
      const ep = f.endpoint_id ? epMap.get(f.endpoint_id) : null;
      if (!ep || !ep.url) {
        results.push({
          findingId: f.id, title: f.title,
          oldConfidence: f.confidence_score || 0, newConfidence: f.confidence_score || 0,
          status: "error", notes: "endpoint missing — cannot revalidate",
        });
        continue;
      }

      // Fire baseline + mutated payload requests
      try {
        const baseline = await safeFetch(ep.url, { method: ep.method || "GET", headers: { "User-Agent": "CyberScope-Reval/1.0" } }, 6000);
        const baselineBody = await baseline.text().catch(() => "");
        const baselineLen = baselineBody.length;

        // Append mutated payload as query param "q" (safe + non-destructive probe)
        const sep = ep.url.includes("?") ? "&" : "?";
        const probeUrl = `${ep.url}${sep}q=${encodeURIComponent(f.payload || "")}`;
        const probe = await safeFetch(probeUrl, { method: ep.method || "GET", headers: { "User-Agent": "CyberScope-Reval/1.0" } }, 6000);
        const probeBody = await probe.text().catch(() => "");
        const probeLen = probeBody.length;

        // Compute delta + new confidence
        const delta = baselineLen > 0 ? Math.abs(probeLen - baselineLen) / baselineLen : 0;
        const statusDiff = probe.status !== baseline.status;
        const old = f.confidence_score || 0;

        let status: RevalidationResult["status"] = "inconclusive";
        let newConf = old;
        let notes = "";

        if (probe.status >= 500 || (statusDiff && delta > 0.25)) {
          // Strong signal — payload still triggers anomaly post-drift
          status = "confirmed";
          newConf = Math.min(100, old + 15);
          notes = `Drift-mutated payload still triggers anomaly (status ${probe.status}, ${(delta * 100).toFixed(1)}% body delta). WAF bypass holding.`;
        } else if (probe.status === 403 || probe.status === 406 || probe.status === 429) {
          status = "regressed";
          newConf = Math.max(0, old - 20);
          notes = `New WAF blocked mutated payload (${probe.status}). Original finding likely mitigated by drift.`;
        } else if (delta > 0.05) {
          status = "inconclusive";
          newConf = Math.max(0, Math.min(100, old + 3));
          notes = `Minor response delta (${(delta * 100).toFixed(1)}%). Manual review recommended.`;
        } else {
          status = "regressed";
          newConf = Math.max(0, old - 10);
          notes = `No anomaly detected post-drift (status ${probe.status}, no body delta).`;
        }

        await db.from("vulnerability_findings").update({
          confidence_score: newConf,
          confidence_level: newConf >= 70 ? "high" : newConf >= 40 ? "medium" : "low",
          validation_status: status === "confirmed" ? "verified_post_drift"
            : status === "regressed" ? "regressed_post_drift"
            : "needs_review",
          triage_reasoning: `[Drift Revalidation] ${notes}`,
        }).eq("id", f.id);

        results.push({
          findingId: f.id, title: f.title,
          oldConfidence: old, newConfidence: newConf,
          status, responseStatus: probe.status, responseDelta: Number(delta.toFixed(3)),
          notes,
        });
      } catch (e) {
        results.push({
          findingId: f.id, title: f.title,
          oldConfidence: f.confidence_score || 0, newConfidence: f.confidence_score || 0,
          status: "error", notes: `revalidation error: ${(e as Error).message}`,
        });
      }
    }

    // Log summary
    await db.from("scan_logs").insert({
      target_id: targetId,
      log_type: "result",
      message: `🔬 Drift revalidation complete — ${results.filter(r => r.status === "confirmed").length} confirmed, ${results.filter(r => r.status === "regressed").length} regressed, ${results.filter(r => r.status === "inconclusive").length} inconclusive`,
      metadata: { results: results.slice(0, 10) },
    });

    return new Response(
      JSON.stringify({ ok: true, processed: results.length, results }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" }, status: 200 }
    );
  } catch (err) {
    return new Response(
      JSON.stringify({ ok: false, error: (err as Error).message }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" }, status: 200 }
    );
  }
});
