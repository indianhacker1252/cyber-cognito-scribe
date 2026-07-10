// matrix-fuzzer — runs the full (method × location × param × payload) injection
// matrix against every asset in scope. Designed to fan out by subdomain so the
// scanner no longer collapses to the apex host.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { expandScope } from "../_shared/scope-expander.ts";
import {
  buildProbes,
  applyProbe,
  detectProof,
  extractParamsFromUrl,
  type EndpointSpec,
  type PayloadClass,
} from "../_shared/injection-matrix.ts";
import { recordFinding } from "../_shared/findings-writer.ts";
import { loadJar, applyJar } from "../_shared/session-jar.ts";
import { checkLoopGuard, recordLoopRun } from "../_shared/loop-guard.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

const SUPA = Deno.env.get("SUPABASE_URL")!;
const SVC = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

const MAX_MS = 42000;
const start = Date.now();
const tl = () => MAX_MS - (Date.now() - start);

async function safeFetch(url: string, init: RequestInit, ms = 6000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...init, signal: ctrl.signal });
  } finally {
    clearTimeout(t);
  }
}

function severityFor(pc: PayloadClass): string {
  if (pc === "rce" || pc === "ssti" || pc === "sqli") return "critical";
  if (pc === "ssrf" || pc === ("xxe" as any) || pc === "lfi") return "high";
  return "medium";
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  const ok = (b: any) =>
    new Response(JSON.stringify(b), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });

  try {
    const { targetId, perAssetCap = 60, methods, classes } = await req.json().catch(() => ({}));
    if (!targetId) return ok({ ok: false, error: "targetId required" });
    const db = createClient(SUPA, SVC);

    // Gap #1: auth-aware — load persisted session jar for this target
    const jar = await loadJar(db, targetId);

    const assets = await expandScope(db, targetId);
    if (!assets.length) return ok({ ok: false, error: "no assets in scope" });

    await db.from("scan_logs").insert({
      target_id: targetId,
      log_type: "action",
      message: `🧮 Matrix-fuzzer fanning out across ${assets.length} asset(s): ${assets
        .slice(0, 8)
        .map((a) => a.host)
        .join(", ")}`,
      metadata: { assetCount: assets.length },
    });

    let probesSent = 0,
      findingsCreated = 0,
      hitsByClass: Record<string, number> = {};
    const methodsTested = new Set<string>();
    const paramsFuzzed = new Set<string>();

    for (const asset of assets) {
      if (tl() < 4000) break;
      // Collect endpoints belonging to this asset
      const { data: eps } = await db
        .from("discovered_endpoints")
        .select("url,method,parameters")
        .eq("target_id", targetId)
        .limit(200);
      const own = (eps || []).filter((e: any) => {
        try {
          return new URL(e.url).host.toLowerCase().includes(asset.host);
        } catch {
          return false;
        }
      });
      if (own.length === 0) own.push({ url: asset.base_url, method: "GET", parameters: {} });

      let sentForAsset = 0;
      for (const ep of own) {
        if (tl() < 3000 || sentForAsset >= perAssetCap) break;
        const qp = extractParamsFromUrl(ep.url);
        const params: Record<string, any> = (ep.parameters as any) || {};
        const spec: EndpointSpec = {
          url: ep.url,
          queryParams: Array.from(new Set([...qp, ...Object.keys(params)])).slice(0, 8),
          bodyParams: Object.keys(params).slice(0, 8),
        };

        for (const probe of buildProbes(spec, { perClassCap: 2, methods, classes })) {
          if (tl() < 2500 || sentForAsset >= perAssetCap) break;
          const { url, init } = applyProbe(ep.url, probe);
          // inject session jar headers (cookies/JWT/CSRF)
          init.headers = applyJar(jar, (init.headers as Record<string, string>) || {});
          try {
            const r = await safeFetch(url, init, 5500);

            const body = await r.text().catch(() => "");
            probesSent++;
            sentForAsset++;
            methodsTested.add(probe.method);
            paramsFuzzed.add(`${asset.host}|${probe.param}`);
            const proven = detectProof(probe.payloadClass, r.status, body, r.headers);
            if (proven) {
              hitsByClass[probe.payloadClass] = (hitsByClass[probe.payloadClass] || 0) + 1;
              await recordFinding({
                targetId,
                source: "matrix-fuzzer",
                category: probe.payloadClass,
                vulnClass: probe.payloadClass,
                severity: severityFor(probe.payloadClass) as any,
                title: `[matrix] ${probe.payloadClass.toUpperCase()} via ${probe.method} ${probe.location} param "${probe.param}"`,
                description: `Matrix-fuzzer proved ${probe.payloadClass} on ${asset.host}. Payload echoed/triggered proof marker.`,
                payload: probe.payload,
                proofTier: "exploited",
                autoEnqueueExploit: true,
                evidence: {
                  templateId: probe.payloadClass,
                  vuln_class: probe.payloadClass,
                  method: probe.method,
                  location: probe.location,
                  param: probe.param,
                  status: r.status,
                  bodySnippet: body.slice(0, 800),
                  asset: asset.host,
                  affected_url: ep.url,
                  probeUrl: url,
                },
                // request.url becomes findings-writer's affected_url column,
                // which exploit-engine later fetches as its BASELINE (the
                // "before" state to diff mutations against). It must be the
                // clean endpoint, not the weaponized probe URL with the
                // payload already embedded — otherwise the baseline fetch
                // itself trips the WAF / server-side validation and comes
                // back empty, corrupting confirmation for every finding.
                request: {
                  method: probe.method,
                  url: ep.url,
                  headers: (init.headers as any) || {},
                  body: typeof init.body === "string" ? init.body : undefined,
                },
                response: { status: r.status, body: body.slice(0, 4000) },
              });
              findingsCreated++;
            }
          } catch {
            /* ignore probe error */
          }
        }
      }

      await db
        .from("scan_assets")
        .update({ last_scanned_at: new Date().toISOString() })
        .eq("target_id", targetId)
        .eq("host", asset.host);
    }

    await db.from("scan_logs").insert({
      target_id: targetId,
      log_type: findingsCreated ? "warning" : "info",
      message: `🧮 Matrix-fuzzer done: ${probesSent} probes, ${methodsTested.size} methods, ${paramsFuzzed.size} params, ${findingsCreated} findings`,
      metadata: {
        probesSent,
        findings: findingsCreated,
        methods: Array.from(methodsTested),
        hits: hitsByClass,
        assets: assets.length,
      },
    });

    return ok({
      ok: true,
      assets: assets.length,
      probesSent,
      findingsCreated,
      methodsTested: Array.from(methodsTested),
      paramsFuzzed: paramsFuzzed.size,
      hitsByClass,
    });
  } catch (e) {
    return ok({ ok: false, error: e instanceof Error ? e.message : "err" });
  }
});
