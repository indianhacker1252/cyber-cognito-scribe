// OpenAPI / Swagger Importer — fetches a JSON/YAML schema, expands every
// path × method × param into discovered_endpoints, and (when requested)
// queues full auto-attack jobs (fuzz, llm_attack, oob, chain) per endpoint.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

function db() {
  return createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
}

async function safeFetch(url: string, ms = 15000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try { return await fetch(url, { signal: ctrl.signal, headers: { "User-Agent": "SPECTER-OpenAPI/1.0" } }); }
  finally { clearTimeout(t); }
}

function joinUrl(base: string, path: string): string {
  try { return new URL(path, base.endsWith("/") ? base : base + "/").toString(); }
  catch { return path; }
}

function resolveBaseUrl(schema: any, schemaUrl: string): string {
  // OpenAPI 3.x: servers[0].url, Swagger 2.0: host + basePath + schemes[0]
  if (Array.isArray(schema?.servers) && schema.servers[0]?.url) {
    const s = schema.servers[0].url;
    if (/^https?:\/\//i.test(s)) return s;
    try { return new URL(s, schemaUrl).toString(); } catch { /* fallthrough */ }
  }
  if (schema?.host) {
    const scheme = (schema.schemes?.[0]) || "https";
    return `${scheme}://${schema.host}${schema.basePath || ""}`;
  }
  try { const u = new URL(schemaUrl); return `${u.protocol}//${u.host}`; }
  catch { return schemaUrl; }
}

interface ExpandedEndpoint {
  url: string;
  method: string;
  params: Record<string, string>;
  bodyParams: string[];
  headerParams: string[];
  acceptsFiles: boolean;
}

function expandSchema(schema: any, baseUrl: string): ExpandedEndpoint[] {
  const out: ExpandedEndpoint[] = [];
  const paths = schema?.paths || {};
  for (const [path, item] of Object.entries<any>(paths)) {
    if (!item || typeof item !== "object") continue;
    const methods = ["get","post","put","patch","delete","options","head"];
    for (const method of methods) {
      const op = item[method];
      if (!op) continue;
      const url = joinUrl(baseUrl, path);
      const params: Record<string,string> = {};
      const headerParams: string[] = [];
      const allParams = [...(item.parameters || []), ...(op.parameters || [])];
      for (const p of allParams) {
        if (!p?.name) continue;
        if (p.in === "query") params[p.name] = String(p.example ?? p.schema?.example ?? "1");
        else if (p.in === "header") headerParams.push(p.name);
      }
      const bodyParams: string[] = [];
      let acceptsFiles = false;
      const rb = op.requestBody?.content || {};
      for (const [ct, def] of Object.entries<any>(rb)) {
        if (ct.includes("multipart/form-data") || ct.includes("octet-stream")) acceptsFiles = true;
        const props = def?.schema?.properties || {};
        for (const k of Object.keys(props)) bodyParams.push(k);
      }
      // Swagger 2.0 body param fallback
      for (const p of allParams) {
        if (p?.in === "body" && p?.schema?.properties) {
          for (const k of Object.keys(p.schema.properties)) bodyParams.push(k);
        }
        if (p?.in === "formData") {
          bodyParams.push(p.name);
          if (p.type === "file") acceptsFiles = true;
        }
      }
      out.push({
        url,
        method: method.toUpperCase(),
        params,
        bodyParams: [...new Set(bodyParams)],
        headerParams,
        acceptsFiles,
      });
    }
  }
  return out;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const supa = db();
    const { targetId, schemaUrl, autoAttack = true } = await req.json();
    if (!targetId) {
      return new Response(JSON.stringify({ error: "targetId required" }), {
        status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const { data: target } = await supa.from("target_workspaces").select("*").eq("id", targetId).maybeSingle();
    const url = schemaUrl || target?.api_schema_url;
    if (!url) {
      return new Response(JSON.stringify({ error: "no api_schema_url on target" }), {
        status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    await supa.from("scan_logs").insert({
      target_id: targetId, log_type: "info",
      message: `📘 OpenAPI importer: fetching ${url}`,
      metadata: { kind: "openapi_import_start", url },
    });

    const r = await safeFetch(url, 20000);
    if (!r.ok) {
      await supa.from("scan_logs").insert({
        target_id: targetId, log_type: "error",
        message: `❌ Schema fetch failed: HTTP ${r.status}`,
        metadata: { kind: "openapi_fetch_fail", status: r.status, url },
      });
      return new Response(JSON.stringify({ error: `fetch HTTP ${r.status}` }), {
        status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
    const text = await r.text();
    let schema: any;
    try { schema = JSON.parse(text); }
    catch {
      // very small YAML→JSON fallback (only top-level structure for common Swagger files)
      try {
        const yamlMod = await import("https://deno.land/std@0.224.0/yaml/mod.ts");
        schema = yamlMod.parse(text);
      } catch (e) {
        await supa.from("scan_logs").insert({
          target_id: targetId, log_type: "error",
          message: `❌ Schema parse failed: ${e instanceof Error ? e.message : "parse error"}`,
          metadata: { kind: "openapi_parse_fail" },
        });
        return new Response(JSON.stringify({ error: "parse failed" }), {
          status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
    }

    const baseUrl = resolveBaseUrl(schema, url);
    const endpoints = expandSchema(schema, baseUrl);

    // Persist endpoints
    let written = 0;
    for (const ep of endpoints) {
      const { error } = await supa.from("discovered_endpoints").upsert({
        target_id: targetId,
        url: ep.url,
        method: ep.method,
        parameters: { query: ep.params, body: ep.bodyParams, headers: ep.headerParams, acceptsFiles: ep.acceptsFiles },
        source: "openapi",
      }, { onConflict: "target_id,url,method" });
      if (!error) written++;
    }

    let queued = 0;
    if (autoAttack) {
      // Fan out attack jobs. Cap per category to avoid queue floods.
      const CAP = 40;
      const slice = endpoints.slice(0, CAP);
      const { enqueueJobs } = await import("../_shared/enqueue.ts");
      const jobs: any[] = [];
      const mk = (job_type: string, priority: number, payload: any, technique: string) => ({
        target_id: targetId, job_type, priority, payload,
        dedupWindowMs: 60 * 60_000,
        dedupExtraKey: `${technique}|${payload.method || "GET"}|${payload.url || ""}`,
      });
      for (const ep of slice) {
        jobs.push(mk("fuzz", 7, { url: ep.url, method: ep.method, params: ep.params, bodyParams: ep.bodyParams, source: "openapi" }, "fuzz"));
        if (ep.acceptsFiles) {
          jobs.push(mk("fuzz", 6, { url: ep.url, method: ep.method, mode: "upload", source: "openapi" }, "upload"));
        }
        if (/chat|ai|completion|prompt|llm/i.test(ep.url)) {
          jobs.push(mk("llm_attack", 7, { url: ep.url, method: ep.method, source: "openapi" }, "llm_attack"));
        }
        jobs.push(mk("oob", 5, { url: ep.url, method: ep.method, source: "openapi" }, "oob"));
      }
      // One chain pass over the imported surface
      jobs.push({
        target_id: targetId, job_type: "chain", priority: 6,
        payload: { source: "openapi", endpointCount: slice.length },
        dedupWindowMs: 60 * 60_000,
        dedupExtraKey: `chain|openapi|${slice.length}`,
      });
      queued = await enqueueJobs(supa, jobs);
    }

    await supa.from("scan_logs").insert({
      target_id: targetId, log_type: "result",
      message: `📘 OpenAPI import done: ${endpoints.length} endpoints parsed, ${written} stored, ${queued} attack jobs queued`,
      metadata: { kind: "openapi_import_complete", endpoints: endpoints.length, written, queued, baseUrl },
    });

    return new Response(JSON.stringify({
      ok: true, endpoints: endpoints.length, written, queued, baseUrl,
    }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: e instanceof Error ? e.message : "err" }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
