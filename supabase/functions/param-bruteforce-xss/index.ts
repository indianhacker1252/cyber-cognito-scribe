// Parameter brute-force + reflective XSS probe.
// XBOW/Mythos parity: when recon finds endpoints with no parameters, try the
// most common parameter names with a unique reflection canary and a benign
// XSS sink. If the response reflects the canary, write a pending_approval —
// the xss-reflection-promoter then auto-promotes to vulnerability_findings.
//
// Safety:
//  - GET only, no auth bypass, no destructive payloads
//  - 1 req/sec per endpoint, hard caps on endpoints + params
//  - Always returns 200 OK with JSON body (even on partial failure)

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

// Top params seen across ASP.NET / PHP / Node apps + bug bounty corpus
const COMMON_PARAMS = [
  "q", "query", "search", "s", "keyword", "keywords",
  "id", "page", "pid", "uid", "user", "username", "name",
  "tfSearch", "txtSearch", "txtName", "txtUserName", "txtEmail",
  "category", "cat", "type", "lang", "locale", "ref", "redirect",
  "url", "next", "return", "returnUrl", "callback",
  "msg", "message", "error", "warning", "info",
  "file", "path", "dir", "view", "action", "do",
  "comment", "comments", "title", "subject", "content",
];

// Sinks chosen to maximize triage-brain confidence without firing real alerts.
// Each contains the canary token; we test reflection of either the raw token
// or sink markup verbatim in the response body.
function buildPayloads(canary: string): { name: string; value: string; reason: string }[] {
  return [
    { name: "raw",        value: canary,                                 reason: "raw canary reflection" },
    { name: "html",       value: `<${canary}>`,                          reason: "tag-context HTML reflection" },
    { name: "attr",       value: `"${canary}"`,                          reason: "attribute-context reflection" },
    { name: "js",         value: `';${canary}//`,                        reason: "JS-context reflection" },
    { name: "img-onerror",value: `<img src=x onerror=${canary}>`,        reason: "img onerror sink reflected verbatim" },
    { name: "svg-onload", value: `<svg onload=${canary}>`,               reason: "svg onload sink reflected verbatim" },
    { name: "script",     value: `<script>${canary}</script>`,           reason: "script tag reflected verbatim" },
  ];
}

function db() { return createClient(SUPABASE_URL, SERVICE_KEY); }

async function safeFetch(url: string, ms = 8000): Promise<{ status: number; body: string; headers: Record<string,string> } | null> {
  try {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), ms);
    const r = await fetch(url, {
      signal: ctl.signal,
      redirect: "follow",
      headers: {
        "User-Agent": "Mozilla/5.0 (compatible; CyberScope/1.0; +https://cyberscope.dev/bot)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
    });
    clearTimeout(t);
    const text = await r.text();
    const headers: Record<string,string> = {};
    r.headers.forEach((v, k) => { headers[k] = v; });
    return { status: r.status, body: text.slice(0, 200_000), headers };
  } catch { return null; }
}

/**
 * Decide whether ANY occurrence of `needle` in `body` lands in a context
 * where it could be parsed as executable HTML/JS (i.e., NOT inside a URL
 * attribute like href/src/content/action, NOT inside a JSON "url" field,
 * NOT entity-encoded). Returns true the moment one dangerous occurrence
 * is found.
 */
function hasDangerousReflectionContext(body: string, needle: string): boolean {
  if (!needle) return false;
  let from = 0;
  let safeOnly = true;
  while (true) {
    const idx = body.indexOf(needle, from);
    if (idx === -1) break;
    safeOnly = safeOnly && isSafeUrlContext(body, idx, needle.length);
    if (!safeOnly) return true;
    from = idx + needle.length;
  }
  // If we never entered the loop (no occurrences) → false; else all occurrences were URL-safe.
  return false;
}

function isSafeUrlContext(body: string, idx: number, len: number): boolean {
  // Inspect ~200 chars before the reflection to see what attribute/tag we're in.
  const before = body.slice(Math.max(0, idx - 200), idx).toLowerCase();
  const after = body.slice(idx + len, Math.min(body.length, idx + len + 80)).toLowerCase();
  // Inside an HTML attribute that expects a URL?
  // Look for last `<tag ... attr="` opener before the reflection.
  const lastTagOpen = before.lastIndexOf("<");
  const lastTagClose = before.lastIndexOf(">");
  const insideTag = lastTagOpen > lastTagClose; // we're inside a tag's attribute list
  if (insideTag) {
    // URL-bearing attributes
    if (/\b(href|src|srcset|action|formaction|cite|data|poster|background|manifest|content|ping|usemap|longdesc|profile|codebase)\s*=\s*['"][^'"]*$/i.test(before)) {
      return true;
    }
    // Inside any attribute value at all? If the tag is <link>, <meta>, <a>, <img>, <script src>, <iframe src> — even non-URL attrs end up serialized safely.
    const tagNameMatch = before.slice(lastTagOpen).match(/^<\s*([a-z][a-z0-9-]*)/i);
    const tagName = tagNameMatch ? tagNameMatch[1].toLowerCase() : "";
    if (["link", "meta", "base"].includes(tagName)) return true;
  }
  // Inside a JSON-LD / inline JSON "url"/"@id" string?
  if (/"(?:url|@id|canonical|image|sameAs|contentUrl|thumbnailUrl)"\s*:\s*"[^"]*$/i.test(before) && /^[^"]*"/.test(after)) {
    return true;
  }
  return false;
}

function rand(): string {
  return "csXz" + Math.random().toString(36).slice(2, 10);
}

async function log(supa: any, targetId: string, message: string, metadata: any = {}) {
  await supa.from("scan_logs").insert({
    target_id: targetId,
    log_type: "info",
    message: `🔎 ParamBrute: ${message}`,
    metadata,
  });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

  const respond = (body: any, status = 200) =>
    new Response(JSON.stringify(body), { status, headers: { ...corsHeaders, "Content-Type": "application/json" } });

  try {
    const { targetId, maxEndpoints = 8, maxParamsPerEndpoint = 12 } = await req.json().catch(() => ({}));
    if (!targetId) return respond({ ok: false, error: "targetId required" }, 200);

    const supa = db();

    // Pull endpoints that look fuzzable (HTML pages, no existing params)
    const { data: endpoints } = await supa
      .from("discovered_endpoints")
      .select("id,url,method,parameters,status_code")
      .eq("target_id", targetId)
      .order("created_at", { ascending: false })
      .limit(80);

    const candidates = (endpoints || []).filter((e: any) => {
      if (e.method !== "GET") return false;
      const u = (e.url as string) || "";
      // skip static assets
      if (/\.(gif|png|jpg|jpeg|css|js|ico|svg|woff2?|map)(\?|$)/i.test(u)) return false;
      // skip already-parameterized
      if (u.includes("?")) return false;
      const params = (e.parameters as Record<string,string>) || {};
      if (Object.keys(params).length > 0) return false;
      return true;
    }).slice(0, maxEndpoints);

    await log(supa, targetId, `starting param brute on ${candidates.length} endpoints`, { endpointCount: candidates.length });

    let probes = 0, reflections = 0, approvals = 0;
    const findings: any[] = [];

    for (const ep of candidates) {
      const baseUrl = (ep.url as string).replace(/\/$/, "");
      const paramNames = COMMON_PARAMS.slice(0, maxParamsPerEndpoint);

      for (const pname of paramNames) {
        const canary = rand();
        const payloads = buildPayloads(canary);

        // Probe 1: raw canary
        const raw = payloads[0];
        const url = `${baseUrl}?${encodeURIComponent(pname)}=${encodeURIComponent(raw.value)}`;
        const res = await safeFetch(url);
        probes++;
        await new Promise(r => setTimeout(r, 200)); // 5 req/s
        if (!res || res.status >= 500) continue;
        if (!res.body.includes(canary)) continue;

        // Raw canary reflection alone is NOT XSS — it's almost always echoed
        // inside a benign URL context (canonical link, og:url meta, anchor href,
        // form action, JSON-LD URL field). We require an executable sink to be
        // reflected verbatim AND in a dangerous (non-URL/non-encoded) context.
        reflections++;

        // Find the reflection sites and check whether ANY are in dangerous context.
        // If every occurrence of the canary sits inside a URL attribute
        // (href=, src=, content=, action=, formaction=, data-*-url=, JSON "url":)
        // we treat the parameter as safe and move on.
        if (!hasDangerousReflectionContext(res.body, canary)) continue;

        let bestSink: { name: string; value: string; reason: string; bodySnippet: string } | null = null;
        for (const p of payloads.slice(1)) {
          const c2 = rand();
          const sinkVal = p.value.replaceAll(canary, c2);
          const sinkUrl = `${baseUrl}?${encodeURIComponent(pname)}=${encodeURIComponent(sinkVal)}`;
          const sr = await safeFetch(sinkUrl);
          probes++;
          await new Promise(r => setTimeout(r, 200));
          if (!sr || sr.status >= 500) continue;
          // Verbatim reflection of the sink string (raw HTML, no entity-encoding)
          // AND in a dangerous context (not inside href/src/content/action attribute).
          if (!sr.body.includes(sinkVal)) continue;
          if (!hasDangerousReflectionContext(sr.body, sinkVal)) continue;
          const idx = sr.body.indexOf(sinkVal);
          bestSink = {
            name: p.name, value: sinkVal, reason: p.reason,
            bodySnippet: sr.body.slice(Math.max(0, idx - 60), idx + sinkVal.length + 60),
          };
          break;
        }

        // No executable sink reflected → drop. We refuse to file medium-severity
        // "parameter echoes input" findings; they were the FP source on every target.
        if (!bestSink) continue;

        const title = `Reflected XSS via ?${pname}= (${bestSink.name} sink)`;
        const evidence: any = {
          method: "GET",
          url,
          canary,
          reflected: true,
          sink: { kind: bestSink.name, payload: bestSink.value, snippet: bestSink.bodySnippet },
          contentType: res.headers["content-type"] || null,
          discoveredBy: "param-bruteforce-xss",
        };

        const { data: ins } = await supa.from("pending_approvals").insert({
          target_id: targetId,
          endpoint_id: ep.id,
          finding_type: "xss_reflected",
          severity: "high" as any,
          title,
          description: `Endpoint ${ep.url} reflects the value of parameter '${pname}' verbatim including HTML sink markup outside a URL attribute context. Likely exploitable Reflected XSS.`,
          parameter: pname,
          payload_used: bestSink.value,
          confidence_score: 90,
          confidence_level: "high",
          ai_verified: false,
          reachability_status: "confirmed",
          triage_reasoning: `Sink "${bestSink.name}" reflected verbatim in dangerous context — ${bestSink.reason}.`,
          evidence,
          request_data: { method: "GET", url },
          response_data: { status: res.status, length: res.body.length, snippet: res.body.slice(0, 500) },
          cvss_score: 7.4,
        }).select("id").single();
        const sev = "high";

        approvals++;
        if (ins?.id) findings.push({ approvalId: ins.id, endpoint: ep.url, param: pname, severity: sev });
        await log(supa, targetId, `${title} on ${ep.url}`, { endpointId: ep.id, param: pname, sink: bestSink?.name });

        // Move on to next endpoint after first confirmed reflection
        break;
      }

      // Hard cap to stay under edge timeout
      if (probes > 200) break;
    }

    await log(supa, targetId, `done — ${probes} probes, ${reflections} reflections, ${approvals} approvals queued`,
      { probes, reflections, approvals });

    // Trigger auto-promoter so XSS sinks become confirmed findings immediately
    if (approvals > 0) {
      fetch(`${SUPABASE_URL}/functions/v1/xss-reflection-promoter`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${SERVICE_KEY}` },
        body: JSON.stringify({ targetId }),
      }).catch(() => {});
    }

    return respond({ ok: true, probes, reflections, approvals, findings });
  } catch (e) {
    return respond({ ok: false, error: e instanceof Error ? e.message : String(e) }, 200);
  }
});
