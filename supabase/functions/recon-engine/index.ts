import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

// ─── Helpers ───────────────────────────────────────────────

function supabaseAdmin() {
  return createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
  );
}

async function log(
  db: ReturnType<typeof createClient>,
  targetId: string,
  taskId: string,
  type: "thought" | "action" | "result" | "error" | "info",
  message: string,
  metadata: Record<string, unknown> = {}
) {
  await db.from("scan_logs").insert({
    target_id: targetId,
    task_id: taskId,
    log_type: type,
    message,
    metadata,
  });
}

// ─── 1. Subdomain Enumeration (crt.sh) ────────────────────

async function enumerateSubdomains(domain: string): Promise<string[]> {
  const subdomains = new Set<string>();
  try {
    const resp = await fetch(
      `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`,
      { headers: { Accept: "application/json" } }
    );
    if (resp.ok) {
      const data = await resp.json();
      for (const entry of data) {
        const names = (entry.name_value || "").split("\n");
        for (const name of names) {
          const clean = name.trim().toLowerCase().replace(/^\*\./, "");
          if (clean.endsWith(domain) && clean.length > 0) {
            subdomains.add(clean);
          }
        }
      }
    }
  } catch (e) {
    console.error("crt.sh error:", e);
  }
  return [...subdomains];
}

// ─── 2. Wayback Machine Harvesting ─────────────────────────

async function harvestWayback(
  domain: string
): Promise<{ url: string; timestamp: string }[]> {
  const urls: { url: string; timestamp: string }[] = [];
  try {
    const resp = await fetch(
      `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(
        domain
      )}/*&output=json&fl=timestamp,original&collapse=urlkey&limit=200`
    );
    if (resp.ok) {
      const data = await resp.json();
      // First row is headers
      for (let i = 1; i < data.length; i++) {
        urls.push({ timestamp: data[i][0], url: data[i][1] });
      }
    }
  } catch (e) {
    console.error("Wayback error:", e);
  }
  return urls;
}

// ─── 3. OTX AlienVault Passive DNS ─────────────────────────

async function harvestOTX(
  domain: string
): Promise<{ url: string; type: string }[]> {
  const results: { url: string; type: string }[] = [];
  try {
    const resp = await fetch(
      `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(
        domain
      )}/url_list?limit=100`
    );
    if (resp.ok) {
      const data = await resp.json();
      for (const entry of data.url_list || []) {
        results.push({ url: entry.url, type: "otx" });
      }
    }
  } catch (e) {
    console.error("OTX error:", e);
  }
  return results;
}

// ─── 3.5. Spider Crawler — Deep Link & Form Extraction ─────

async function spiderCrawl(
  domain: string,
  maxPages = 30,
  maxDepth = 3
): Promise<{ urls: string[]; forms: Array<{ action: string; method: string; inputs: string[] }>; jsFiles: string[] }> {
  const visited = new Set<string>();
  const discovered: string[] = [];
  const forms: Array<{ action: string; method: string; inputs: string[] }> = [];
  const jsFiles: string[] = [];
  const queue: Array<{ url: string; depth: number }> = [{ url: `https://${domain}`, depth: 0 }];

  while (queue.length > 0 && visited.size < maxPages) {
    const item = queue.shift();
    if (!item || item.depth > maxDepth) continue;
    if (visited.has(item.url)) continue;
    visited.add(item.url);

    try {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), 6000);
      const resp = await fetch(item.url, {
        method: "GET",
        headers: { "User-Agent": "CyberScope-Spider/1.0" },
        redirect: "follow",
        signal: ctrl.signal,
      });
      clearTimeout(timer);

      if (!resp.ok) continue;
      const contentType = resp.headers.get("content-type") || "";
      if (!contentType.includes("text/html")) continue;

      const html = await resp.text();

      // Extract links
      const linkRegex = /href\s*=\s*["']([^"'#]+)["']/gi;
      let match;
      while ((match = linkRegex.exec(html)) !== null) {
        try {
          const href = match[1];
          let fullUrl: string;
          if (href.startsWith("http")) fullUrl = href;
          else if (href.startsWith("//")) fullUrl = `https:${href}`;
          else if (href.startsWith("/")) fullUrl = `https://${domain}${href}`;
          else fullUrl = `${item.url.replace(/\/[^/]*$/, "/")}${href}`;

          const parsed = new URL(fullUrl);
          if (parsed.hostname.endsWith(domain) && !visited.has(fullUrl)) {
            discovered.push(fullUrl);
            if (item.depth + 1 <= maxDepth) {
              queue.push({ url: `${parsed.origin}${parsed.pathname}`, depth: item.depth + 1 });
            }
          }
        } catch { /* skip malformed */ }
      }

      // Extract forms with inputs
      const formRegex = /<form[^>]*>([\s\S]*?)<\/form>/gi;
      while ((match = formRegex.exec(html)) !== null) {
        const formTag = match[0];
        const actionMatch = formTag.match(/action\s*=\s*["']([^"']+)["']/i);
        const methodMatch = formTag.match(/method\s*=\s*["']([^"']+)["']/i);
        const inputRegex = /name\s*=\s*["']([^"']+)["']/gi;
        const inputs: string[] = [];
        let inputMatch;
        while ((inputMatch = inputRegex.exec(formTag)) !== null) {
          inputs.push(inputMatch[1]);
        }
        if (inputs.length > 0) {
          let action = actionMatch?.[1] || item.url;
          if (!action.startsWith("http")) {
            action = action.startsWith("/") ? `https://${domain}${action}` : `${item.url.replace(/\/[^/]*$/, "/")}${action}`;
          }
          forms.push({ action, method: (methodMatch?.[1] || "GET").toUpperCase(), inputs });
        }
      }

      // Extract JS files
      const jsRegex = /src\s*=\s*["']([^"']+\.js(?:\?[^"']*)?)["']/gi;
      while ((match = jsRegex.exec(html)) !== null) {
        let jsSrc = match[1];
        if (!jsSrc.startsWith("http")) {
          jsSrc = jsSrc.startsWith("/") ? `https://${domain}${jsSrc}` : `${item.url.replace(/\/[^/]*$/, "/")}${jsSrc}`;
        }
        jsFiles.push(jsSrc);
      }

      await new Promise((r) => setTimeout(r, 150));
    } catch { /* skip failed pages */ }
  }

  return { urls: [...new Set(discovered)], forms, jsFiles: [...new Set(jsFiles)] };
}

// ─── 4. Technology Fingerprinting ──────────────────────────

interface TechFingerprint {
  server?: string;
  poweredBy?: string;
  framework?: string;
  waf?: string;
  cookies: string[];
  headers: Record<string, string>;
}

async function fingerprintTech(url: string): Promise<TechFingerprint> {
  const result: TechFingerprint = { cookies: [], headers: {} };
  try {
    const resp = await fetch(url, {
      method: "GET",
      redirect: "follow",
      headers: { "User-Agent": "CyberScope-Scanner/1.0" },
    });

    // Collect relevant headers
    for (const [key, value] of resp.headers.entries()) {
      const k = key.toLowerCase();
      result.headers[k] = value;

      if (k === "server") result.server = value;
      if (k === "x-powered-by") result.poweredBy = value;
      if (k === "set-cookie") result.cookies.push(value);
    }

    // WAF detection
    const wafSignatures: Record<string, string[]> = {
      Cloudflare: ["cf-ray", "cf-cache-status", "__cfduid"],
      Akamai: ["x-akamai-transformed", "akamai-origin-hop"],
      "AWS WAF": ["x-amzn-requestid", "x-amz-cf-id"],
      Sucuri: ["x-sucuri-id"],
      Imperva: ["x-iinfo"],
    };

    for (const [waf, sigs] of Object.entries(wafSignatures)) {
      for (const sig of sigs) {
        if (resp.headers.has(sig) || result.cookies.some((c) => c.includes(sig))) {
          result.waf = waf;
          break;
        }
      }
      if (result.waf) break;
    }

    // Framework detection from HTML
    const html = await resp.text();
    if (html.includes("wp-content") || html.includes("wp-json"))
      result.framework = "WordPress";
    else if (html.includes("next/static") || html.includes("__NEXT_DATA__"))
      result.framework = "Next.js";
    else if (html.includes("ng-version") || html.includes("ng-app"))
      result.framework = "Angular";
    else if (html.includes("__NUXT__")) result.framework = "Nuxt.js";
    else if (html.includes("data-reactroot") || html.includes("__REACT"))
      result.framework = "React";
    else if (html.includes("Laravel")) result.framework = "Laravel";
    else if (html.includes("django") || html.includes("csrfmiddlewaretoken"))
      result.framework = "Django";
    else if (html.includes("rails") || html.includes("csrf-token"))
      result.framework = "Ruby on Rails";
  } catch (e) {
    console.error("Fingerprint error:", e);
  }
  return result;
}

// ─── 5. AI-Powered JS/Parameter Analysis ───────────────────

async function aiAnalyzeTarget(
  domain: string,
  subdomains: string[],
  waybackUrls: string[],
  fingerprint: TechFingerprint
): Promise<{
  apiEndpoints: string[];
  hiddenParams: string[];
  securityNotes: string[];
}> {
  const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
  if (!LOVABLE_API_KEY) {
    return { apiEndpoints: [], hiddenParams: [], securityNotes: [] };
  }

  const prompt = `You are a security reconnaissance AI. Analyze this target and extract security-relevant intelligence.

Target: ${domain}
Subdomains found (${subdomains.length}): ${subdomains.slice(0, 30).join(", ")}
Historical URLs (sample): ${waybackUrls.slice(0, 30).join(", ")}
Server: ${fingerprint.server || "unknown"}
Powered By: ${fingerprint.poweredBy || "unknown"}
Framework: ${fingerprint.framework || "unknown"}
WAF: ${fingerprint.waf || "none detected"}

Based on this recon data, identify:
1. Likely API endpoints (REST/GraphQL patterns from URLs)
2. Hidden parameters worth testing (CSRF tokens, debug params, admin paths)
3. Security observations and attack surface notes`;

  try {
    const resp = await fetch(
      "https://ai.gateway.lovable.dev/v1/chat/completions",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${LOVABLE_API_KEY}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model: "google/gemini-3-flash-preview",
          messages: [
            {
              role: "system",
              content:
                "You are a VAPT reconnaissance AI. Return structured JSON only.",
            },
            { role: "user", content: prompt },
          ],
          tools: [
            {
              type: "function",
              function: {
                name: "report_recon_findings",
                description: "Report reconnaissance findings",
                parameters: {
                  type: "object",
                  properties: {
                    apiEndpoints: {
                      type: "array",
                      items: { type: "string" },
                      description: "Discovered or inferred API endpoints",
                    },
                    hiddenParams: {
                      type: "array",
                      items: { type: "string" },
                      description:
                        "Hidden parameters worth testing (csrf, debug, admin)",
                    },
                    securityNotes: {
                      type: "array",
                      items: { type: "string" },
                      description: "Security observations and attack surface notes",
                    },
                  },
                  required: ["apiEndpoints", "hiddenParams", "securityNotes"],
                  additionalProperties: false,
                },
              },
            },
          ],
          tool_choice: {
            type: "function",
            function: { name: "report_recon_findings" },
          },
        }),
      }
    );

    if (resp.status === 429) {
      return {
        apiEndpoints: [],
        hiddenParams: [],
        securityNotes: ["AI rate limited — skipping analysis"],
      };
    }
    if (resp.status === 402) {
      return {
        apiEndpoints: [],
        hiddenParams: [],
        securityNotes: ["AI credits exhausted"],
      };
    }

    if (resp.ok) {
      const data = await resp.json();
      const toolCall = data.choices?.[0]?.message?.tool_calls?.[0];
      if (toolCall) {
        return JSON.parse(toolCall.function.arguments);
      }
    }
  } catch (e) {
    console.error("AI analysis error:", e);
  }
  return { apiEndpoints: [], hiddenParams: [], securityNotes: [] };
}

// ─── 6. Main Recon Pipeline ────────────────────────────────

serve(async (req) => {
  if (req.method === "OPTIONS")
    return new Response(null, { headers: corsHeaders });

  try {
    const { targetId } = await req.json();
    if (!targetId) {
      return new Response(
        JSON.stringify({ error: "targetId is required" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const db = supabaseAdmin();

    // Fetch target
    const { data: target, error: tErr } = await db
      .from("target_workspaces")
      .select("*")
      .eq("id", targetId)
      .single();

    if (tErr || !target) {
      return new Response(
        JSON.stringify({ error: "Target not found" }),
        { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const domain = target.domain;
    if (!domain) {
      return new Response(
        JSON.stringify({ error: "Target has no domain configured" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Create agent task
    const { data: task } = await db
      .from("agent_tasks")
      .insert({
        target_id: targetId,
        task_type: "reconnaissance",
        status: "running",
      })
      .select()
      .single();

    const taskId = task!.id;

    // Update target status
    await db
      .from("target_workspaces")
      .update({ status: "scanning" })
      .eq("id", targetId);

    await log(db, targetId, taskId, "info", `Recon pipeline started for ${domain}`);

    // ── Step 1: Subdomain enumeration ──
    await log(db, targetId, taskId, "thought", `Enumerating subdomains via Certificate Transparency for ${domain}`);
    const subdomains = await enumerateSubdomains(domain);
    await log(db, targetId, taskId, "action", `Found ${subdomains.length} subdomains via crt.sh`, { subdomains: subdomains.slice(0, 50) });

    // ── Step 2: Wayback Machine ──
    await log(db, targetId, taskId, "thought", `Querying Wayback Machine for historical URLs of ${domain}`);
    const waybackResults = await harvestWayback(domain);
    await log(db, targetId, taskId, "action", `Harvested ${waybackResults.length} historical URLs from Wayback Machine`);

    // ── Step 3: OTX AlienVault ──
    await log(db, targetId, taskId, "thought", `Querying OTX AlienVault for passive DNS data on ${domain}`);
    const otxResults = await harvestOTX(domain);
    await log(db, targetId, taskId, "action", `Retrieved ${otxResults.length} URLs from OTX AlienVault`);

    // ── Step 4: Tech fingerprinting ──
    await log(db, targetId, taskId, "thought", `Fingerprinting technology stack for https://${domain}`);
    const fingerprint = await fingerprintTech(`https://${domain}`);
    await log(db, targetId, taskId, "result", `Tech stack: Server=${fingerprint.server || "unknown"}, Framework=${fingerprint.framework || "unknown"}, WAF=${fingerprint.waf || "none"}`, { fingerprint });

    // ── Step 5: AI Analysis ──
    await log(db, targetId, taskId, "thought", `Running AI analysis on collected recon data for ${domain}`);
    const aiResults = await aiAnalyzeTarget(
      domain,
      subdomains,
      waybackResults.map((w) => w.url),
      fingerprint
    );
    await log(db, targetId, taskId, "result", `AI identified ${aiResults.apiEndpoints.length} API endpoints, ${aiResults.hiddenParams.length} hidden params`, { aiResults });

    for (const note of aiResults.securityNotes) {
      await log(db, targetId, taskId, "info", `[AI] ${note}`);
    }

    // ── Step 6: Normalize & Ingest ──
    await log(db, targetId, taskId, "action", "Normalizing and deduplicating discovered endpoints");

    const allUrls = new Map<string, { method: string; params: Record<string, unknown>; source: string }>();

    // Subdomains as root endpoints
    for (const sub of subdomains) {
      const key = `https://${sub}`;
      if (!allUrls.has(key)) {
        allUrls.set(key, { method: "GET", params: {}, source: "crt.sh" });
      }
    }

    // Wayback URLs
    for (const wb of waybackResults) {
      try {
        const u = new URL(wb.url);
        const key = `${u.origin}${u.pathname}`;
        const params: Record<string, string> = {};
        u.searchParams.forEach((v, k) => (params[k] = v));
        if (!allUrls.has(key)) {
          allUrls.set(key, { method: "GET", params, source: "wayback" });
        }
      } catch {
        // skip malformed URLs
      }
    }

    // OTX URLs
    for (const otx of otxResults) {
      try {
        const u = new URL(otx.url);
        const key = `${u.origin}${u.pathname}`;
        const params: Record<string, string> = {};
        u.searchParams.forEach((v, k) => (params[k] = v));
        if (!allUrls.has(key)) {
          allUrls.set(key, { method: "GET", params, source: "otx" });
        }
      } catch {
        // skip
      }
    }

    // AI-inferred endpoints
    for (const ep of aiResults.apiEndpoints) {
      const key = ep.startsWith("http") ? ep : `https://${domain}${ep.startsWith("/") ? ep : "/" + ep}`;
      if (!allUrls.has(key)) {
        allUrls.set(key, { method: "GET", params: {}, source: "ai-inferred" });
      }
    }

    // Batch insert endpoints (max 100 at a time)
    const endpoints = [...allUrls.entries()].map(([url, info]) => ({
      target_id: targetId,
      url,
      method: info.method,
      parameters: info.params,
      headers: { source: info.source },
    }));

    let insertedCount = 0;
    for (let i = 0; i < endpoints.length; i += 100) {
      const batch = endpoints.slice(i, i + 100);
      const { error: insertErr } = await db.from("discovered_endpoints").insert(batch);
      if (!insertErr) insertedCount += batch.length;
    }

    await log(db, targetId, taskId, "result", `Ingested ${insertedCount} unique endpoints into database`);

    // Store fingerprint as metadata in task result
    await db
      .from("agent_tasks")
      .update({
        status: "completed",
        result: {
          subdomains_found: subdomains.length,
          wayback_urls: waybackResults.length,
          otx_urls: otxResults.length,
          endpoints_ingested: insertedCount,
          tech_fingerprint: fingerprint,
          ai_analysis: aiResults,
        },
      })
      .eq("id", taskId);

    await db
      .from("target_workspaces")
      .update({ status: "completed" })
      .eq("id", targetId);

    await log(db, targetId, taskId, "info", `✅ Recon pipeline completed for ${domain} — ${insertedCount} endpoints mapped`);

    return new Response(
      JSON.stringify({
        success: true,
        subdomains: subdomains.length,
        waybackUrls: waybackResults.length,
        otxUrls: otxResults.length,
        endpointsIngested: insertedCount,
        fingerprint,
      }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (e) {
    console.error("Recon engine error:", e);
    return new Response(
      JSON.stringify({ error: e instanceof Error ? e.message : "Unknown error" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
