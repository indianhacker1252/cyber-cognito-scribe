import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

function supabaseAdmin() {
  return createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
  );
}

async function safeFetch(url: string, opts: RequestInit = {}, timeoutMs = 8000): Promise<Response> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try { return await fetch(url, { ...opts, signal: ctrl.signal }); }
  finally { clearTimeout(timer); }
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
    const resp = await safeFetch(
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

// ─── 1b. Google Dorking for Subdomain & Param Discovery ───

async function googleDorkDiscovery(domain: string): Promise<{
  subdomains: string[];
  paramUrls: Array<{ url: string; params: Record<string, string> }>;
  juicyPaths: string[];
}> {
  const subdomains = new Set<string>();
  const paramUrls: Array<{ url: string; params: Record<string, string> }> = [];
  const juicyPaths: string[] = [];

  // Use multiple free search APIs/techniques
  const dorkQueries = [
    `site:*.${domain}`,                          // All subdomains
    `site:${domain} inurl:php?`,                 // PHP params
    `site:${domain} inurl:asp?`,                 // ASP params
    `site:${domain} inurl:jsp?`,                 // JSP params
    `site:${domain} inurl:api`,                  // API endpoints
    `site:${domain} inurl:admin`,                // Admin panels
    `site:${domain} inurl:login`,                // Login pages
    `site:${domain} ext:xml | ext:json | ext:conf`, // Config files
    `site:${domain} inurl:redirect | inurl:url= | inurl:next=`, // Open redirect params
    `site:${domain} inurl:file= | inurl:path= | inurl:page=`,   // LFI params
  ];

  // Use web.archive.org CDX API for param discovery (free, no API key needed)
  try {
    const cdxResp = await safeFetch(
      `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(domain)}/*&output=json&fl=original&collapse=urlkey&filter=mimetype:text/html&limit=500`,
      {}, 10000
    );
    if (cdxResp.ok) {
      const data = await cdxResp.json();
      for (let i = 1; i < data.length; i++) {
        const rawUrl = data[i][0];
        try {
          const u = new URL(rawUrl);
          // Extract subdomains
          if (u.hostname.endsWith(domain) && u.hostname !== domain) {
            subdomains.add(u.hostname);
          }
          // Extract URLs with parameters (gold for bug hunting)
          if (u.search) {
            const params: Record<string, string> = {};
            u.searchParams.forEach((v, k) => { params[k] = v; });
            paramUrls.push({ url: `${u.origin}${u.pathname}`, params });
          }
          // Detect juicy paths
          const path = u.pathname.toLowerCase();
          if (/\/(admin|api|dashboard|config|debug|test|backup|upload|download|internal|swagger|graphql)/.test(path)) {
            juicyPaths.push(`${u.origin}${u.pathname}`);
          }
        } catch { /* skip */ }
      }
    }
  } catch (e) {
    console.error("CDX param discovery error:", e);
  }

  // ── URLScan.io for additional subdomain/param discovery ──
  try {
    const urlscanResp = await safeFetch(
      `https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}&size=100`,
      { headers: { "User-Agent": "CyberScope-Recon/2.0" } }, 8000
    );
    if (urlscanResp.ok) {
      const data = await urlscanResp.json();
      for (const result of data.results || []) {
        const pageUrl = result.page?.url || "";
        try {
          const u = new URL(pageUrl);
          if (u.hostname.endsWith(domain) && u.hostname !== domain) {
            subdomains.add(u.hostname);
          }
          if (u.search) {
            const params: Record<string, string> = {};
            u.searchParams.forEach((v, k) => { params[k] = v; });
            paramUrls.push({ url: `${u.origin}${u.pathname}`, params });
          }
        } catch { /* skip */ }
      }
    }
  } catch { /* skip */ }

  // ── ThreatCrowd API for additional subdomain discovery ──
  try {
    const tcResp = await safeFetch(
      `https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=${encodeURIComponent(domain)}`,
      {}, 6000
    );
    if (tcResp.ok) {
      const data = await tcResp.json();
      for (const sub of data.subdomains || []) {
        if (sub.endsWith(domain)) subdomains.add(sub.toLowerCase());
      }
    }
  } catch { /* skip */ }

  return {
    subdomains: [...subdomains],
    paramUrls: paramUrls.slice(0, 200),
    juicyPaths: [...new Set(juicyPaths)].slice(0, 50),
  };
}

// ─── 1c. Probe Live Subdomains ───────────────────────────

async function probeLiveSubdomains(subdomains: string[]): Promise<Array<{ subdomain: string; status: number; server: string; redirect?: string }>> {
  const results: Array<{ subdomain: string; status: number; server: string; redirect?: string }> = [];
  const batch = subdomains.slice(0, 50); // Test up to 50 subdomains

  const promises = batch.map(async (sub) => {
    try {
      const resp = await safeFetch(`https://${sub}`, {
        method: "HEAD",
        headers: { "User-Agent": "Mozilla/5.0 CyberScope-Probe/1.0" },
        redirect: "manual",
      }, 4000);
      const server = resp.headers.get("server") || "";
      const location = resp.headers.get("location") || "";
      results.push({ subdomain: sub, status: resp.status, server, redirect: location || undefined });
    } catch {
      // Try HTTP fallback
      try {
        const resp = await safeFetch(`http://${sub}`, {
          method: "HEAD",
          headers: { "User-Agent": "Mozilla/5.0 CyberScope-Probe/1.0" },
          redirect: "manual",
        }, 3000);
        results.push({ subdomain: sub, status: resp.status, server: resp.headers.get("server") || "", redirect: resp.headers.get("location") || undefined });
      } catch { /* dead */ }
    }
  });

  // Run in batches of 10 to avoid overwhelming
  for (let i = 0; i < promises.length; i += 10) {
    await Promise.allSettled(promises.slice(i, i + 10));
    await new Promise(r => setTimeout(r, 200));
  }

  return results;
}

// ─── 2. Wayback Machine Harvesting ─────────────────────────

async function harvestWayback(
  domain: string
): Promise<{ url: string; timestamp: string }[]> {
  const urls: { url: string; timestamp: string }[] = [];
  try {
    const resp = await safeFetch(
      `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(
        domain
      )}/*&output=json&fl=timestamp,original&collapse=urlkey&limit=300`
    );
    if (resp.ok) {
      const data = await resp.json();
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
    const resp = await safeFetch(
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
        headers: { "User-Agent": "CyberScope-Spider/2.0" },
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

// ─── 3.6. JS Analysis — Extract API endpoints & secrets from JS files ──

async function analyzeJsFiles(jsFiles: string[]): Promise<{
  apiEndpoints: string[];
  potentialSecrets: Array<{ file: string; type: string; snippet: string }>;
  hiddenParams: string[];
}> {
  const apiEndpoints: string[] = [];
  const potentialSecrets: Array<{ file: string; type: string; snippet: string }> = [];
  const hiddenParams = new Set<string>();

  const secretPatterns = [
    { regex: /['"](AIza[0-9A-Za-z_-]{35})['"]/, type: "Google API Key" },
    { regex: /['"](?:sk_live|sk_test)_[0-9a-zA-Z]{24,}['"]/, type: "Stripe Key" },
    { regex: /['"]AKIA[0-9A-Z]{16}['"]/, type: "AWS Access Key" },
    { regex: /['"]ghp_[0-9a-zA-Z]{36}['"]/, type: "GitHub Token" },
    { regex: /['"]eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+/, type: "JWT Token" },
    { regex: /password\s*[:=]\s*['"][^'"]{4,}['"]/, type: "Hardcoded Password" },
    { regex: /api[_-]?key\s*[:=]\s*['"][^'"]{8,}['"]/, type: "API Key" },
    { regex: /secret\s*[:=]\s*['"][^'"]{8,}['"]/, type: "Secret" },
  ];

  const apiPatterns = [
    /['"]\/api\/v?\d*\/[^'"]+['"]/g,
    /['"]https?:\/\/[^'"]*\/api\/[^'"]+['"]/g,
    /fetch\s*\(\s*['"]([^'"]+)['"]/g,
    /axios\.\w+\s*\(\s*['"]([^'"]+)['"]/g,
    /\.get\s*\(\s*['"]([^'"]+)['"]/g,
    /\.post\s*\(\s*['"]([^'"]+)['"]/g,
  ];

  const paramPatterns = [
    /[?&](\w+)=/g,
    /params\.\s*(\w+)/g,
    /['"](\w+)['"]\s*:/g,
  ];

  for (const jsUrl of jsFiles.slice(0, 15)) {
    try {
      const resp = await safeFetch(jsUrl, { headers: { "User-Agent": "Mozilla/5.0" } }, 5000);
      if (!resp.ok) continue;
      const content = await resp.text();
      if (content.length > 500000) continue; // Skip huge files

      // Extract API endpoints
      for (const pattern of apiPatterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          const ep = match[1] || match[0].replace(/['"]/g, "");
          if (ep.startsWith("/") || ep.startsWith("http")) {
            apiEndpoints.push(ep);
          }
        }
      }

      // Extract secrets
      for (const { regex, type } of secretPatterns) {
        const match = content.match(regex);
        if (match) {
          potentialSecrets.push({
            file: jsUrl.split("/").pop() || jsUrl,
            type,
            snippet: match[0].slice(0, 80),
          });
        }
      }

      // Extract hidden params
      for (const pattern of paramPatterns) {
        let match;
        while ((match = pattern.exec(content)) !== null) {
          if (match[1] && match[1].length > 2 && match[1].length < 30) {
            hiddenParams.add(match[1]);
          }
        }
      }
    } catch { /* skip */ }
  }

  return {
    apiEndpoints: [...new Set(apiEndpoints)].slice(0, 100),
    potentialSecrets: potentialSecrets.slice(0, 20),
    hiddenParams: [...hiddenParams].slice(0, 50),
  };
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
      headers: { "User-Agent": "CyberScope-Scanner/2.0" },
    });

    for (const [key, value] of resp.headers.entries()) {
      const k = key.toLowerCase();
      result.headers[k] = value;
      if (k === "server") result.server = value;
      if (k === "x-powered-by") result.poweredBy = value;
      if (k === "set-cookie") result.cookies.push(value);
    }

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

    const html = await resp.text();
    if (html.includes("wp-content") || html.includes("wp-json")) result.framework = "WordPress";
    else if (html.includes("next/static") || html.includes("__NEXT_DATA__")) result.framework = "Next.js";
    else if (html.includes("ng-version") || html.includes("ng-app")) result.framework = "Angular";
    else if (html.includes("__NUXT__")) result.framework = "Nuxt.js";
    else if (html.includes("data-reactroot") || html.includes("__REACT")) result.framework = "React";
    else if (html.includes("Laravel")) result.framework = "Laravel";
    else if (html.includes("django") || html.includes("csrfmiddlewaretoken")) result.framework = "Django";
    else if (html.includes("rails") || html.includes("csrf-token")) result.framework = "Ruby on Rails";
    else if (html.includes("Flask") || html.includes("Werkzeug")) result.framework = "Flask";
    else if (html.includes("Express") || html.includes("x-powered-by: Express")) result.framework = "Express.js";
    else if (html.includes("Spring") || html.includes("JSESSIONID")) result.framework = "Spring";
  } catch (e) {
    console.error("Fingerprint error:", e);
  }
  return result;
}

// ─── 5. AI-Powered Recon Analysis ───────────────────────

async function aiAnalyzeTarget(
  domain: string,
  subdomains: string[],
  waybackUrls: string[],
  fingerprint: TechFingerprint,
  jsAnalysis: { apiEndpoints: string[]; potentialSecrets: Array<{ file: string; type: string; snippet: string }>; hiddenParams: string[] },
  dorkResults: { subdomains: string[]; paramUrls: Array<{ url: string; params: Record<string, string> }>; juicyPaths: string[] }
): Promise<{
  apiEndpoints: string[];
  hiddenParams: string[];
  securityNotes: string[];
}> {
  const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
  if (!LOVABLE_API_KEY) {
    return { apiEndpoints: [], hiddenParams: [], securityNotes: [] };
  }

  const prompt = `You are an ELITE offensive security researcher doing reconnaissance on a target. Think like a BLACK HAT HACKER looking for every possible entry point.

Target: ${domain}
Subdomains found (${subdomains.length}): ${subdomains.slice(0, 40).join(", ")}
Historical URLs (sample): ${waybackUrls.slice(0, 30).join(", ")}
Server: ${fingerprint.server || "unknown"}
Powered By: ${fingerprint.poweredBy || "unknown"}
Framework: ${fingerprint.framework || "unknown"}
WAF: ${fingerprint.waf || "none detected"}

JS Analysis:
- API endpoints found: ${jsAnalysis.apiEndpoints.slice(0, 20).join(", ")}
- Potential secrets: ${jsAnalysis.potentialSecrets.map(s => `${s.type} in ${s.file}`).join(", ") || "none"}
- Hidden params from JS: ${jsAnalysis.hiddenParams.slice(0, 30).join(", ")}

Google Dork Results:
- Juicy paths: ${dorkResults.juicyPaths.slice(0, 20).join(", ")}
- Param URLs found: ${dorkResults.paramUrls.length}

Based on this recon data, identify:
1. High-priority API endpoints worth testing for vulns (REST/GraphQL/hidden admin)
2. Hidden parameters that could be injectable (from JS, forms, URL patterns)
3. Attack surface observations: What would a bug bounty hunter target FIRST? What looks misconfigured? What's the most likely vulnerability class?`;

  try {
    const resp = await safeFetch(
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
            { role: "system", content: "You are an elite bug bounty hunter. Analyze recon data and identify the highest-value attack vectors. Be aggressive but legal. Return structured JSON only." },
            { role: "user", content: prompt },
          ],
          tools: [{
            type: "function",
            function: {
              name: "report_recon_findings",
              description: "Report reconnaissance findings",
              parameters: {
                type: "object",
                properties: {
                  apiEndpoints: { type: "array", items: { type: "string" }, description: "High-priority API endpoints to test" },
                  hiddenParams: { type: "array", items: { type: "string" }, description: "Hidden parameters worth testing" },
                  securityNotes: { type: "array", items: { type: "string" }, description: "Attack surface observations and priority targets" },
                },
                required: ["apiEndpoints", "hiddenParams", "securityNotes"],
                additionalProperties: false,
              },
            },
          }],
          tool_choice: { type: "function", function: { name: "report_recon_findings" } },
        }),
      }
    );

    if (resp.status === 429 || resp.status === 402) {
      return { apiEndpoints: [], hiddenParams: [], securityNotes: [`AI ${resp.status === 429 ? "rate limited" : "credits exhausted"}`] };
    }

    if (resp.ok) {
      const data = await resp.json();
      const toolCall = data.choices?.[0]?.message?.tool_calls?.[0];
      if (toolCall) return JSON.parse(toolCall.function.arguments);
    }
  } catch (e) {
    console.error("AI analysis error:", e);
  }
  return { apiEndpoints: [], hiddenParams: [], securityNotes: [] };
}

// ─── 6. Main Recon Pipeline ────────────────────────────────

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  try {
    const { targetId } = await req.json();
    if (!targetId) {
      return new Response(JSON.stringify({ error: "targetId is required" }), {
        status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const db = supabaseAdmin();
    const { data: target, error: tErr } = await db.from("target_workspaces").select("*").eq("id", targetId).single();
    if (tErr || !target) {
      return new Response(JSON.stringify({ error: "Target not found" }), {
        status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const domain = target.domain;
    if (!domain) {
      return new Response(JSON.stringify({ error: "Target has no domain configured" }), {
        status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const { data: task } = await db.from("agent_tasks")
      .insert({ target_id: targetId, task_type: "reconnaissance", status: "running" })
      .select().single();
    const taskId = task!.id;

    await db.from("target_workspaces").update({ status: "scanning" }).eq("id", targetId);
    await log(db, targetId, taskId, "info", `🔍 Elite recon pipeline started for ${domain}`);

    // ── Step 1: Parallel subdomain enumeration (crt.sh + Google Dorks + ThreatCrowd + URLScan) ──
    await log(db, targetId, taskId, "thought", `Enumerating ALL subdomains via crt.sh, Google Dorks, URLScan, ThreatCrowd for ${domain}`);

    const [crtSubdomains, dorkResults, waybackResults, otxResults] = await Promise.all([
      enumerateSubdomains(domain),
      googleDorkDiscovery(domain),
      harvestWayback(domain),
      harvestOTX(domain),
    ]);

    // Merge all subdomains
    const allSubdomains = [...new Set([...crtSubdomains, ...dorkResults.subdomains])];
    await log(db, targetId, taskId, "action", `Found ${allSubdomains.length} total subdomains (crt.sh: ${crtSubdomains.length}, dorks: ${dorkResults.subdomains.length})`);
    await log(db, targetId, taskId, "action", `🎯 Google Dorks found ${dorkResults.paramUrls.length} URLs with params, ${dorkResults.juicyPaths.length} juicy paths`);
    await log(db, targetId, taskId, "action", `Harvested ${waybackResults.length} Wayback URLs, ${otxResults.length} OTX URLs`);

    // ── Step 2: Probe live subdomains ──
    await log(db, targetId, taskId, "thought", `Probing ${allSubdomains.length} subdomains for live hosts`);
    const liveSubdomains = await probeLiveSubdomains(allSubdomains);
    const liveCount = liveSubdomains.filter(s => s.status < 400).length;
    await log(db, targetId, taskId, "result", `🟢 ${liveCount}/${allSubdomains.length} subdomains are LIVE`, { liveSubdomains: liveSubdomains.slice(0, 20) });

    // ── Step 3: Tech fingerprinting ──
    await log(db, targetId, taskId, "thought", `Fingerprinting technology stack for https://${domain}`);
    const fingerprint = await fingerprintTech(`https://${domain}`);
    await log(db, targetId, taskId, "result", `Tech stack: Server=${fingerprint.server || "unknown"}, Framework=${fingerprint.framework || "unknown"}, WAF=${fingerprint.waf || "none"}`, { fingerprint });

    // ── Step 4: Spider crawl on main domain + top live subdomains ──
    const spiderTargets = [domain, ...liveSubdomains.filter(s => s.status < 400).map(s => s.subdomain).slice(0, 5)];
    await log(db, targetId, taskId, "thought", `🕷️ Spider crawling ${spiderTargets.length} targets (main + top subdomains)`);

    let allSpiderUrls: string[] = [];
    let allForms: Array<{ action: string; method: string; inputs: string[] }> = [];
    let allJsFiles: string[] = [];

    for (const target of spiderTargets) {
      const spiderResults = await spiderCrawl(target, 20, 3);
      allSpiderUrls.push(...spiderResults.urls);
      allForms.push(...spiderResults.forms);
      allJsFiles.push(...spiderResults.jsFiles);
    }
    allJsFiles = [...new Set(allJsFiles)];
    allSpiderUrls = [...new Set(allSpiderUrls)];

    await log(db, targetId, taskId, "result", `🕷️ Spider found ${allSpiderUrls.length} links, ${allForms.length} forms, ${allJsFiles.length} JS files across ${spiderTargets.length} targets`);

    // ── Step 5: JS File Analysis — Extract secrets, API endpoints, hidden params ──
    await log(db, targetId, taskId, "thought", `🔍 Analyzing ${allJsFiles.length} JS files for secrets, API endpoints, hidden params`);
    const jsAnalysis = await analyzeJsFiles(allJsFiles);
    await log(db, targetId, taskId, "result", `JS Analysis: ${jsAnalysis.apiEndpoints.length} API endpoints, ${jsAnalysis.potentialSecrets.length} potential secrets, ${jsAnalysis.hiddenParams.length} hidden params`);

    if (jsAnalysis.potentialSecrets.length > 0) {
      await log(db, targetId, taskId, "result", `🔴 SECRETS FOUND IN JS: ${jsAnalysis.potentialSecrets.map(s => `${s.type} in ${s.file}`).join(", ")}`);
    }

    // ── Step 6: AI Analysis ──
    await log(db, targetId, taskId, "thought", `Running AI attack surface analysis on collected recon data`);
    const aiResults = await aiAnalyzeTarget(domain, allSubdomains, waybackResults.map(w => w.url), fingerprint, jsAnalysis, dorkResults);
    await log(db, targetId, taskId, "result", `AI identified ${aiResults.apiEndpoints.length} priority endpoints, ${aiResults.hiddenParams.length} hidden params`);

    for (const note of aiResults.securityNotes) {
      await log(db, targetId, taskId, "info", `[AI] ${note}`);
    }

    // ── Step 7: Normalize & Ingest ALL endpoints ──
    await log(db, targetId, taskId, "action", "Normalizing and deduplicating all discovered endpoints");

    const allUrls = new Map<string, { method: string; params: Record<string, unknown>; source: string }>();

    // Subdomains as root endpoints
    for (const sub of allSubdomains) {
      const key = `https://${sub}`;
      if (!allUrls.has(key)) allUrls.set(key, { method: "GET", params: {}, source: "subdomain" });
    }

    // Wayback URLs with params
    for (const wb of waybackResults) {
      try {
        const u = new URL(wb.url);
        const key = `${u.origin}${u.pathname}`;
        const params: Record<string, string> = {};
        u.searchParams.forEach((v, k) => (params[k] = v));
        if (!allUrls.has(key)) allUrls.set(key, { method: "GET", params, source: "wayback" });
      } catch { /* skip */ }
    }

    // OTX URLs
    for (const otx of otxResults) {
      try {
        const u = new URL(otx.url);
        const key = `${u.origin}${u.pathname}`;
        const params: Record<string, string> = {};
        u.searchParams.forEach((v, k) => (params[k] = v));
        if (!allUrls.has(key)) allUrls.set(key, { method: "GET", params, source: "otx" });
      } catch { /* skip */ }
    }

    // Google Dork param URLs (HIGH VALUE — real params from real users)
    for (const pu of dorkResults.paramUrls) {
      if (!allUrls.has(pu.url)) allUrls.set(pu.url, { method: "GET", params: pu.params, source: "google-dork" });
    }

    // Juicy paths from dorks
    for (const jp of dorkResults.juicyPaths) {
      if (!allUrls.has(jp)) allUrls.set(jp, { method: "GET", params: {}, source: "google-dork-juicy" });
    }

    // AI-inferred endpoints
    for (const ep of aiResults.apiEndpoints) {
      const key = ep.startsWith("http") ? ep : `https://${domain}${ep.startsWith("/") ? ep : "/" + ep}`;
      if (!allUrls.has(key)) allUrls.set(key, { method: "GET", params: {}, source: "ai-inferred" });
    }

    // JS-extracted API endpoints
    for (const ep of jsAnalysis.apiEndpoints) {
      const key = ep.startsWith("http") ? ep : `https://${domain}${ep.startsWith("/") ? ep : "/" + ep}`;
      if (!allUrls.has(key)) allUrls.set(key, { method: "GET", params: {}, source: "js-analysis" });
    }

    // Spider URLs
    for (const spUrl of allSpiderUrls) {
      try {
        const u = new URL(spUrl);
        const key = `${u.origin}${u.pathname}`;
        const params: Record<string, string> = {};
        u.searchParams.forEach((v, k) => (params[k] = v));
        if (!allUrls.has(key)) allUrls.set(key, { method: "GET", params, source: "spider" });
      } catch { /* skip */ }
    }

    // Spider forms
    for (const form of allForms) {
      const params: Record<string, string> = {};
      for (const input of form.inputs) { params[input] = "test"; }
      if (!allUrls.has(form.action)) allUrls.set(form.action, { method: form.method, params, source: "spider-form" });
    }

    // Batch insert endpoints
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

    // Store results
    await db.from("agent_tasks").update({
      status: "completed",
      result: {
        subdomains_found: allSubdomains.length,
        live_subdomains: liveCount,
        wayback_urls: waybackResults.length,
        otx_urls: otxResults.length,
        google_dork_param_urls: dorkResults.paramUrls.length,
        juicy_paths: dorkResults.juicyPaths.length,
        spider_urls: allSpiderUrls.length,
        spider_forms: allForms.length,
        js_files_analyzed: allJsFiles.length,
        js_api_endpoints: jsAnalysis.apiEndpoints.length,
        js_secrets_found: jsAnalysis.potentialSecrets.length,
        js_hidden_params: jsAnalysis.hiddenParams.length,
        endpoints_ingested: insertedCount,
        tech_fingerprint: fingerprint,
        ai_analysis: aiResults,
      },
    }).eq("id", taskId);

    await db.from("target_workspaces").update({ status: "completed" }).eq("id", targetId);

    await log(db, targetId, taskId, "info", `✅ Elite recon completed for ${domain} — ${insertedCount} endpoints, ${allSubdomains.length} subdomains (${liveCount} live), ${jsAnalysis.potentialSecrets.length} secrets found`);

    return new Response(JSON.stringify({
      success: true,
      subdomains: allSubdomains.length,
      liveSubdomains: liveCount,
      waybackUrls: waybackResults.length,
      otxUrls: otxResults.length,
      googleDorkParams: dorkResults.paramUrls.length,
      juicyPaths: dorkResults.juicyPaths.length,
      spiderUrls: allSpiderUrls.length,
      spiderForms: allForms.length,
      jsFilesAnalyzed: allJsFiles.length,
      jsSecretsFound: jsAnalysis.potentialSecrets.length,
      jsApiEndpoints: jsAnalysis.apiEndpoints.length,
      endpointsIngested: insertedCount,
      fingerprint,
    }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (e) {
    console.error("Recon engine error:", e);
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : "Unknown error" }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
