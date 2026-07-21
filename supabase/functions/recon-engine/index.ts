import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { resolveTargetProtocol, browserHeaders, BROWSER_UA } from "../_shared/security-gates.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

function supabaseAdmin() {
  return createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
}

async function safeFetch(url: string, opts: RequestInit = {}, timeoutMs = 8000): Promise<Response> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, { ...opts, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function log(
  db: ReturnType<typeof createClient>,
  targetId: string,
  taskId: string,
  type: "thought" | "action" | "result" | "error" | "info",
  message: string,
  metadata: Record<string, unknown> = {},
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
    const resp = await safeFetch(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, {
      headers: { Accept: "application/json" },
    });
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
  try {
    // Try both wildcard and exact-domain certificate searches. This used to be
    // accidentally outside the function, causing recon-engine to crash at
    // module load with undefined `domain` / `subdomains`.
    const resp2 = await safeFetch(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`, {
      headers: { Accept: "application/json" },
    });
    if (resp2.ok) {
      const data2 = await resp2.json();
      for (const entry of data2) {
        const names = (entry.name_value || "").split("\n");
        for (const name of names) {
          const clean = name.trim().toLowerCase().replace(/^\*\./, "");
          if (clean.endsWith(`.${domain}`) || clean === domain) subdomains.add(clean);
        }
      }
    }
  } catch {
    /* skip */
  }

  const COMMON_SUBS = [
    "www", "store", "shop", "api", "app", "m", "mobile", "cdn", "static", "media", "img", "images",
    "assets", "jobs", "careers", "blog", "news", "help", "support", "account", "accounts", "login", "auth",
    "sso", "checkout", "payment", "pay", "secure", "ssl", "admin", "portal", "dev", "staging", "beta", "test",
    "demo", "api2", "v2", "v1", "mail", "smtp", "ns1", "ns2", "ftp", "vpn", "remote", "partners",
    "wholesale", "b2b", "corporate", "enterprise", "analytics", "tracking", "tag", "pixel", "events", "webmail",
    "server", "mail2", "upload", "download", "alpha", "old", "new", "docs", "wiki", "status", "monitor",
    "dashboard", "panel", "oauth", "my", "user", "users", "cp", "cpanel", "whm", "webdisk", "autodiscover",
    "autoconfig", "imap", "pop", "pop3", "exchange", "owa", "web", "crm", "erp", "hr", "intranet", "internal",
    "corp", "office", "backup", "db", "database", "sql", "mysql", "mongo", "redis", "elastic", "kibana", "grafana",
    "jenkins", "gitlab", "git", "svn", "jira", "confluence", "bitbucket", "sonar", "nexus", "registry", "docker",
    "k8s", "kubernetes", "rancher", "traefik", "nginx", "apache", "proxy", "lb", "load", "fw",
  ];

  const passiveSources = await Promise.allSettled([
    safeFetch(`https://api.hackertarget.com/hostsearch/?q=${domain}`, {}, 8000).then(async (r) => {
      if (!r.ok) return [] as string[];
      const text = await r.text();
      return text.split("\n").map((line) => line.split(",")[0]?.trim().toLowerCase()).filter(Boolean) as string[];
    }),
    safeFetch(`https://rapiddns.io/subdomain/${domain}?full=1`, {}, 8000).then(async (r) => {
      if (!r.ok) return [] as string[];
      const text = await r.text();
      return [...text.matchAll(/<td>([a-z0-9.-]+\.[a-z]{2,})<\/td>/gi)].map((m) => m[1].toLowerCase());
    }),
    safeFetch(`https://api.certspotter.com/v1/issuances?domain=${domain}&include_subdomains=true&expand=dns_names`, {}, 10000).then(async (r) => {
      if (!r.ok) return [] as string[];
      const data = await r.json();
      return (data || []).flatMap((cert: any) => (cert.dns_names || []).map((n: string) => n.replace(/^\*\./, "").toLowerCase()));
    }),
  ]);
  for (const src of passiveSources) {
    if (src.status !== "fulfilled") continue;
    for (const host of src.value) if (host && host.endsWith(domain)) subdomains.add(host);
  }

  const dnsResults = await Promise.allSettled(
    COMMON_SUBS.map(async (sub) => {
      const fqdn = `${sub}.${domain}`;
      try {
        const r = await safeFetch(`https://${fqdn}`, { method: "HEAD", redirect: "manual", headers: { "User-Agent": "Mozilla/5.0" } }, 3000);
        if (r.status > 0) return fqdn;
      } catch {
        /* dead */
      }
      return null;
    }),
  );
  for (const r of dnsResults) if (r.status === "fulfilled" && r.value) subdomains.add(r.value);

  return [...subdomains];
}
// ─── 1b. Google Dorking for Subdomain & Param Discovery ───

const DORK_CATEGORIES = {
  subdomains: (d: string) => [`site:*.${d}`, `site:*.*.${d}`],
  sensitiveFiles: (d: string) => [
    `site:${d} ext:xml | ext:json | ext:conf | ext:env | ext:yml`,
    `site:${d} ext:sql | ext:bak | ext:log | ext:old | ext:swp`,
    `site:${d} ext:php.bak | ext:asp.bak | ext:jsp.bak`,
    `site:${d} intitle:"index of" | intitle:"directory listing"`,
    `site:${d} filetype:pdf | filetype:xlsx | filetype:doc confidential`,
  ],
  authEndpoints: (d: string) => [
    `site:${d} inurl:login | inurl:signin | inurl:auth`,
    `site:${d} inurl:admin | inurl:panel | inurl:dashboard | inurl:cms`,
    `site:${d} inurl:register | inurl:signup | inurl:forgot`,
    `site:${d} inurl:oauth | inurl:sso | inurl:callback`,
    `site:${d} inurl:token | inurl:jwt | inurl:session`,
  ],
  apiDiscovery: (d: string) => [
    `site:${d} inurl:api | inurl:v1 | inurl:v2 | inurl:v3`,
    `site:${d} inurl:graphql | inurl:graphiql`,
    `site:${d} inurl:swagger | inurl:openapi | inurl:api-docs`,
    `site:${d} inurl:rest | inurl:endpoint | inurl:webhook`,
    `site:${d} inurl:ws:// | inurl:wss://`,
  ],
  injectableParams: (d: string) => [
    `site:${d} inurl:php? | inurl:asp? | inurl:aspx? | inurl:jsp?`,
    `site:${d} inurl:id= | inurl:uid= | inurl:pid= | inurl:nid=`,
    `site:${d} inurl:file= | inurl:path= | inurl:page= | inurl:include=`,
    `site:${d} inurl:redirect= | inurl:url= | inurl:next= | inurl:return=`,
    `site:${d} inurl:q= | inurl:query= | inurl:search= | inurl:s=`,
    `site:${d} inurl:sort= | inurl:order= | inurl:column= | inurl:dir=`,
    `site:${d} inurl:action= | inurl:cmd= | inurl:exec= | inurl:command=`,
    `site:${d} inurl:upload | inurl:import | inurl:export`,
    `site:${d} inurl:debug= | inurl:test= | inurl:dev=`,
  ],
  infoLeak: (d: string) => [
    `site:${d} "error" | "warning" | "stack trace" | "debug"`,
    `site:${d} "mysql" | "syntax error" | "unexpected" | "ORA-"`,
    `site:${d} "phpinfo()" | "server at" | "apache" | "nginx"`,
    `site:${d} inurl:.git | inurl:.svn | inurl:.env | inurl:.htaccess`,
    `"${d}" password | api_key | secret | token site:github.com | site:gitlab.com | site:pastebin.com`,
  ],
  cloudInfra: (d: string) => [
    `site:s3.amazonaws.com "${d}"`,
    `site:blob.core.windows.net "${d}"`,
    `site:storage.googleapis.com "${d}"`,
    `site:${d} inurl:aws | inurl:azure | inurl:gcp`,
  ],
};

async function googleDorkDiscovery(domain: string): Promise<{
  subdomains: string[];
  paramUrls: Array<{ url: string; params: Record<string, string> }>;
  juicyPaths: string[];
  dorkCategories: Record<string, number>;
}> {
  const subdomains = new Set<string>();
  const paramUrls: Array<{ url: string; params: Record<string, string> }> = [];
  const juicyPaths: string[] = [];
  const dorkCategories: Record<string, number> = {};

  // Build all dork queries from all categories
  const allDorks: string[] = [];
  for (const [cat, fn] of Object.entries(DORK_CATEGORIES)) {
    const queries = fn(domain);
    dorkCategories[cat] = queries.length;
    allDorks.push(...queries);
  }

  // Use web.archive.org CDX API for param discovery (free, no API key needed)
  try {
    const cdxResp = await safeFetch(
      `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(domain)}/*&output=json&fl=original&collapse=urlkey&filter=mimetype:text/html&limit=500`,
      {},
      10000,
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
            u.searchParams.forEach((v, k) => {
              params[k] = v;
            });
            paramUrls.push({ url: `${u.origin}${u.pathname}`, params });
          }
          // Detect juicy paths
          const path = u.pathname.toLowerCase();
          if (/\/(admin|api|dashboard|config|debug|test|backup|upload|download|internal|swagger|graphql)/.test(path)) {
            juicyPaths.push(`${u.origin}${u.pathname}`);
          }
        } catch {
          /* skip */
        }
      }
    }
  } catch (e) {
    console.error("CDX param discovery error:", e);
  }

  // ── URLScan.io for additional subdomain/param discovery ──
  try {
    const urlscanResp = await safeFetch(
      `https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}&size=100`,
      { headers: { "User-Agent": "CyberScope-Recon/2.0" } },
      8000,
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
            u.searchParams.forEach((v, k) => {
              params[k] = v;
            });
            paramUrls.push({ url: `${u.origin}${u.pathname}`, params });
          }
        } catch {
          /* skip */
        }
      }
    }
  } catch {
    /* skip */
  }

  // ── ThreatCrowd API for additional subdomain discovery ──
  try {
    const tcResp = await safeFetch(
      `https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=${encodeURIComponent(domain)}`,
      {},
      6000,
    );
    if (tcResp.ok) {
      const data = await tcResp.json();
      for (const sub of data.subdomains || []) {
        if (sub.endsWith(domain)) subdomains.add(sub.toLowerCase());
      }
    }
  } catch {
    /* skip */
  }

  return {
    subdomains: [...subdomains],
    paramUrls: paramUrls.slice(0, 200),
    juicyPaths: [...new Set(juicyPaths)].slice(0, 50),
    dorkCategories,
  };
}

// ─── 1c. Probe Live Subdomains ───────────────────────────

async function probeLiveSubdomains(
  subdomains: string[],
): Promise<Array<{ subdomain: string; status: number; server: string; redirect?: string }>> {
  const results: Array<{ subdomain: string; status: number; server: string; redirect?: string }> = [];
  const batch = subdomains.slice(0, 50); // Test up to 50 subdomains

  const promises = batch.map(async (sub) => {
    try {
      const resp = await safeFetch(
        `https://${sub}`,
        {
          method: "HEAD",
          headers: { "User-Agent": "Mozilla/5.0 CyberScope-Probe/1.0" },
          redirect: "manual",
        },
        4000,
      );
      const server = resp.headers.get("server") || "";
      const location = resp.headers.get("location") || "";
      results.push({ subdomain: sub, status: resp.status, server, redirect: location || undefined });
    } catch {
      // Try HTTP fallback
      try {
        const resp = await safeFetch(
          `http://${sub}`,
          {
            method: "HEAD",
            headers: { "User-Agent": "Mozilla/5.0 CyberScope-Probe/1.0" },
            redirect: "manual",
          },
          3000,
        );
        results.push({
          subdomain: sub,
          status: resp.status,
          server: resp.headers.get("server") || "",
          redirect: resp.headers.get("location") || undefined,
        });
      } catch {
        /* dead */
      }
    }
  });

  // Run in batches of 10 to avoid overwhelming
  for (let i = 0; i < promises.length; i += 10) {
    await Promise.allSettled(promises.slice(i, i + 10));
    await new Promise((r) => setTimeout(r, 200));
  }

  return results;
}

// ─── 2. Wayback Machine Harvesting ─────────────────────────

async function harvestWayback(domain: string): Promise<{ url: string; timestamp: string }[]> {
  const urls: { url: string; timestamp: string }[] = [];
  try {
    const resp = await safeFetch(
      `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(
        domain,
      )}/*&output=json&fl=timestamp,original&collapse=urlkey&limit=300`,
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

async function harvestOTX(domain: string): Promise<{ url: string; type: string }[]> {
  const results: { url: string; type: string }[] = [];
  try {
    const resp = await safeFetch(
      `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/url_list?limit=100`,
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
  maxPages = 100,
  maxDepth = 5,
  scheme: "https" | "http" = "https",
): Promise<{ urls: string[]; forms: Array<{ action: string; method: string; inputs: string[] }>; jsFiles: string[] }> {
  const visited = new Set<string>();
  const discovered: string[] = [];
  const forms: Array<{ action: string; method: string; inputs: string[] }> = [];
  const jsFiles: string[] = [];
  const queue: Array<{ url: string; depth: number }> = [{ url: `${scheme}://${domain}`, depth: 0 }];

  while (queue.length > 0 && visited.size < maxPages) {
    const item = queue.shift();
    if (!item || item.depth > maxDepth) continue;
    if (visited.has(item.url)) continue;
    visited.add(item.url);

    try {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), 6000);
      // Rule 6: Inject browser UA so legacy WAFs don't drop the request.
      const resp = await fetch(item.url, {
        method: "GET",
        headers: browserHeaders(),
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
          else if (href.startsWith("//")) fullUrl = `${scheme}:${href}`;
          else if (href.startsWith("/")) fullUrl = `${scheme}://${domain}${href}`;
          else fullUrl = `${item.url.replace(/\/[^/]*$/, "/")}${href}`;

          const parsed = new URL(fullUrl);
          if (parsed.hostname.endsWith(domain) && !visited.has(fullUrl)) {
            discovered.push(fullUrl);
            if (item.depth + 1 <= maxDepth) {
              queue.push({ url: `${parsed.origin}${parsed.pathname}`, depth: item.depth + 1 });
            }
          }
        } catch {
          /* skip malformed */
        }
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
            action = action.startsWith("/")
              ? `https://${domain}${action}`
              : `${item.url.replace(/\/[^/]*$/, "/")}${action}`;
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
    } catch {
      /* skip failed pages */
    }
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

  const paramPatterns = [/[?&](\w+)=/g, /params\.\s*(\w+)/g, /['"](\w+)['"]\s*:/g];

  for (const jsUrl of jsFiles.slice(0, 40)) {
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
    } catch {
      /* skip */
    }
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
      headers: browserHeaders(),
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
  jsAnalysis: {
    apiEndpoints: string[];
    potentialSecrets: Array<{ file: string; type: string; snippet: string }>;
    hiddenParams: string[];
  },
  dorkResults: {
    subdomains: string[];
    paramUrls: Array<{ url: string; params: Record<string, string> }>;
    juicyPaths: string[];
  },
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
- Potential secrets: ${jsAnalysis.potentialSecrets.map((s) => `${s.type} in ${s.file}`).join(", ") || "none"}
- Hidden params from JS: ${jsAnalysis.hiddenParams.slice(0, 30).join(", ")}

Google Dork Results:
- Juicy paths: ${dorkResults.juicyPaths.slice(0, 20).join(", ")}
- Param URLs found: ${dorkResults.paramUrls.length}

Based on this recon data, identify:
1. High-priority API endpoints worth testing for vulns (REST/GraphQL/hidden admin)
2. Hidden parameters that could be injectable (from JS, forms, URL patterns)
3. Attack surface observations: What would a bug bounty hunter target FIRST? What looks misconfigured? What's the most likely vulnerability class?`;

  try {
    const resp = await safeFetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
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
              "You are an elite bug bounty hunter. Analyze recon data and identify the highest-value attack vectors. Be aggressive but legal. Return structured JSON only.",
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
                    description: "High-priority API endpoints to test",
                  },
                  hiddenParams: {
                    type: "array",
                    items: { type: "string" },
                    description: "Hidden parameters worth testing",
                  },
                  securityNotes: {
                    type: "array",
                    items: { type: "string" },
                    description: "Attack surface observations and priority targets",
                  },
                },
                required: ["apiEndpoints", "hiddenParams", "securityNotes"],
                additionalProperties: false,
              },
            },
          },
        ],
        tool_choice: { type: "function", function: { name: "report_recon_findings" } },
      }),
    });

    if (resp.status === 429 || resp.status === 402) {
      return {
        apiEndpoints: [],
        hiddenParams: [],
        securityNotes: [`AI ${resp.status === 429 ? "rate limited" : "credits exhausted"}`],
      };
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
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const db = supabaseAdmin();
    const { data: target, error: tErr } = await db.from("target_workspaces").select("*").eq("id", targetId).single();
    if (tErr || !target) {
      return new Response(JSON.stringify({ error: "Target not found" }), {
        status: 404,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const domain = target.domain;
    if (!domain) {
      return new Response(JSON.stringify({ error: "Target has no domain configured" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const { data: task } = await db
      .from("agent_tasks")
      .insert({ target_id: targetId, task_type: "reconnaissance", status: "running" })
      .select()
      .single();
    const taskId = task!.id;

    await db
      .from("target_workspaces")
      .update({
        status: "scanning",
        resolved_protocol: SCHEME, // FIX: persist resolved protocol for all downstream modules
      })
      .eq("id", targetId);
    await log(db, targetId, taskId, "info", `🔍 Elite recon pipeline started for ${domain}`);
    // Synthesize injectable endpoints from dork patterns even without CDX data
    const INJECTABLE_PARAM_PATTERNS = [
      { path: "/search", params: { q: "", s: "", query: "" } },
      { path: "/products", params: { id: "", category: "", sort: "", page: "" } },
      { path: "/api/v1/search", params: { q: "", term: "" } },
      { path: "/api/v2/products", params: { id: "", filter: "" } },
      { path: "/account/login", params: { redirect: "", next: "", return_url: "" } },
      { path: "/checkout", params: { redirect: "", return: "" } },
      { path: "/api/user", params: { id: "", uid: "" } },
      { path: "/collections", params: { sort_by: "", page: "" } },
      { path: "/?s", params: { s: "" } },
    ];

    for (const pat of INJECTABLE_PARAM_PATTERNS) {
      const url = `${SCHEME}://${domain}${pat.path}`;
      if (!allUrls.has(url)) {
        allUrls.set(url, { method: "GET", params: pat.params, source: "synthetic-injectable" });
      }
    }
    // ── Step 0: Protocol fallback engine (Rule 1) ──
    // Test https first with a strict 3000ms timeout. If it drops/times out,
    // downgrade to http so the spider/fingerprint never hangs on legacy targets.
    await log(
      db,
      targetId,
      taskId,
      "thought",
      `🔌 Resolving protocol for ${domain} (https first, 3s timeout, http fallback)`,
    );
    const resolved = await resolveTargetProtocol(domain, 3000);
    if (resolved.downgraded) {
      await log(
        db,
        targetId,
        taskId,
        "action",
        `⬇️  HTTPS unreachable (${resolved.reason || "timeout"}) — downgraded to http://`,
        { resolved },
      );
    } else {
      await log(db, targetId, taskId, "info", `🔒 Using ${resolved.scheme}:// for ${domain}`, { resolved });
    }
    const SCHEME = resolved.scheme;

    // ── Step 1: Parallel subdomain enumeration (crt.sh + Google Dorks + ThreatCrowd + URLScan) ──
    await log(
      db,
      targetId,
      taskId,
      "thought",
      `Enumerating ALL subdomains via crt.sh, Google Dorks, URLScan, ThreatCrowd for ${domain}`,
    );

    const [crtSubdomains, dorkResults, waybackResults, otxResults] = await Promise.all([
      enumerateSubdomains(domain),
      googleDorkDiscovery(domain),
      harvestWayback(domain),
      harvestOTX(domain),
    ]);

    // Merge all subdomains
    const allSubdomains = [...new Set([...crtSubdomains, ...dorkResults.subdomains])];
    await log(
      db,
      targetId,
      taskId,
      "action",
      `Found ${allSubdomains.length} total subdomains (crt.sh: ${crtSubdomains.length}, dorks: ${dorkResults.subdomains.length})`,
    );
    await log(
      db,
      targetId,
      taskId,
      "action",
      `🎯 Google Dorks found ${dorkResults.paramUrls.length} URLs with params, ${dorkResults.juicyPaths.length} juicy paths`,
    );
    await log(
      db,
      targetId,
      taskId,
      "action",
      `Harvested ${waybackResults.length} Wayback URLs, ${otxResults.length} OTX URLs`,
    );

    // ── Step 2: Probe live subdomains ──
    await log(db, targetId, taskId, "thought", `Probing ${allSubdomains.length} subdomains for live hosts`);
    const liveSubdomains = await probeLiveSubdomains(allSubdomains);
    const liveCount = liveSubdomains.filter((s) => s.status < 400).length;
    await log(db, targetId, taskId, "result", `🟢 ${liveCount}/${allSubdomains.length} subdomains are LIVE`, {
      liveSubdomains: liveSubdomains.slice(0, 20),
    });
    // ── MISSING: Store live subdomains into scan_assets so all attack modules can find them ──
    const assetRows = liveSubdomains
      .filter((s) => s.status < 400)
      .map((s) => ({
        target_id: targetId,
        host: s.subdomain,
        base_url: `https://${s.subdomain}`,
        source: "recon-subdomain",
        status_code: s.status,
        server_header: s.server || null,
        discovered_at: new Date().toISOString(),
      }));

    if (assetRows.length > 0) {
      await db.from("scan_assets").upsert(assetRows, { onConflict: "target_id,host" });
      await log(
        db,
        targetId,
        taskId,
        "action",
        `📦 Stored ${assetRows.length} live subdomains into scan_assets for attack modules`,
      );
    }

    // Also spider crawl ALL live subdomains — not just top 5
    const allLiveHosts = liveSubdomains.filter((s) => s.status < 400).map((s) => s.subdomain);
    // (existing code uses slice(0,5) — REMOVE that limit)

    // ── Step 3: Tech fingerprinting (uses resolved scheme) ──
    await log(db, targetId, taskId, "thought", `Fingerprinting technology stack for ${SCHEME}://${domain}`);
    const fingerprint = await fingerprintTech(`${SCHEME}://${domain}`);
    await log(
      db,
      targetId,
      taskId,
      "result",
      `Tech stack: Server=${fingerprint.server || "unknown"}, Framework=${fingerprint.framework || "unknown"}, WAF=${fingerprint.waf || "none"}`,
      { fingerprint },
    );

    // ── Step 4: Spider crawl on main domain + top live subdomains ──
    const spiderTargets = [domain, ...liveSubdomains.filter((s) => s.status < 400).map((s) => s.subdomain)]; // ← No limit
    await log(
      db,
      targetId,
      taskId,
      "thought",
      `🕷️ Spider crawling ${spiderTargets.length} targets via ${SCHEME}:// (main + top subdomains)`,
    );

    let allSpiderUrls: string[] = [];
    let allForms: Array<{ action: string; method: string; inputs: string[] }> = [];
    let allJsFiles: string[] = [];

    for (const target of spiderTargets) {
      const spiderResults = await spiderCrawl(target, 20, 3, SCHEME);
      allSpiderUrls.push(...spiderResults.urls);
      allForms.push(...spiderResults.forms);
      allJsFiles.push(...spiderResults.jsFiles);
    }
    allJsFiles = [...new Set(allJsFiles)];
    allSpiderUrls = [...new Set(allSpiderUrls)];

    // Bug #4 fix — if HTTP spider found almost nothing, target is likely an SPA.
    // Fall back to headless-browser to render JS and harvest real links/forms.
    if (allSpiderUrls.length < 5) {
      await log(
        db,
        targetId,
        taskId,
        "thought",
        `🌐 SPA suspected — only ${allSpiderUrls.length} static links. Switching to headless browser`,
      );
      try {
        const hbRes = await safeFetch(
          `${Deno.env.get("SUPABASE_URL")}/functions/v1/headless-browser`,
          {
            method: "POST",
            headers: {
              Authorization: `Bearer ${Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")}`,
              "Content-Type": "application/json",
            },
            body: JSON.stringify({ targetId, url: `${SCHEME}://${domain}` }),
          },
          25000,
        );
        if (hbRes.ok) {
          const hbData: any = await hbRes.json().catch(() => ({}));
          // Fix #11 — headless-browser actually returns `endpoints`, not `urls`. Accept either.
          const hbUrls: string[] = Array.isArray(hbData?.endpoints)
            ? hbData.endpoints
            : Array.isArray(hbData?.urls)
              ? hbData.urls
              : [];
          const hbForms: any[] = Array.isArray(hbData?.forms) ? hbData.forms : [];
          allSpiderUrls.push(...hbUrls);
          allForms.push(...hbForms);
          allSpiderUrls = [...new Set(allSpiderUrls)];
          await log(
            db,
            targetId,
            taskId,
            "result",
            `🌐 Headless browser added ${hbUrls.length} URLs, ${hbForms.length} forms`,
          );
        } else {
          await log(db, targetId, taskId, "info", `headless-browser returned ${hbRes.status}`);
        }
      } catch (e) {
        await log(db, targetId, taskId, "error", `headless-browser fallback failed: ${(e as Error).message}`);
      }
    }

    await log(
      db,
      targetId,
      taskId,
      "result",
      `🕷️ Spider found ${allSpiderUrls.length} links, ${allForms.length} forms, ${allJsFiles.length} JS files across ${spiderTargets.length} targets`,
      {
        sampleLinks: allSpiderUrls.slice(0, 20),
        sampleForms: allForms.slice(0, 10).map((f) => ({ action: f.action, method: f.method, inputs: f.inputs })),
        sampleJsFiles: allJsFiles.slice(0, 10),
      },
    );

    // ── Step 5: JS File Analysis — Extract secrets, API endpoints, hidden params ──
    await log(
      db,
      targetId,
      taskId,
      "thought",
      `🔍 Analyzing ${allJsFiles.length} JS files for secrets, API endpoints, hidden params`,
    );
    const jsAnalysis = await analyzeJsFiles(allJsFiles);
    await log(
      db,
      targetId,
      taskId,
      "result",
      `JS Analysis: ${jsAnalysis.apiEndpoints.length} API endpoints, ${jsAnalysis.potentialSecrets.length} potential secrets, ${jsAnalysis.hiddenParams.length} hidden params`,
    );

    if (jsAnalysis.potentialSecrets.length > 0) {
      await log(
        db,
        targetId,
        taskId,
        "result",
        `🔴 SECRETS FOUND IN JS: ${jsAnalysis.potentialSecrets.map((s) => `${s.type} in ${s.file}`).join(", ")}`,
      );
      // Part A — push secrets into the global findings queue (was previously dropped)
      try {
        const { recordFinding } = await import("../_shared/findings-writer.ts");
        for (const sec of jsAnalysis.potentialSecrets) {
          const sev = /private key|AWS|secret/i.test(sec.type) ? "critical" : "high";
          await recordFinding({
            targetId,
            source: "recon-secret",
            category: "secret-exposure",
            severity: sev as any,
            title: `${sec.type} exposed in JavaScript bundle`,
            description: `Static analysis of ${sec.file} extracted a literal ${sec.type}. Even read-only keys allow quota abuse, billing fraud, and pivoting; private keys allow full impersonation.`,
            payload: sec.snippet,
            poc: `curl -s https://${domain}/${sec.file} | grep -E '${sec.type.replace(/[^a-z0-9]/gi, ".")}'`,
            proofTier: "exploited", // literal secret in public asset is self-proving
            evidence: { file: sec.file, type: sec.type, snippet: sec.snippet },
            scanLogId: taskId,
          });
        }
      } catch (e) {
        console.error("recordFinding(secret) failed", e);
      }
    }

    // ── Step 6: AI Analysis ──
    await log(db, targetId, taskId, "thought", `Running AI attack surface analysis on collected recon data`);
    const aiResults = await aiAnalyzeTarget(
      domain,
      allSubdomains,
      waybackResults.map((w) => w.url),
      fingerprint,
      jsAnalysis,
      dorkResults,
    );
    await log(
      db,
      targetId,
      taskId,
      "result",
      `AI identified ${aiResults.apiEndpoints.length} priority endpoints, ${aiResults.hiddenParams.length} hidden params`,
    );

    for (const note of aiResults.securityNotes) {
      await log(db, targetId, taskId, "info", `[AI] ${note}`);
    }

    // ── Step 7: Normalize & Ingest ALL endpoints ──
    await log(db, targetId, taskId, "action", "Normalizing and deduplicating all discovered endpoints");

    const allUrls = new Map<string, { method: string; params: Record<string, unknown>; source: string }>();

    // Fix #13 — normalize URLs to dedupe http/https + www. variants of the same endpoint.
    // Strategy: prefer HTTPS, strip leading "www.", lowercase host, drop trailing slash, drop fragments.
    // FIX: normalizeUrl now respects the resolved protocol (SCHEME) instead of
    // force-upgrading every endpoint to https. This was the root cause of all
    // error(0, 0b, 0ms) results on HTTP-only targets — every variant test was
    // hitting https:// on a server that only speaks http://.
    const normalizeUrl = (raw: string, preferScheme?: string): string => {
      try {
        const u = new URL(raw);
        // Only override protocol if a preference is given AND the URL is not
        // already using a non-http scheme (e.g. ws://, ftp://)
        if (preferScheme && (u.protocol === "http:" || u.protocol === "https:")) {
          u.protocol = preferScheme + ":";
        }
        u.hash = "";
        u.hostname = u.hostname.toLowerCase().replace(/^www\./, "");
        if (u.pathname.length > 1 && u.pathname.endsWith("/")) u.pathname = u.pathname.replace(/\/+$/, "");
        return u.toString();
      } catch {
        return raw;
      }
    };
    const setUrl = (rawKey: string, info: { method: string; params: Record<string, unknown>; source: string }) => {
      const key = normalizeUrl(rawKey, SCHEME);
      if (!allUrls.has(key)) allUrls.set(key, info);
    };

    // Subdomains as root endpoints
    for (const sub of allSubdomains) {
      const key = `https://${sub}`;
      if (!allUrls.has(key)) allUrls.set(key, { method: "GET", params: {}, source: "subdomain" });
    }

    // Wayback URLs with params
    for (const wb of waybackResults) {
      try {
        const u = new URL(wb.url);
        // FIX: was `${u.origin}${u.pathname}` — bypassed normalizeUrl entirely,
        // so Wayback's historically-archived scheme (often https://) overrode
        // the SCHEME this recon run actually determined was reachable. On
        // HTTP-only targets this silently stored every wayback-discovered
        // endpoint (including textbook-vulnerable ones) as https://, dooming
        // every subsequent probe to fail/timeout against a dead HTTPS port.
        const key = normalizeUrl(`${u.origin}${u.pathname}`, SCHEME);
        const params: Record<string, string> = {};
        u.searchParams.forEach((v, k) => (params[k] = v));
        if (!allUrls.has(key)) allUrls.set(key, { method: "GET", params, source: "wayback" });
      } catch {
        /* skip */
      }
    }

    // OTX URLs
    for (const otx of otxResults) {
      try {
        const u = new URL(otx.url);
        const key = normalizeUrl(`${u.origin}${u.pathname}`, SCHEME);
        const params: Record<string, string> = {};
        u.searchParams.forEach((v, k) => (params[k] = v));
        if (!allUrls.has(key)) allUrls.set(key, { method: "GET", params, source: "otx" });
      } catch {
        /* skip */
      }
    }

    // Google Dork param URLs (HIGH VALUE — real params from real users)
    for (const pu of dorkResults.paramUrls) {
      if (!allUrls.has(pu.url)) allUrls.set(pu.url, { method: "GET", params: pu.params, source: "google-dork" });
    }

    // Juicy paths from dorks
    for (const jp of dorkResults.juicyPaths) {
      const key = normalizeUrl(jp, SCHEME);
      if (!allUrls.has(key)) allUrls.set(key, { method: "GET", params: {}, source: "google-dork-juicy" });
    }

    // AI-inferred endpoints
    for (const ep of aiResults.apiEndpoints) {
      const key = ep.startsWith("http")
        ? normalizeUrl(ep, SCHEME)
        : normalizeUrl(`${SCHEME}://${domain}${ep.startsWith("/") ? ep : "/" + ep}`, SCHEME);
      if (!allUrls.has(key)) allUrls.set(key, { method: "GET", params: {}, source: "ai-inferred" });
    }

    // JS-extracted API endpoints
    for (const ep of jsAnalysis.apiEndpoints) {
      const key = ep.startsWith("http")
        ? normalizeUrl(ep, SCHEME)
        : normalizeUrl(`${SCHEME}://${domain}${ep.startsWith("/") ? ep : "/" + ep}`, SCHEME);
      if (!allUrls.has(key)) allUrls.set(key, { method: "GET", params: {}, source: "js-analysis" });
    }

    // Spider URLs
    for (const spUrl of allSpiderUrls) {
      try {
        const u = new URL(spUrl);
        const key = normalizeUrl(`${u.origin}${u.pathname}`, SCHEME);
        const params: Record<string, string> = {};
        u.searchParams.forEach((v, k) => (params[k] = v));
        if (!allUrls.has(key)) allUrls.set(key, { method: "GET", params, source: "spider" });
      } catch {
        /* skip */
      }
    }

    // Spider forms
    for (const form of allForms) {
      const params: Record<string, string> = {};
      for (const input of form.inputs) {
        params[input] = "test";
      }
      if (!allUrls.has(form.action)) allUrls.set(form.action, { method: form.method, params, source: "spider-form" });
    }

    // Persist form STRUCTURE to discovered_forms so form-attacker has real
    // data to POST-fuzz. Without this, only the form's action URL survived
    // (as a generic fuzzable endpoint) — the field names, method, and
    // file-upload detection were discarded, so form-attacker always found
    // "0 forms" unless dom-fuzz happened to run separately and repopulate
    // the same table on its own initiative.
    if (allForms.length > 0) {
      const formRows = allForms.map((form) => ({
        target_id: targetId,
        page_url: domain,
        action_url: form.action,
        method: (form.method || "POST").toUpperCase(),
        enctype: form.inputs.some((i) => /file|upload|attachment/i.test(i))
          ? "multipart/form-data"
          : "application/x-www-form-urlencoded",
        fields: form.inputs.map((name) => ({ name, type: /file|upload/i.test(name) ? "file" : "text" })),
        has_file_upload: form.inputs.some((i) => /file|upload|attachment/i.test(i)),
      }));
      try {
        await db.from("discovered_forms").upsert(formRows as any, {
          onConflict: "target_id,action_url,method",
          ignoreDuplicates: true,
        });
      } catch {
        /* best-effort — dom-fuzz can still backfill later */
      }
    }

    // Collapse http/https and www. duplicates — use SCHEME so HTTP targets stay HTTP
    const normalizedMap = new Map<string, { method: string; params: Record<string, unknown>; source: string }>();
    for (const [url, info] of allUrls.entries()) {
      const key = normalizeUrl(url, SCHEME);
      if (!normalizedMap.has(key)) normalizedMap.set(key, info);
    }

    // Batch insert endpoints
    const endpoints = [...normalizedMap.entries()].map(([url, info]) => ({
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

    await log(db, targetId, taskId, "result", `Ingested ${insertedCount} unique endpoints into database`, {
      sampleEndpoints: endpoints
        .slice(0, 20)
        .map((e) => ({ url: e.url, method: e.method, source: (e.headers as any)?.source })),
    });

    // Store results
    await db
      .from("agent_tasks")
      .update({
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
      })
      .eq("id", taskId);

    // Persist detected tech so cve-to-exploit / ai-intruder / advanced-fuzzer
    // can actually see the target's stack (they all read `detected_tech`).
    const techArr = Array.from(new Set(
      [fingerprint.server, fingerprint.poweredBy, fingerprint.framework, fingerprint.waf]
        .filter(Boolean)
        .map((s) => String(s).toLowerCase())
    ));
    await db.from("target_workspaces").update({
      status: "completed",
      detected_tech: techArr,
      tech_fingerprint: fingerprint,
      tech_stack: techArr,
    }).eq("id", targetId);

    await log(
      db,
      targetId,
      taskId,
      "info",
      `✅ Elite recon completed for ${domain} — ${insertedCount} endpoints, ${allSubdomains.length} subdomains (${liveCount} live), ${jsAnalysis.potentialSecrets.length} secrets found`,
    );

    return new Response(
      JSON.stringify({
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
      }),
      {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      },
    );
  } catch (e) {
    console.error("Recon engine error:", e);
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : "Unknown error" }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
