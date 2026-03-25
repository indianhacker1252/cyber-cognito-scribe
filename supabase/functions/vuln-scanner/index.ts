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

// ─── SAFE PAYLOADS ONLY ──────────────────────────────────
const FORBIDDEN_PATTERNS = [
  /drop\s+table/i, /truncate/i, /delete\s+from/i, /rm\s+-rf/i,
  /shutdown/i, /<script[^>]*>.*<\/script>/i, /exec\s*\(/i,
  /xp_cmdshell/i, /eval\s*\(/i, /format\s+c:/i,
];

function isSafePayload(payload: string): boolean {
  return !FORBIDDEN_PATTERNS.some((p) => p.test(payload));
}

// ─── 1. COMPREHENSIVE HEURISTIC ROUTER ──────────────────
// Maps parameters to OWASP vulnerability classes

interface VulnCheck {
  paramName: string;
  paramValue: string;
  vulnClasses: string[];
  url: string;
  endpointId: string;
}

function classifyParameters(
  endpoints: Array<{ id: string; url: string; parameters: Record<string, string> }>
): VulnCheck[] {
  const checks: VulnCheck[] = [];

  const paramClassMap: Record<string, string[]> = {
    // SQL Injection
    id: ["sqli", "idor"], user_id: ["sqli", "idor"], item_id: ["sqli", "idor"],
    order_id: ["sqli", "idor"], product_id: ["sqli", "idor"],
    category: ["sqli"], sort: ["sqli"], order: ["sqli"],
    filter: ["sqli", "nosqli"], where: ["sqli"],
    // NoSQL Injection
    username: ["nosqli", "auth-bypass"], email: ["nosqli", "auth-bypass"],
    password: ["auth-bypass"], login: ["auth-bypass"],
    // Command Injection
    cmd: ["cmdi"], command: ["cmdi"], exec: ["cmdi"],
    ping: ["cmdi"], host: ["cmdi", "ssrf"], ip: ["cmdi", "ssrf"],
    filename: ["cmdi", "path-traversal"], dir: ["cmdi", "path-traversal"],
    // LDAP Injection
    cn: ["ldapi"], dn: ["ldapi"], uid: ["ldapi"],
    ou: ["ldapi"], dc: ["ldapi"],
    // SSRF / Open Redirect
    url: ["ssrf", "open-redirect"], redirect: ["open-redirect"],
    redirect_url: ["open-redirect"], redirect_uri: ["open-redirect"],
    return_url: ["open-redirect"], next: ["open-redirect"],
    callback: ["ssrf", "open-redirect"], dest: ["open-redirect"],
    target: ["ssrf"], uri: ["ssrf"], link: ["ssrf", "open-redirect"],
    webhook: ["ssrf"], proxy: ["ssrf"], fetch: ["ssrf"],
    // XSS (Reflected, Stored, DOM)
    q: ["rxss"], search: ["rxss"], query: ["rxss", "sqli"],
    keyword: ["rxss"], name: ["rxss", "stored-xss"],
    message: ["rxss", "stored-xss"], comment: ["rxss", "stored-xss"],
    title: ["stored-xss"], body: ["stored-xss"],
    content: ["stored-xss"], bio: ["stored-xss"],
    // Path Traversal / LFI
    file: ["path-traversal", "lfi"], path: ["path-traversal"],
    page: ["path-traversal", "lfi"], doc: ["path-traversal"],
    folder: ["path-traversal"], include: ["lfi"],
    // SSTI
    template: ["ssti", "lfi"], lang: ["ssti"], view: ["ssti"],
    layout: ["ssti"],
    // XXE
    xml: ["xxe"], data: ["xxe", "deserialization"],
    input: ["xxe", "rxss"], payload: ["deserialization"],
    // Insecure Deserialization
    token: ["deserialization", "auth-bypass"],
    session: ["deserialization", "auth-bypass"],
    object: ["deserialization"], state: ["deserialization"],
    viewstate: ["deserialization"],
    // IDOR / Broken Access Control
    account_id: ["idor"], profile_id: ["idor"],
    doc_id: ["idor"], file_id: ["idor"],
    invoice_id: ["idor"], report_id: ["idor"],
    // Privilege Escalation
    role: ["privilege-escalation"], admin: ["privilege-escalation"],
    is_admin: ["privilege-escalation"], access_level: ["privilege-escalation"],
    permissions: ["privilege-escalation"],
  };

  for (const ep of endpoints) {
    const params = ep.parameters || {};
    for (const [paramName, paramValue] of Object.entries(params)) {
      const key = paramName.toLowerCase();
      const vulnClasses = paramClassMap[key] || [];
      if (vulnClasses.length > 0) {
        checks.push({
          paramName,
          paramValue: String(paramValue),
          vulnClasses,
          url: ep.url,
          endpointId: ep.id,
        });
      }
    }
  }

  return checks;
}

// ─── 2. DIFFERENTIAL VALIDATOR WITH ADAPTIVE RETRY ──────

interface DiffResult {
  isVulnerable: boolean;
  vulnClass: string;
  confidence: "high" | "medium" | "low";
  baseline: { status: number; length: number };
  mutated: { status: number; length: number };
  truePayload: string;
  falsePayload: string;
  adaptationUsed?: string;
  owaspCategory: string;
}

// Map vuln classes to OWASP categories
const OWASP_MAP: Record<string, string> = {
  sqli: "A03:2021 Injection",
  nosqli: "A03:2021 Injection",
  cmdi: "A03:2021 Injection",
  ldapi: "A03:2021 Injection",
  rxss: "A03:2021 Injection",
  "stored-xss": "A03:2021 Injection",
  "dom-xss": "A03:2021 Injection",
  ssti: "A03:2021 Injection",
  xxe: "A05:2021 Security Misconfiguration",
  "auth-bypass": "A07:2021 Identification and Authentication Failures",
  "privilege-escalation": "A01:2021 Broken Access Control",
  idor: "A01:2021 Broken Access Control",
  "open-redirect": "A01:2021 Broken Access Control",
  ssrf: "A10:2021 Server-Side Request Forgery",
  "path-traversal": "A01:2021 Broken Access Control",
  lfi: "A01:2021 Broken Access Control",
  deserialization: "A08:2021 Software and Data Integrity Failures",
  "security-misconfig": "A05:2021 Security Misconfiguration",
  "sensitive-data": "A02:2021 Cryptographic Failures",
  "known-vuln": "A06:2021 Vulnerable and Outdated Components",
  "insufficient-logging": "A09:2021 Security Logging and Monitoring Failures",
};

// Define safe boolean test pairs per vuln class — FULL OWASP COVERAGE
function getTestPairs(paramValue: string): Record<string, { truthy: string; falsy: string }> {
  return {
    sqli: {
      truthy: `${paramValue}' AND '1'='1`,
      falsy: `${paramValue}' AND '1'='0`,
    },
    nosqli: {
      truthy: `${paramValue}[$ne]=impossible_value_12345`,
      falsy: paramValue,
    },
    cmdi: {
      truthy: `${paramValue}; echo cyberscope_marker`,
      falsy: paramValue,
    },
    ldapi: {
      truthy: `${paramValue})(|(cn=*`,
      falsy: paramValue,
    },
    rxss: {
      truthy: `${paramValue}<cyberscope>`,
      falsy: paramValue,
    },
    "stored-xss": {
      truthy: `${paramValue}<img src=x onerror=cyberscope>`,
      falsy: paramValue,
    },
    "open-redirect": {
      truthy: "https://safe-test.cyberscope.local",
      falsy: paramValue,
    },
    ssrf: {
      truthy: "http://127.0.0.1:1",
      falsy: paramValue,
    },
    idor: {
      truthy: "999999",
      falsy: paramValue,
    },
    "path-traversal": {
      truthy: "....//....//etc/hostname",
      falsy: paramValue,
    },
    lfi: {
      truthy: "....//....//etc/hostname",
      falsy: paramValue,
    },
    ssti: {
      truthy: "{{7*7}}",
      falsy: "{{invalid}}",
    },
    xxe: {
      truthy: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "cyberscope">]><foo>&xxe;</foo>',
      falsy: '<?xml version="1.0"?><foo>safe</foo>',
    },
    "auth-bypass": {
      truthy: `${paramValue}' OR '1'='1`,
      falsy: paramValue,
    },
    deserialization: {
      truthy: 'O:8:"stdClass":0:{}',
      falsy: paramValue,
    },
    "privilege-escalation": {
      truthy: "admin",
      falsy: paramValue,
    },
  };
}

// Adaptive mutation strategies for blocked payloads
const MUTATIONS: Array<{ name: string; transform: (s: string) => string }> = [
  {
    name: "URL Encoding",
    transform: (s) => s.replace(/[^a-zA-Z0-9_.~-]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`),
  },
  {
    name: "Double Hex Encoding",
    transform: (s) => s.replace(/[^a-zA-Z0-9]/g, (c) => `%25${c.charCodeAt(0).toString(16).toUpperCase()}`),
  },
  {
    name: "Unicode Escape",
    transform: (s) => s.replace(/['"<>&]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`),
  },
  {
    name: "Whitespace Variation",
    transform: (s) => s.replace(/ /g, "/**/"),
  },
  {
    name: "Case Toggle",
    transform: (s) => s.split("").map((c, i) => i % 2 === 0 ? c.toUpperCase() : c.toLowerCase()).join(""),
  },
];

const MAX_ADAPTIVE_RETRIES = 3;

async function runDifferentialTest(
  baseUrl: string,
  paramName: string,
  paramValue: string,
  vulnClass: string
): Promise<DiffResult | null> {
  const testPairs = getTestPairs(paramValue);
  const pair = testPairs[vulnClass];
  if (!pair) return null;
  if (!isSafePayload(pair.truthy) || !isSafePayload(pair.falsy)) return null;

  // Try original payload first, then adaptive mutations if blocked
  const payloadsToTry = [
    { payload: pair.truthy, name: "original" },
    ...MUTATIONS.slice(0, MAX_ADAPTIVE_RETRIES).map((m) => ({
      payload: m.transform(pair.truthy),
      name: m.name,
    })),
  ];

  for (const attempt of payloadsToTry) {
    if (!isSafePayload(attempt.payload)) continue;

    try {
      const url = new URL(baseUrl);

      // Truthy test
      url.searchParams.set(paramName, attempt.payload);
      const trueResp = await fetch(url.toString(), {
        method: "GET",
        headers: { "User-Agent": "CyberScope-Scanner/1.0" },
        redirect: "manual",
      });
      const trueBody = await trueResp.text();

      await new Promise((r) => setTimeout(r, 300));

      // Falsy test
      url.searchParams.set(paramName, pair.falsy);
      const falseResp = await fetch(url.toString(), {
        method: "GET",
        headers: { "User-Agent": "CyberScope-Scanner/1.0" },
        redirect: "manual",
      });
      const falseBody = await falseResp.text();

      // If blocked (403/406/429), try next mutation
      if ([403, 406, 429].includes(trueResp.status) && attempt.name !== payloadsToTry[payloadsToTry.length - 1].name) {
        await new Promise((r) => setTimeout(r, 500));
        continue;
      }

      const result: DiffResult = {
        isVulnerable: false,
        vulnClass,
        confidence: "low",
        baseline: { status: trueResp.status, length: trueBody.length },
        mutated: { status: falseResp.status, length: falseBody.length },
        truePayload: attempt.payload,
        falsePayload: pair.falsy,
        adaptationUsed: attempt.name !== "original" ? attempt.name : undefined,
        owaspCategory: OWASP_MAP[vulnClass] || "Unknown",
      };

      // ─── Differential Analysis per vuln class ───
      if (vulnClass === "sqli" || vulnClass === "auth-bypass") {
        const lengthDiff = Math.abs(trueBody.length - falseBody.length);
        const statusDiff = trueResp.status !== falseResp.status;
        if (lengthDiff > 50 || statusDiff) {
          result.isVulnerable = true;
          result.confidence = lengthDiff > 200 || statusDiff ? "high" : "medium";
        }
      } else if (vulnClass === "nosqli") {
        if (trueResp.status !== falseResp.status || Math.abs(trueBody.length - falseBody.length) > 30) {
          result.isVulnerable = true;
          result.confidence = "medium";
        }
      } else if (vulnClass === "cmdi") {
        if (trueBody.includes("cyberscope_marker")) {
          result.isVulnerable = true;
          result.confidence = "high";
        } else if (trueResp.status === 500 && falseResp.status !== 500) {
          result.isVulnerable = true;
          result.confidence = "medium";
        }
      } else if (vulnClass === "ldapi") {
        if (trueResp.status !== falseResp.status || Math.abs(trueBody.length - falseBody.length) > 50) {
          result.isVulnerable = true;
          result.confidence = "medium";
        }
      } else if (vulnClass === "rxss" || vulnClass === "stored-xss") {
        if (trueBody.includes("<cyberscope>") || trueBody.includes("onerror=cyberscope")) {
          result.isVulnerable = true;
          result.confidence = "high";
        }
      } else if (vulnClass === "open-redirect") {
        const location = trueResp.headers.get("location") || "";
        if (trueResp.status >= 300 && trueResp.status < 400 && location.includes("safe-test.cyberscope.local")) {
          result.isVulnerable = true;
          result.confidence = "high";
        }
      } else if (vulnClass === "ssrf") {
        if (trueResp.status !== falseResp.status) {
          result.isVulnerable = true;
          result.confidence = "medium";
        }
      } else if (vulnClass === "idor" || vulnClass === "privilege-escalation") {
        if (trueResp.status === 200 && falseResp.status === 200) {
          const lengthDiff = Math.abs(trueBody.length - falseBody.length);
          if (lengthDiff > 100) {
            result.isVulnerable = true;
            result.confidence = "medium";
          }
        }
      } else if (vulnClass === "ssti") {
        if (trueBody.includes("49")) {
          result.isVulnerable = true;
          result.confidence = "high";
        }
      } else if (vulnClass === "path-traversal" || vulnClass === "lfi") {
        if (trueBody.includes("root:") || trueBody.includes("/bin/") || trueBody.length !== falseBody.length) {
          result.isVulnerable = true;
          result.confidence = trueBody.includes("root:") ? "high" : "medium";
        }
      } else if (vulnClass === "xxe") {
        if (trueBody.includes("cyberscope") && !falseBody.includes("cyberscope")) {
          result.isVulnerable = true;
          result.confidence = "high";
        } else if (trueResp.status !== falseResp.status) {
          result.isVulnerable = true;
          result.confidence = "medium";
        }
      } else if (vulnClass === "deserialization") {
        if (trueResp.status === 500 || trueBody.includes("unserialize") || trueBody.includes("ClassNotFoundException")) {
          result.isVulnerable = true;
          result.confidence = trueResp.status === 500 ? "medium" : "high";
        }
      }

      return result;
    } catch (e) {
      console.error(`Differential test error for ${vulnClass} (${attempt.name}):`, e);
    }
  }
  return null;
}

// ─── 3. PASSIVE SECURITY CHECKS ─────────────────────────
// Checks that don't send payloads — header analysis, TLS, misconfigs

interface PassiveResult {
  check: string;
  vulnClass: string;
  owaspCategory: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  remediation: string;
}

async function runPassiveChecks(domain: string): Promise<PassiveResult[]> {
  const results: PassiveResult[] = [];

  try {
    const resp = await fetch(`https://${domain}`, {
      method: "GET",
      headers: { "User-Agent": "CyberScope-Scanner/1.0" },
      redirect: "follow",
    });

    const headers = Object.fromEntries(resp.headers.entries());
    const body = await resp.text();

    // Security Headers Check
    const securityHeaders: Array<{ header: string; title: string; desc: string; severity: "medium" | "low" | "info" }> = [
      { header: "strict-transport-security", title: "Missing HSTS Header", desc: "Strict-Transport-Security header is not set, enabling potential MITM downgrade attacks.", severity: "medium" },
      { header: "x-content-type-options", title: "Missing X-Content-Type-Options", desc: "X-Content-Type-Options: nosniff is not set, enabling MIME-type confusion attacks.", severity: "low" },
      { header: "x-frame-options", title: "Missing X-Frame-Options", desc: "X-Frame-Options is not set, making the application vulnerable to clickjacking.", severity: "medium" },
      { header: "content-security-policy", title: "Missing Content-Security-Policy", desc: "No CSP header found. This enables XSS and data injection attacks.", severity: "medium" },
      { header: "x-xss-protection", title: "Missing X-XSS-Protection", desc: "X-XSS-Protection header is not configured.", severity: "low" },
      { header: "referrer-policy", title: "Missing Referrer-Policy", desc: "No Referrer-Policy set, potentially leaking sensitive URL paths to third parties.", severity: "low" },
      { header: "permissions-policy", title: "Missing Permissions-Policy", desc: "No Permissions-Policy header to restrict browser feature access.", severity: "info" },
    ];

    for (const h of securityHeaders) {
      if (!headers[h.header]) {
        results.push({
          check: "security-headers",
          vulnClass: "security-misconfig",
          owaspCategory: "A05:2021 Security Misconfiguration",
          severity: h.severity,
          title: h.title,
          description: h.desc,
          remediation: `Add the ${h.header} response header with appropriate values.`,
        });
      }
    }

    // Sensitive Data Exposure Checks
    if (headers["server"]) {
      results.push({
        check: "server-disclosure",
        vulnClass: "sensitive-data",
        owaspCategory: "A05:2021 Security Misconfiguration",
        severity: "low",
        title: `Server Version Disclosed: ${headers["server"]}`,
        description: `The Server header reveals technology information: "${headers["server"]}". This aids attacker reconnaissance.`,
        remediation: "Remove or anonymize the Server response header.",
      });
    }

    if (headers["x-powered-by"]) {
      results.push({
        check: "tech-disclosure",
        vulnClass: "sensitive-data",
        owaspCategory: "A05:2021 Security Misconfiguration",
        severity: "low",
        title: `Technology Disclosed: ${headers["x-powered-by"]}`,
        description: `X-Powered-By header exposes backend technology: "${headers["x-powered-by"]}".`,
        remediation: "Remove the X-Powered-By response header.",
      });
    }

    // Cookie Security
    const setCookie = headers["set-cookie"] || "";
    if (setCookie) {
      if (!setCookie.toLowerCase().includes("httponly")) {
        results.push({
          check: "cookie-httponly",
          vulnClass: "security-misconfig",
          owaspCategory: "A05:2021 Security Misconfiguration",
          severity: "medium",
          title: "Cookie Missing HttpOnly Flag",
          description: "Session cookies are set without HttpOnly, making them accessible to JavaScript and vulnerable to XSS theft.",
          remediation: "Set the HttpOnly flag on all session cookies.",
        });
      }
      if (!setCookie.toLowerCase().includes("secure")) {
        results.push({
          check: "cookie-secure",
          vulnClass: "sensitive-data",
          owaspCategory: "A02:2021 Cryptographic Failures",
          severity: "medium",
          title: "Cookie Missing Secure Flag",
          description: "Cookies are transmitted without the Secure flag, enabling interception over unencrypted connections.",
          remediation: "Set the Secure flag on all cookies to prevent transmission over HTTP.",
        });
      }
      if (!setCookie.toLowerCase().includes("samesite")) {
        results.push({
          check: "cookie-samesite",
          vulnClass: "security-misconfig",
          owaspCategory: "A01:2021 Broken Access Control",
          severity: "low",
          title: "Cookie Missing SameSite Attribute",
          description: "Cookies lack SameSite attribute, potentially enabling CSRF attacks.",
          remediation: "Set SameSite=Lax or SameSite=Strict on session cookies.",
        });
      }
    }

    // CORS Misconfiguration
    if (headers["access-control-allow-origin"] === "*") {
      results.push({
        check: "cors-wildcard",
        vulnClass: "security-misconfig",
        owaspCategory: "A05:2021 Security Misconfiguration",
        severity: "medium",
        title: "Wildcard CORS Policy Detected",
        description: "Access-Control-Allow-Origin is set to '*', allowing any origin to make cross-origin requests.",
        remediation: "Restrict CORS to specific trusted origins instead of using a wildcard.",
      });
    }

    // Verbose Error Detection
    const errorPatterns = [
      /stack\s*trace/i, /exception\s+in/i, /traceback/i,
      /syntax\s+error/i, /fatal\s+error/i, /debug\s+mode/i,
      /mysql_/i, /pg_query/i, /ORA-\d+/i,
    ];
    for (const pattern of errorPatterns) {
      if (pattern.test(body)) {
        results.push({
          check: "verbose-errors",
          vulnClass: "security-misconfig",
          owaspCategory: "A05:2021 Security Misconfiguration",
          severity: "medium",
          title: "Verbose Error Messages / Debug Info Exposed",
          description: "The application response contains stack traces or debug information that could aid attackers.",
          remediation: "Disable debug mode and implement custom error pages in production.",
        });
        break;
      }
    }

    // Insufficient Logging Check (check for common logging endpoints)
    const loggingPaths = ["/.well-known/security.txt", "/security.txt"];
    for (const lp of loggingPaths) {
      try {
        const lResp = await fetch(`https://${domain}${lp}`, {
          method: "GET",
          headers: { "User-Agent": "CyberScope-Scanner/1.0" },
        });
        if (lResp.status !== 200) {
          results.push({
            check: "security-txt",
            vulnClass: "insufficient-logging",
            owaspCategory: "A09:2021 Security Logging and Monitoring Failures",
            severity: "info",
            title: "Missing security.txt",
            description: `No security.txt found at ${lp}. This file helps security researchers report vulnerabilities responsibly.`,
            remediation: "Create a security.txt file per RFC 9116 at /.well-known/security.txt.",
          });
          break;
        }
      } catch { /* skip */ }
    }

  } catch (e) {
    console.error("Passive checks error:", e);
  }

  return results;
}

// ─── 4. CVE VERSION CORRELATION ──────────────────────────

interface CveResult {
  cveId: string;
  description: string;
  severity: string;
  cvssScore: number;
}

async function queryCveDatabase(
  techStack: Record<string, string | undefined>
): Promise<CveResult[]> {
  const results: CveResult[] = [];
  const searchTerms: string[] = [];
  if (techStack.server) searchTerms.push(techStack.server);
  if (techStack.poweredBy) searchTerms.push(techStack.poweredBy);
  if (techStack.framework) searchTerms.push(techStack.framework);

  for (const term of searchTerms) {
    try {
      const resp = await fetch(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(term)}&resultsPerPage=10`,
        { headers: { "User-Agent": "CyberScope-Scanner/1.0" } }
      );
      if (resp.ok) {
        const data = await resp.json();
        for (const vuln of data.vulnerabilities || []) {
          const cve = vuln.cve;
          const metrics = cve.metrics?.cvssMetricV31?.[0]?.cvssData || cve.metrics?.cvssMetricV30?.[0]?.cvssData;
          results.push({
            cveId: cve.id,
            description: cve.descriptions?.find((d: { lang: string }) => d.lang === "en")?.value || "No description",
            severity: metrics?.baseSeverity || "UNKNOWN",
            cvssScore: metrics?.baseScore || 0,
          });
        }
      }
      await new Promise((r) => setTimeout(r, 6500));
    } catch (e) {
      console.error(`NVD query error for "${term}":`, e);
    }
  }

  return results;
}

// ─── 5. AI-POWERED DEEP VULNERABILITY ANALYSIS ──────────

async function aiAnalyzeFindings(
  domain: string,
  diffResults: DiffResult[],
  cveResults: CveResult[],
  passiveResults: PassiveResult[],
  techStack: Record<string, string | undefined>
): Promise<{
  assessments: Array<{
    title: string;
    severity: string;
    description: string;
    remediation: string;
    owaspCategory: string;
    cvssScore: number;
  }>;
}> {
  const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
  if (!LOVABLE_API_KEY) return { assessments: [] };

  const vulnFindings = diffResults.filter((r) => r.isVulnerable);
  if (vulnFindings.length === 0 && cveResults.length === 0 && passiveResults.length === 0) return { assessments: [] };

  const prompt = `You are a senior penetration tester conducting an OWASP Top 10 assessment for ${domain}.

Tech Stack: ${JSON.stringify(techStack)}

Active Test Results (${vulnFindings.length} potential vulnerabilities):
${vulnFindings.map((r) => `- ${r.vulnClass} [${r.owaspCategory}]: baseline(status=${r.baseline.status}, len=${r.baseline.length}) vs mutated(status=${r.mutated.status}, len=${r.mutated.length}), confidence=${r.confidence}${r.adaptationUsed ? `, adaptation=${r.adaptationUsed}` : ""}`).join("\n")}

CVE Matches (${cveResults.length}):
${cveResults.slice(0, 10).map((c) => `- ${c.cveId}: ${c.severity} (${c.cvssScore}) - ${c.description.slice(0, 100)}`).join("\n")}

Passive Security Checks (${passiveResults.length}):
${passiveResults.map((p) => `- ${p.title} [${p.owaspCategory}]: ${p.severity}`).join("\n")}

For each real finding, provide a professional assessment with:
- title: Clear vulnerability title
- severity: critical/high/medium/low
- description: Technical explanation
- remediation: Specific fix instructions
- owaspCategory: The relevant OWASP Top 10 2021 category
- cvssScore: Estimated CVSS 3.1 base score (0.0-10.0)`;

  try {
    const resp = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${LOVABLE_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-3-flash-preview",
        messages: [
          { role: "system", content: "You are a VAPT analyst specializing in OWASP Top 10 assessments. Return structured assessments via the tool." },
          { role: "user", content: prompt },
        ],
        tools: [{
          type: "function",
          function: {
            name: "report_assessments",
            description: "Report vulnerability assessments",
            parameters: {
              type: "object",
              properties: {
                assessments: {
                  type: "array",
                  items: {
                    type: "object",
                    properties: {
                      title: { type: "string" },
                      severity: { type: "string", enum: ["critical", "high", "medium", "low"] },
                      description: { type: "string" },
                      remediation: { type: "string" },
                      owaspCategory: { type: "string" },
                      cvssScore: { type: "number" },
                    },
                    required: ["title", "severity", "description", "remediation", "owaspCategory", "cvssScore"],
                    additionalProperties: false,
                  },
                },
              },
              required: ["assessments"],
              additionalProperties: false,
            },
          },
        }],
        tool_choice: { type: "function", function: { name: "report_assessments" } },
      }),
    });

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

  return { assessments: [] };
}

// ─── 6. MAIN PIPELINE ───────────────────────────────────

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

    const { data: target } = await db.from("target_workspaces").select("*").eq("id", targetId).single();
    if (!target) {
      return new Response(JSON.stringify({ error: "Target not found" }), {
        status: 404,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const { data: task } = await db
      .from("agent_tasks")
      .insert({ target_id: targetId, task_type: "vulnerability-scan", status: "running" })
      .select()
      .single();

    const taskId = task!.id;

    await db.from("target_workspaces").update({ status: "scanning" }).eq("id", targetId);
    await log(db, targetId, taskId, "info", "🔬 Comprehensive OWASP Top 10 vulnerability scan started");

    // ── Fetch endpoints ──
    const { data: endpoints } = await db.from("discovered_endpoints").select("*").eq("target_id", targetId);

    if (!endpoints || endpoints.length === 0) {
      await log(db, targetId, taskId, "error", "No endpoints found — run recon first");
      await db.from("agent_tasks").update({ status: "failed", result: { error: "No endpoints" } }).eq("id", taskId);
      return new Response(JSON.stringify({ error: "No endpoints discovered. Run recon first." }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    await log(db, targetId, taskId, "action", `Loaded ${endpoints.length} endpoints for OWASP analysis`);

    // ── Step 1: Passive Security Checks ──
    await log(db, targetId, taskId, "thought", "Running passive security header & misconfiguration checks");
    const passiveResults = target.domain ? await runPassiveChecks(target.domain) : [];
    await log(db, targetId, taskId, "result", `Passive checks found ${passiveResults.length} issues`);

    // ── Step 2: Heuristic Parameter Classification ──
    await log(db, targetId, taskId, "thought", "Classifying parameters for OWASP Top 10 vuln testing (SQLi, NoSQLi, CmdI, XSS, SSRF, XXE, IDOR, etc.)");
    const vulnChecks = classifyParameters(
      endpoints.map((ep) => ({
        id: ep.id,
        url: ep.url,
        parameters: (ep.parameters as Record<string, string>) || {},
      }))
    );
    const uniqueVulnClasses = new Set(vulnChecks.flatMap((c) => c.vulnClasses));
    await log(db, targetId, taskId, "result",
      `Classified ${vulnChecks.length} parameter-vuln pairs across ${uniqueVulnClasses.size} vulnerability classes: ${[...uniqueVulnClasses].join(", ")}`
    );

    // ── Step 3: Differential Analysis with Adaptive Retry ──
    await log(db, targetId, taskId, "thought", "Running differential tests with adaptive mutation retry (max 3 retries per blocked test)");
    const diffResults: DiffResult[] = [];
    const maxTests = Math.min(vulnChecks.length, 30);

    for (let i = 0; i < maxTests; i++) {
      const check = vulnChecks[i];
      for (const vulnClass of check.vulnClasses) {
        await log(db, targetId, taskId, "action", `Testing ${check.paramName} for ${vulnClass} at ${check.url}`);
        const result = await runDifferentialTest(check.url, check.paramName, check.paramValue, vulnClass);
        if (result) {
          diffResults.push(result);
          if (result.isVulnerable) {
            const adaptNote = result.adaptationUsed ? ` (via ${result.adaptationUsed} adaptation)` : "";
            await log(db, targetId, taskId, "result",
              `⚠️ POTENTIAL ${vulnClass.toUpperCase()} [${result.owaspCategory}]: ${check.paramName} at ${check.url} (confidence: ${result.confidence})${adaptNote}`
            );
          }
        }
        await new Promise((r) => setTimeout(r, 500));
      }
    }

    const vulnFindings = diffResults.filter((r) => r.isVulnerable);
    await log(db, targetId, taskId, "result", `Active testing found ${vulnFindings.length} potential vulnerabilities out of ${diffResults.length} tests`);

    // ── Step 4: CVE Correlation ──
    await log(db, targetId, taskId, "thought", "Querying NVD for CVE correlation (known vulnerable components)");
    const { data: reconTask } = await db
      .from("agent_tasks")
      .select("result")
      .eq("target_id", targetId)
      .eq("task_type", "reconnaissance")
      .eq("status", "completed")
      .order("created_at", { ascending: false })
      .limit(1)
      .single();

    const techStack = (reconTask?.result as any)?.tech_fingerprint || {};
    const cveResults = await queryCveDatabase(techStack);
    await log(db, targetId, taskId, "result", `CVE correlation found ${cveResults.length} potentially relevant CVEs [A06:2021 Vulnerable Components]`);

    // ── Step 5: AI Deep Assessment ──
    await log(db, targetId, taskId, "thought", "Running AI deep vulnerability assessment across all OWASP categories");
    const aiAssessments = await aiAnalyzeFindings(target.domain || "unknown", diffResults, cveResults, passiveResults, techStack);
    await log(db, targetId, taskId, "result", `AI produced ${aiAssessments.assessments.length} verified assessments`);

    // ── Step 6: Push to HITL Approval Queue ──
    await log(db, targetId, taskId, "thought", "Routing all findings to HITL approval queue");
    let approvalCount = 0;

    // Passive findings
    for (const passive of passiveResults) {
      await db.from("pending_approvals").insert({
        target_id: targetId,
        finding_type: `passive-${passive.vulnClass}`,
        severity: passive.severity,
        title: passive.title,
        description: `${passive.description}\n\n**Remediation:** ${passive.remediation}`,
        evidence: { check: passive.check, owaspCategory: passive.owaspCategory },
      });
      approvalCount++;
    }

    // Active differential findings
    for (const diff of vulnFindings) {
      const matchingCheck = vulnChecks.find((c) => c.vulnClasses.includes(diff.vulnClass));
      const severityMap: Record<string, string> = { high: "high", medium: "medium", low: "low" };

      await db.from("pending_approvals").insert({
        target_id: targetId,
        endpoint_id: matchingCheck?.endpointId || null,
        finding_type: `active-${diff.vulnClass}`,
        severity: severityMap[diff.confidence] || "medium",
        title: `Potential ${diff.vulnClass.toUpperCase()} [${diff.owaspCategory}]`,
        description: `Parameter "${matchingCheck?.paramName}" showed differential response behavior indicating possible ${diff.vulnClass}.${diff.adaptationUsed ? `\n\nAdaptive mutation "${diff.adaptationUsed}" was used to navigate filters.` : ""}`,
        parameter: matchingCheck?.paramName,
        payload_used: diff.truePayload,
        baseline_response: diff.baseline,
        mutated_response: diff.mutated,
        evidence: {
          vulnClass: diff.vulnClass,
          confidence: diff.confidence,
          url: matchingCheck?.url,
          owaspCategory: diff.owaspCategory,
          adaptationUsed: diff.adaptationUsed || null,
        },
      });
      approvalCount++;
    }

    // CVE findings
    for (const cve of cveResults.slice(0, 10)) {
      const severityMap: Record<string, string> = { CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low" };
      await db.from("pending_approvals").insert({
        target_id: targetId,
        finding_type: "cve-correlation",
        severity: severityMap[cve.severity] || "medium",
        title: `${cve.cveId} — ${cve.description.slice(0, 80)}`,
        description: cve.description,
        cve_ids: [cve.cveId],
        cvss_score: cve.cvssScore,
        evidence: { techStack, cveId: cve.cveId, severity: cve.severity, owaspCategory: "A06:2021 Vulnerable and Outdated Components" },
      });
      approvalCount++;
    }

    // AI assessments
    for (const assessment of aiAssessments.assessments) {
      await db.from("pending_approvals").insert({
        target_id: targetId,
        finding_type: "ai-deep-assessment",
        severity: assessment.severity,
        title: `${assessment.title} [${assessment.owaspCategory}]`,
        description: `${assessment.description}\n\n**Remediation:** ${assessment.remediation}`,
        cvss_score: assessment.cvssScore,
        evidence: {
          source: "ai-deep-analysis",
          owaspCategory: assessment.owaspCategory,
          remediation: assessment.remediation,
          cvssScore: assessment.cvssScore,
        },
      });
      approvalCount++;
    }

    await log(db, targetId, taskId, "info",
      `✅ Comprehensive OWASP scan complete — ${approvalCount} findings pushed to HITL approval queue (${passiveResults.length} passive, ${vulnFindings.length} active, ${cveResults.length} CVE, ${aiAssessments.assessments.length} AI)`
    );

    // Update task
    const owaspCoverage = [...new Set([
      ...passiveResults.map((p) => p.owaspCategory),
      ...vulnFindings.map((v) => v.owaspCategory),
      ...aiAssessments.assessments.map((a) => a.owaspCategory),
    ])];

    await db.from("agent_tasks").update({
      status: "completed",
      result: {
        parameters_classified: vulnChecks.length,
        differential_tests: diffResults.length,
        vulns_found: vulnFindings.length,
        passive_issues: passiveResults.length,
        cves_matched: cveResults.length,
        ai_assessments: aiAssessments.assessments.length,
        approvals_queued: approvalCount,
        owasp_categories_covered: owaspCoverage,
        adaptive_mutations_used: vulnFindings.filter((v) => v.adaptationUsed).length,
      },
    }).eq("id", taskId);

    await db.from("target_workspaces").update({ status: "completed" }).eq("id", targetId);

    return new Response(
      JSON.stringify({
        success: true,
        parametersClassified: vulnChecks.length,
        differentialTests: diffResults.length,
        vulnsFound: vulnFindings.length,
        passiveIssues: passiveResults.length,
        cvesMatched: cveResults.length,
        aiAssessments: aiAssessments.assessments.length,
        approvalsQueued: approvalCount,
        owaspCoverage,
      }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (e) {
    console.error("Vuln scanner error:", e);
    return new Response(
      JSON.stringify({ error: e instanceof Error ? e.message : "Unknown error" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
