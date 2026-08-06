// Deterministic proof oracles for CyberScope (Mythos L1).
// Every oracle returns { ok, reason, details }. Runtime rejects findings whose oracle returns ok:false.
import { request } from "undici";
import { chromium, type Browser } from "playwright";

let _b: Browser | null = null;
async function getBrowser() {
  if (!_b) _b = await chromium.launch({ headless: true, args: ["--no-sandbox"] });
  return _b;
}
export async function closeOracleBrowser() { if (_b) { await _b.close(); _b = null; } }

export type OracleResult = { ok: boolean; reason: string; details?: Record<string, unknown> };

const timedGet = async (url: string, timeout = 12_000, headers: Record<string,string> = {}) => {
  const t0 = Date.now();
  try {
    const ac = new AbortController();
    const to = setTimeout(() => ac.abort(), timeout);
    const r = await request(url, { signal: ac.signal, maxRedirections: 0, headers });
    const body = await r.body.text();
    clearTimeout(to);
    return { status: r.statusCode, body, ms: Date.now() - t0, headers: r.headers };
  } catch (e: any) {
    return { status: 0, body: "", ms: Date.now() - t0, error: String(e?.message ?? e), headers: {} as any };
  }
};

// ---------- L1.1 SQLi ----------
export async function oracleSqli(baseUrl: string, payloadUrl: string): Promise<OracleResult> {
  const [base, evil] = await Promise.all([timedGet(baseUrl), timedGet(payloadUrl)]);
  const errStrings = /(sql syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|SQLite\/JDBCDriver|SqlException|Warning:\s+pg_|Warning:\s+mysqli_)/i;
  if (evil.body && errStrings.test(evil.body) && !(base.body && errStrings.test(base.body))) {
    return { ok: true, reason: "sql error string only on payload", details: { snippet: evil.body.slice(0, 400) } };
  }
  if (evil.ms >= 4500 && evil.ms >= base.ms * 3 && base.ms < 3000) {
    return { ok: true, reason: "time delta", details: { baseline_ms: base.ms, payload_ms: evil.ms } };
  }
  return { ok: false, reason: "no error string, no timing delta" };
}

// ---------- L1.2 XSS ----------
export async function oracleXss(url: string): Promise<OracleResult> {
  const b = await getBrowser();
  const ctx = await b.newContext();
  const page = await ctx.newPage();
  let fired = false;
  page.on("dialog", async (d) => { fired = true; await d.dismiss().catch(() => {}); });
  try {
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: 15000 });
    await page.waitForTimeout(1500);
    if (fired) return { ok: true, reason: "dialog fired" };
    const html = await page.content();
    if (/<script[^>]*>[^<]*cs_xss_\w+/i.test(html)) return { ok: true, reason: "script tag reflected raw" };
    return { ok: false, reason: "no dialog, no raw script reflection" };
  } catch (e: any) {
    return { ok: false, reason: String(e?.message ?? e) };
  } finally { await ctx.close(); }
}

// ---------- L1.3 Open Redirect ----------
export async function oracleOpenRedirect(url: string, targetHost: string): Promise<OracleResult> {
  const r = await timedGet(url);
  const loc = (r.headers?.location as string) || "";
  if (!loc) return { ok: false, reason: "no Location header" };
  try {
    const u = new URL(loc, url);
    if (u.host && u.host !== targetHost) return { ok: true, reason: "redirect to external host", details: { location: loc } };
    return { ok: false, reason: `same-host redirect (${u.host})` };
  } catch { return { ok: false, reason: "unparseable Location" }; }
}

// ---------- L1.4 SSRF (OOB) ----------
export async function oracleSsrf(interactshBase: string, correlationId: string): Promise<OracleResult> {
  if (!interactshBase) return { ok: false, reason: "INTERACTSH_URL not set" };
  const r = await timedGet(`${interactshBase}/poll?id=${correlationId}`);
  if (r.status === 200 && r.body && r.body.length > 20 && /"protocol"|"remote_address"|"raw-request"/i.test(r.body)) {
    return { ok: true, reason: "OOB callback observed", details: { poll_snippet: r.body.slice(0, 300) } };
  }
  return { ok: false, reason: "no OOB interaction" };
}

// ---------- L1.5 RCE (marker or time-based) ----------
export async function oracleRce(baseUrl: string, payloadUrl: string, marker?: string): Promise<OracleResult> {
  const [base, evil] = await Promise.all([timedGet(baseUrl), timedGet(payloadUrl)]);
  if (marker && evil.body?.includes(marker) && !base.body?.includes(marker)) {
    return { ok: true, reason: "command marker reflected", details: { marker, snippet: evil.body.slice(0, 400) } };
  }
  // time-based sleep, e.g. `;sleep 6`
  if (evil.ms >= 5500 && evil.ms >= base.ms * 3 && base.ms < 3000) {
    return { ok: true, reason: "command sleep observed", details: { baseline_ms: base.ms, payload_ms: evil.ms } };
  }
  return { ok: false, reason: "no marker, no sleep delta" };
}

// ---------- L1.6 SSTI (differential rendering) ----------
export async function oracleSsti(baseUrl: string, payloadUrl: string, expected: string): Promise<OracleResult> {
  const r = await timedGet(payloadUrl);
  if (r.body && r.body.includes(expected)) {
    // Also ensure baseline did NOT contain the exact rendered value (guards constant reflection).
    const base = await timedGet(baseUrl);
    if (!base.body || !base.body.includes(expected)) {
      return { ok: true, reason: "template expression evaluated", details: { expected, snippet: r.body.slice(0, 400) } };
    }
  }
  return { ok: false, reason: "expected computed value not present" };
}

// ---------- L1.7 LFI / Path Traversal ----------
const LFI_SIGS = [
  /root:.*:0:0:/,             // /etc/passwd
  /\[boot loader\]/i,          // boot.ini
  /^\s*<\?xml\s+version="[^"]+"\?>[\s\S]{0,4000}<\/httpd>/i,
  /daemon:x:/,
  /\[extensions\]/i,
];
export async function oracleLfi(baseUrl: string, payloadUrl: string): Promise<OracleResult> {
  const [base, evil] = await Promise.all([timedGet(baseUrl), timedGet(payloadUrl)]);
  for (const sig of LFI_SIGS) {
    if (evil.body && sig.test(evil.body) && !(base.body && sig.test(base.body))) {
      return { ok: true, reason: `filesystem signature ${sig.source.slice(0, 40)}`, details: { snippet: evil.body.slice(0, 400) } };
    }
  }
  return { ok: false, reason: "no filesystem signature" };
}

// ---------- L1.8 XXE (OOB or entity resolution) ----------
export async function oracleXxe(interactshBase: string, correlationId: string, responseBody?: string): Promise<OracleResult> {
  if (responseBody && /file:\/\/|root:.*:0:0:|SYSTEM\s+"file/i.test(responseBody)) {
    return { ok: true, reason: "entity resolved in response body", details: { snippet: responseBody.slice(0, 400) } };
  }
  if (interactshBase && correlationId) {
    const r = await timedGet(`${interactshBase}/poll?id=${correlationId}`);
    if (r.status === 200 && r.body && /"protocol"/i.test(r.body)) {
      return { ok: true, reason: "XXE OOB callback observed", details: { poll_snippet: r.body.slice(0, 300) } };
    }
  }
  return { ok: false, reason: "no XXE proof" };
}

// ---------- L1.9 IDOR / Broken Access Control (cross-context differential) ----------
export async function oracleIdor(
  urlA: string, cookiesA: string,
  urlB: string, cookiesB: string,
  expectFieldA?: string,
): Promise<OracleResult> {
  const [a, b] = await Promise.all([
    timedGet(urlA, 10000, cookiesA ? { cookie: cookiesA } : {}),
    timedGet(urlB, 10000, cookiesB ? { cookie: cookiesB } : {}),
  ]);
  if (a.status && b.status && a.status === 200 && b.status === 200) {
    // Both contexts got the same private resource — expected user-scoped resources should differ or 403.
    if (expectFieldA && a.body?.includes(expectFieldA) && b.body?.includes(expectFieldA)) {
      return { ok: true, reason: "userB read userA-scoped field", details: { field: expectFieldA } };
    }
    if (!expectFieldA && a.body && b.body && a.body === b.body && a.body.length > 200) {
      return { ok: true, reason: "identical private response across auth contexts", details: { size: a.body.length } };
    }
  }
  return { ok: false, reason: `no cross-context leak (statusA=${a.status}, statusB=${b.status})` };
}

// ---------- L1.10 Auth Bypass ----------
export async function oracleAuthBypass(protectedUrl: string, headersUnauth: Record<string,string> = {}): Promise<OracleResult> {
  const r = await timedGet(protectedUrl, 10000, headersUnauth);
  if (r.status === 200 && r.body && r.body.length > 500 && !/login|sign\s*in|unauthori[sz]ed|forbidden/i.test(r.body.slice(0, 2000))) {
    return { ok: true, reason: "protected resource returned 200 without auth", details: { size: r.body.length, status: r.status } };
  }
  return { ok: false, reason: `not bypassable (status=${r.status})` };
}

// ---------- Dispatcher ----------
export async function runOracle(
  vulnClass: string,
  affectedUrl: string,
  evidence: Record<string, any>,
): Promise<OracleResult> {
  const cls = vulnClass.toLowerCase();
  const oob = process.env.INTERACTSH_URL || "";
  try {
    if (cls.includes("sqli") || cls.includes("sql_injection") || cls.includes("sql injection")) {
      const payloadUrl = evidence.payload_url || affectedUrl;
      const baseUrl = evidence.baseline_url || affectedUrl.replace(/([?&])[^=]+=[^&]*/, "");
      return await oracleSqli(baseUrl, payloadUrl);
    }
    if (cls.includes("xss")) return await oracleXss(evidence.payload_url || affectedUrl);
    if (cls.includes("redirect")) {
      const host = evidence.target_host || new URL(affectedUrl).host;
      return await oracleOpenRedirect(evidence.payload_url || affectedUrl, host);
    }
    if (cls.includes("ssrf")) return await oracleSsrf(oob, evidence.correlation_id || "");
    if (cls.includes("rce") || cls.includes("command_injection") || cls.includes("cmdi")) {
      return await oracleRce(evidence.baseline_url || affectedUrl, evidence.payload_url || affectedUrl, evidence.marker);
    }
    if (cls.includes("ssti") || cls.includes("template_injection")) {
      return await oracleSsti(evidence.baseline_url || affectedUrl, evidence.payload_url || affectedUrl, String(evidence.expected ?? "49"));
    }
    if (cls.includes("lfi") || cls.includes("path_traversal") || cls.includes("path traversal") || cls.includes("file_inclusion")) {
      return await oracleLfi(evidence.baseline_url || affectedUrl, evidence.payload_url || affectedUrl);
    }
    if (cls.includes("xxe") || cls.includes("xml_external")) {
      return await oracleXxe(oob, evidence.correlation_id || "", evidence.response_body);
    }
    if (cls.includes("idor") || cls.includes("bola") || cls.includes("bac") || cls.includes("broken_access")) {
      return await oracleIdor(
        evidence.url_a || affectedUrl, evidence.cookies_a || "",
        evidence.url_b || affectedUrl, evidence.cookies_b || "",
        evidence.expect_field,
      );
    }
    if (cls.includes("auth_bypass") || cls.includes("authentication_bypass") || cls.includes("missing_auth")) {
      return await oracleAuthBypass(evidence.payload_url || affectedUrl, evidence.headers || {});
    }
    // Nuclei / third-party — accept as-is but flag.
    return { ok: true, reason: `no oracle for '${cls}', accepted (mark 'suspected')` };
  } catch (e: any) {
    return { ok: false, reason: `oracle threw: ${String(e?.message ?? e)}` };
  }
}
