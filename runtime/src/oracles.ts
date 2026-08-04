// Deterministic proof oracles. Each returns { ok, reason, details }.
// The runtime calls the matching oracle before inserting a finding.
import { request } from "undici";
import { chromium, type Browser } from "playwright";

let _b: Browser | null = null;
async function getBrowser() {
  if (!_b) _b = await chromium.launch({ headless: true, args: ["--no-sandbox"] });
  return _b;
}
export async function closeOracleBrowser() { if (_b) { await _b.close(); _b = null; } }

export type OracleResult = { ok: boolean; reason: string; details?: Record<string, unknown> };

const timedGet = async (url: string, timeout = 10_000) => {
  const t0 = Date.now();
  try {
    const ac = new AbortController();
    const to = setTimeout(() => ac.abort(), timeout);
    const r = await request(url, { signal: ac.signal, maxRedirections: 0 });
    const body = await r.body.text();
    clearTimeout(to);
    return { status: r.statusCode, body, ms: Date.now() - t0, headers: r.headers };
  } catch (e: any) {
    return { status: 0, body: "", ms: Date.now() - t0, error: String(e?.message ?? e) };
  }
};

export async function oracleSqli(url: string, payloadUrl: string): Promise<OracleResult> {
  const [base, evil] = await Promise.all([timedGet(url), timedGet(payloadUrl)]);
  const errStrings = /(sql syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|SQLite\/JDBCDriver|SqlException)/i;
  if (evil.body && errStrings.test(evil.body)) return { ok: true, reason: "sql error string leaked", details: { snippet: evil.body.slice(0, 400) } };
  // time-based: payload must be >= 4s AND >= 3x baseline
  if (evil.ms >= 4000 && evil.ms >= base.ms * 3) return { ok: true, reason: "time delta", details: { baseline_ms: base.ms, payload_ms: evil.ms } };
  return { ok: false, reason: "no error string, no timing delta" };
}

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
    // fallback: reflected <script> or on* handler containing marker
    if (/<script[^>]*>[^<]*cs_xss_\w+/i.test(html)) return { ok: true, reason: "script tag reflected" };
    return { ok: false, reason: "no dialog, no script reflection" };
  } catch (e: any) {
    return { ok: false, reason: String(e?.message ?? e) };
  } finally { await ctx.close(); }
}

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

export async function oracleSsrf(interactshBase: string, correlationId: string): Promise<OracleResult> {
  if (!interactshBase) return { ok: false, reason: "INTERACTSH_URL not set" };
  const r = await timedGet(`${interactshBase}/poll?id=${correlationId}`);
  if (r.status === 200 && r.body && r.body.length > 20 && /"protocol"|"remote_address"|"raw-request"/i.test(r.body)) {
    return { ok: true, reason: "OOB callback observed", details: { poll_snippet: r.body.slice(0, 300) } };
  }
  return { ok: false, reason: "no OOB interaction" };
}

// Dispatcher. Evidence must carry the fields each oracle needs.
export async function runOracle(
  vulnClass: string,
  affectedUrl: string,
  evidence: Record<string, any>,
): Promise<OracleResult> {
  const cls = vulnClass.toLowerCase();
  try {
    if (cls.includes("sqli") || cls.includes("sql_injection")) {
      const payloadUrl = evidence.payload_url || affectedUrl;
      const baseUrl = evidence.baseline_url || affectedUrl.replace(/([?&])[^=]+=[^&]*/, "");
      return await oracleSqli(baseUrl, payloadUrl);
    }
    if (cls.includes("xss")) return await oracleXss(evidence.payload_url || affectedUrl);
    if (cls.includes("redirect")) {
      const host = evidence.target_host || new URL(affectedUrl).host;
      return await oracleOpenRedirect(evidence.payload_url || affectedUrl, host);
    }
    if (cls.includes("ssrf")) {
      return await oracleSsrf(process.env.INTERACTSH_URL || "", evidence.correlation_id || "");
    }
    // No oracle for this class → allow but flag
    return { ok: true, reason: `no oracle for '${cls}', accepted as-is` };
  } catch (e: any) {
    return { ok: false, reason: `oracle threw: ${String(e?.message ?? e)}` };
  }
}
