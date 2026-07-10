// recon-juicy — passive/low-touch reconnaissance grading for a target.
// Covers: DNS/email hygiene, TLS posture, HTTP security headers, CORS,
// risky HTTP methods, public files & secret leaks, dangerous subdomains.
// All checks are READ-ONLY (no writes, no auth attempts).
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { probeFetchWithSchemeFallback, probeFetch, readBodySafe } from "../_shared/safe-fetch.ts";
import { checkLoopGuard, recordLoopRun } from "../_shared/loop-guard.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

type Finding = {
  title: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  cvss_score: number;
  finding_type: string;
  vuln_class: string;
  description: string;
  remediation: string;
  affected_url?: string;
  poc?: string;
  evidence?: Record<string, unknown>;
};

const SECRET_PATTERNS: Array<[string, RegExp]> = [
  ["aws_access_key", /AKIA[0-9A-Z]{16}/],
  ["aws_secret_key", /(?<![A-Za-z0-9])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9])/],
  ["google_api_key", /AIza[0-9A-Za-z_\-]{35}/],
  ["github_token", /gh[pousr]_[A-Za-z0-9]{36,}/],
  ["gitlab_token", /glpat-[A-Za-z0-9_\-]{20,}/],
  ["slack_token", /xox[baprs]-[A-Za-z0-9-]{10,}/],
  ["slack_webhook", /https:\/\/hooks\.slack\.com\/services\/[A-Z0-9\/]+/],
  ["stripe_live", /sk_live_[A-Za-z0-9]{20,}/],
  ["sendgrid", /SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{30,}/],
  ["twilio_sid", /AC[0-9a-f]{32}/],
  ["jwt", /eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+/],
  ["private_key", /-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----/],
];

async function dohResolve(name: string, type: string): Promise<string[]> {
  try {
    const r = await probeFetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
      { headers: { accept: "application/dns-json" } }, 5000,
    );
    if (!r.ok) return [];
    const j: any = await r.response.json().catch(() => null);
    return (j?.Answer || []).map((a: any) => String(a.data || "")).filter(Boolean);
  } catch { return []; }
}

async function auditDns(host: string, out: Finding[]) {
  const [mx, txt, dmarc, spf, caa] = await Promise.all([
    dohResolve(host, "MX"),
    dohResolve(host, "TXT"),
    dohResolve(`_dmarc.${host}`, "TXT"),
    dohResolve(host, "TXT"),
    dohResolve(host, "CAA"),
  ]);
  const spfText = spf.find((t) => /v=spf1/i.test(t)) || "";
  if (!spfText) {
    out.push({
      title: "SPF record missing", severity: "low", cvss_score: 3.7,
      finding_type: "missing_spf", vuln_class: "email_spoofing",
      description: `Domain ${host} has no SPF record. Spoofed mail from this domain may pass downstream filters.`,
      remediation: "Publish an SPF record (v=spf1 ... -all). Use -all (hardfail), avoid +all.",
      poc: `dig +short TXT ${host}`,
      evidence: { txt },
    });
  } else if (/\+all/i.test(spfText)) {
    out.push({
      title: "SPF '+all' allows anyone to spoof mail", severity: "high", cvss_score: 7.5,
      finding_type: "weak_spf", vuln_class: "email_spoofing",
      description: `SPF record contains +all: any sender is authorised to mail as ${host}.`,
      remediation: "Replace +all with -all (hardfail) or ~all (softfail).",
      poc: `dig +short TXT ${host}`,
      evidence: { spf: spfText },
    });
  }
  const dmarcText = dmarc.find((t) => /v=DMARC1/i.test(t)) || "";
  if (!dmarcText) {
    out.push({
      title: "DMARC record missing", severity: "medium", cvss_score: 5.3,
      finding_type: "missing_dmarc", vuln_class: "email_spoofing",
      description: `_dmarc.${host} has no record. Receivers have no policy guidance for spoofed mail.`,
      remediation: "Publish v=DMARC1; p=reject; rua=mailto:dmarc@... once monitoring confirms legit senders.",
      poc: `dig +short TXT _dmarc.${host}`,
    });
  } else if (/p=none/i.test(dmarcText)) {
    out.push({
      title: "DMARC policy is p=none (monitor only)", severity: "low", cvss_score: 3.1,
      finding_type: "weak_dmarc", vuln_class: "email_spoofing",
      description: `DMARC for ${host} uses p=none — spoofed mail is not rejected.`,
      remediation: "Move policy to p=quarantine then p=reject once aligned.",
      evidence: { dmarc: dmarcText },
    });
  }
  if (!caa.length) {
    out.push({
      title: "CAA record missing", severity: "info", cvss_score: 2.0,
      finding_type: "missing_caa", vuln_class: "tls_governance",
      description: `${host} has no CAA record. Any CA may issue certificates for this domain.`,
      remediation: `Publish CAA records, e.g. ${host}. CAA 0 issue "letsencrypt.org"`,
      poc: `dig +short CAA ${host}`,
    });
  }
  if (mx.length === 0 && txt.length === 0) {
    out.push({
      title: "Empty DNS answers (NXDOMAIN-like)", severity: "info", cvss_score: 1.0,
      finding_type: "dns_empty", vuln_class: "dns_hygiene",
      description: `${host} returned no MX/TXT — possible parked or dangling host.`,
      remediation: "Confirm the host is intentionally hosted; remove dangling delegations.",
    });
  }
}

async function auditTlsAndHeaders(baseUrl: string, host: string, out: Finding[]) {
  const r = await probeFetchWithSchemeFallback(baseUrl, { redirect: "manual" }, 8000);
  if (!r.response) {
    out.push({
      title: "Host unreachable on both HTTPS and HTTP", severity: "info", cvss_score: 0,
      finding_type: "host_unreachable", vuln_class: "availability",
      description: `Could not reach ${baseUrl}. Errors: ${r.errors.join(" | ")}`,
      remediation: "Verify the host is in scope and exposed to the public internet.",
      affected_url: baseUrl,
    });
    return;
  }
  if (r.schemeDowngraded) {
    out.push({
      title: "HTTPS unavailable — service only reachable over HTTP", severity: "medium", cvss_score: 5.3,
      finding_type: "missing_https", vuln_class: "transport_security",
      description: `${baseUrl} failed HTTPS handshake but answered over HTTP. Traffic exposed to MITM.`,
      remediation: "Provision a TLS certificate (e.g. Let's Encrypt), redirect HTTP→HTTPS, enable HSTS preload.",
      affected_url: baseUrl, evidence: { final_url: r.finalUrl },
    });
  }
  const hdrs = r.response.headers;
  const get = (k: string) => hdrs.get(k) || "";
  const url = r.finalUrl;
  const isHttps = url.startsWith("https://");

  if (isHttps && !get("strict-transport-security")) {
    out.push({
      title: "HSTS header missing", severity: "low", cvss_score: 3.7,
      finding_type: "missing_hsts", vuln_class: "transport_security",
      description: `${url} does not set Strict-Transport-Security. Browsers will allow HTTP downgrade attacks.`,
      remediation: "Add: Strict-Transport-Security: max-age=63072000; includeSubDomains; preload",
      affected_url: url,
    });
  }
  if (!get("content-security-policy")) {
    out.push({
      title: "Content-Security-Policy header missing", severity: "low", cvss_score: 3.1,
      finding_type: "missing_csp", vuln_class: "xss_defence",
      description: `${url} ships no CSP — any XSS sink is exploitable with full script capability.`,
      remediation: "Define a CSP starting from script-src 'self'; object-src 'none'; base-uri 'self'.",
      affected_url: url,
    });
  } else if (/unsafe-inline|\*/.test(get("content-security-policy"))) {
    out.push({
      title: "Weak CSP (contains 'unsafe-inline' or *)", severity: "low", cvss_score: 3.5,
      finding_type: "weak_csp", vuln_class: "xss_defence",
      description: `CSP for ${url} uses unsafe-inline / wildcard — XSS bypass trivial.`,
      remediation: "Adopt nonces/hashes, remove unsafe-inline, restrict source lists.",
      affected_url: url, evidence: { csp: get("content-security-policy") },
    });
  }
  if (!get("x-content-type-options")) {
    out.push({
      title: "X-Content-Type-Options header missing", severity: "info", cvss_score: 2.0,
      finding_type: "missing_xcto", vuln_class: "mime_sniffing",
      description: `${url} allows MIME sniffing — adds attack surface to uploads/reflected files.`,
      remediation: "Set: X-Content-Type-Options: nosniff", affected_url: url,
    });
  }
  if (!get("x-frame-options") && !/frame-ancestors/i.test(get("content-security-policy"))) {
    out.push({
      title: "Clickjacking protection missing", severity: "low", cvss_score: 3.1,
      finding_type: "missing_xfo", vuln_class: "clickjacking",
      description: `${url} can be iframed by any origin (no X-Frame-Options / frame-ancestors).`,
      remediation: "Add X-Frame-Options: DENY or CSP frame-ancestors 'self'.",
      affected_url: url,
    });
  }
  if (!get("referrer-policy")) {
    out.push({
      title: "Referrer-Policy header missing", severity: "info", cvss_score: 1.6,
      finding_type: "missing_referrer_policy", vuln_class: "info_leak",
      description: `${url} leaks full Referer to third-party origins on outbound links.`,
      remediation: "Add Referrer-Policy: strict-origin-when-cross-origin", affected_url: url,
    });
  }
  const aco = get("access-control-allow-origin");
  const acc = get("access-control-allow-credentials");
  if (aco === "*" && /true/i.test(acc)) {
    out.push({
      title: "CORS: wildcard origin with credentials", severity: "high", cvss_score: 7.5,
      finding_type: "cors_credentialed_wildcard", vuln_class: "cors_misconfig",
      description: `${url} returns Access-Control-Allow-Origin: * with Allow-Credentials: true. Browsers normally block this but reverse-proxies & older UAs can be exploited.`,
      remediation: "Echo only allow-listed origins, never *, when credentials are enabled.",
      affected_url: url, evidence: { aco, acc },
    });
  }
  // Reflected-origin CORS check
  const reflectProbe = await probeFetch(url, { headers: { Origin: "https://evil.example.com" } }, 6000);
  if (reflectProbe.ok) {
    const acoR = reflectProbe.response.headers.get("access-control-allow-origin") || "";
    if (acoR === "https://evil.example.com") {
      out.push({
        title: "CORS: reflected arbitrary Origin", severity: "high", cvss_score: 7.5,
        finding_type: "cors_reflected_origin", vuln_class: "cors_misconfig",
        description: `${url} reflected Origin: https://evil.example.com in Access-Control-Allow-Origin.`,
        remediation: "Validate Origin against an allow-list before echoing.",
        affected_url: url, evidence: { reflected_aco: acoR },
      });
    }
  }
  // Cookie hygiene
  const setCookies = hdrs.get("set-cookie") || "";
  if (setCookies) {
    if (!/HttpOnly/i.test(setCookies)) {
      out.push({
        title: "Cookie missing HttpOnly flag", severity: "low", cvss_score: 3.5,
        finding_type: "cookie_missing_httponly", vuln_class: "session_security",
        description: `${url} sets cookies without HttpOnly — any XSS reads session tokens.`,
        remediation: "Mark session cookies HttpOnly.",
        affected_url: url, evidence: { set_cookie: setCookies.slice(0, 200) },
      });
    }
    if (isHttps && !/Secure/i.test(setCookies)) {
      out.push({
        title: "Cookie missing Secure flag on HTTPS site", severity: "low", cvss_score: 3.7,
        finding_type: "cookie_missing_secure", vuln_class: "session_security",
        description: `${url} sets cookies without Secure — cookie may leak over downgraded HTTP.`,
        remediation: "Mark cookies Secure when serving HTTPS.",
        affected_url: url,
      });
    }
    if (!/SameSite=/i.test(setCookies)) {
      out.push({
        title: "Cookie missing SameSite attribute", severity: "low", cvss_score: 3.1,
        finding_type: "cookie_missing_samesite", vuln_class: "csrf",
        description: `${url} cookies have no SameSite — CSRF surface widened.`,
        remediation: "Set SameSite=Lax or Strict for session cookies.",
        affected_url: url,
      });
    }
  }
  // Server/version banner leakage
  const server = get("server"); const xpb = get("x-powered-by");
  if (/\d/.test(server) || /\d/.test(xpb)) {
    out.push({
      title: "Server/X-Powered-By banner leaks version", severity: "info", cvss_score: 2.0,
      finding_type: "version_banner", vuln_class: "info_leak",
      description: `Server="${server}", X-Powered-By="${xpb}" disclose stack versions, easing CVE matching.`,
      remediation: "Strip Server and X-Powered-By headers at the reverse proxy.",
      affected_url: url, evidence: { server, x_powered_by: xpb },
    });
  }
}

async function auditMethods(baseUrl: string, out: Finding[]) {
  const url = baseUrl.replace(/\/$/, "") + "/";
  const r = await probeFetch(url, { method: "OPTIONS" }, 6000);
  if (!r.ok) return;
  const allow = r.response.headers.get("allow") || r.response.headers.get("access-control-allow-methods") || "";
  if (!allow) return;
  const risky = ["PUT", "DELETE", "TRACE", "TRACK", "CONNECT", "PATCH"];
  const exposed = risky.filter((m) => new RegExp(`\\b${m}\\b`, "i").test(allow));
  if (exposed.length) {
    out.push({
      title: `Risky HTTP methods enabled: ${exposed.join(", ")}`,
      severity: exposed.includes("TRACE") || exposed.includes("PUT") ? "medium" : "low",
      cvss_score: exposed.includes("PUT") ? 6.5 : 4.0,
      finding_type: "risky_http_methods", vuln_class: "protocol_misconfig",
      description: `${url} OPTIONS returned Allow: ${allow}. Risky methods can enable arbitrary upload, XST, or smuggling.`,
      remediation: "Disable PUT/DELETE/TRACE/TRACK/CONNECT at the reverse proxy unless explicitly required.",
      affected_url: url, evidence: { allow },
    });
  }
}

async function auditPublicFiles(baseUrl: string, out: Finding[]) {
  const targets = [
    "/.env", "/.git/HEAD", "/.git/config", "/.svn/entries", "/.DS_Store",
    "/backup.zip", "/backup.tar.gz", "/db.sql", "/phpinfo.php", "/server-status",
    "/.well-known/security.txt", "/robots.txt", "/sitemap.xml",
    "/wp-config.php.bak", "/config.json", "/credentials.json",
  ];
  const root = baseUrl.replace(/\/$/, "");
  const probes = await Promise.allSettled(targets.map(async (p) => {
    const u = root + p;
    const r = await probeFetch(u, { method: "GET" }, 5000);
    if (!r.ok) return null;
    const body = await readBodySafe(r.response, 8 * 1024);
    return { path: p, url: u, status: r.response.status, len: body.length, body };
  }));
  for (const s of probes) {
    if (s.status !== "fulfilled" || !s.value) continue;
    const { path, url, status, len, body } = s.value;
    if (status >= 400 || len < 5) continue;
    const looksReal =
      (path === "/.env" && /^[A-Z][A-Z0-9_]+=/m.test(body)) ||
      (path === "/.git/HEAD" && /^ref:\s*refs\//m.test(body)) ||
      (path === "/.git/config" && /\[core\]/.test(body)) ||
      (path === "/.svn/entries" && /^12$/m.test(body)) ||
      (path === "/.DS_Store" && body.length > 100) ||
      (path === "/phpinfo.php" && /PHP Version/i.test(body)) ||
      (path === "/server-status" && /Apache Server Status/i.test(body)) ||
      (path.endsWith(".sql") && /CREATE TABLE|INSERT INTO/i.test(body)) ||
      (path.endsWith(".zip") || path.endsWith(".tar.gz")) ||
      (path === "/wp-config.php.bak" && /DB_PASSWORD/i.test(body)) ||
      (path === "/config.json" && /\{[\s\S]*"/m.test(body)) ||
      (path === "/credentials.json" && /\{[\s\S]*"/m.test(body));
    if (looksReal) {
      out.push({
        title: `Sensitive file publicly exposed: ${path}`,
        severity: path === "/.env" || path.includes(".git") || path.endsWith(".sql") || path === "/wp-config.php.bak" ? "critical" : "high",
        cvss_score: path === "/.env" ? 9.1 : path.includes(".git") ? 8.6 : 7.5,
        finding_type: "sensitive_file_exposure", vuln_class: "info_disclosure",
        description: `${url} is publicly readable (HTTP ${status}, ${len}B). Contents match a real configuration / VCS artefact.`,
        remediation: `Block ${path} at the reverse proxy (return 404), rotate any leaked credentials.`,
        affected_url: url,
        poc: `curl -i ${url}`,
        evidence: { snippet: body.slice(0, 400), bytes: len },
      });
    } else if (path === "/robots.txt" || path === "/.well-known/security.txt" || path === "/sitemap.xml") {
      // Informational only
    }
  }
}

async function auditOpenRedirect(baseUrl: string, out: Finding[]) {
  const u = new URL(baseUrl);
  const params = ["next", "redirect", "url", "return", "returnTo", "rurl", "dest", "destination", "continue"];
  for (const p of params) {
    const probeUrl = `${u.origin}${u.pathname || "/"}?${p}=https://evil.example.com/`;
    const r = await probeFetch(probeUrl, { redirect: "manual" }, 5000);
    if (!r.ok) continue;
    const loc = r.response.headers.get("location") || "";
    if (/^https?:\/\/evil\.example\.com/i.test(loc)) {
      out.push({
        title: `Open redirect via ?${p}=`, severity: "medium", cvss_score: 6.1,
        finding_type: "open_redirect", vuln_class: "open_redirect",
        description: `${probeUrl} returned Location: ${loc}. Attacker-controlled targets enable phishing & OAuth chains.`,
        remediation: "Validate redirect targets against an allow-list of internal paths.",
        affected_url: probeUrl, poc: `curl -i '${probeUrl}'`, evidence: { location: loc },
      });
      break;
    }
  }
}

async function auditJsSecrets(baseUrl: string, out: Finding[]) {
  // Fetch root HTML, find ≤10 first-party JS URLs, regex-scan each for secrets.
  const r = await probeFetch(baseUrl, {}, 6000);
  if (!r.ok) return;
  const html = await readBodySafe(r.response, 64 * 1024);
  const jsUrls = new Set<string>();
  const root = new URL(baseUrl);
  const reScript = /<script[^>]+src=["']([^"']+\.js[^"']*)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = reScript.exec(html)) !== null) {
    try {
      const u = new URL(m[1], root);
      if (u.host === root.host) jsUrls.add(u.toString());
    } catch { /* ignore */ }
    if (jsUrls.size >= 8) break;
  }
  // Always include /js/main.js and /static/js/bundle.js style attempts
  const guesses = ["/main.js", "/app.js", "/bundle.js", "/static/js/main.js", "/static/js/app.js"];
  for (const g of guesses) jsUrls.add(new URL(g, root).toString());

  const checked: string[] = [];
  for (const jsUrl of jsUrls) {
    if (checked.length >= 12) break;
    checked.push(jsUrl);
    const jr = await probeFetch(jsUrl, {}, 5000);
    if (!jr.ok || jr.response.status >= 400) continue;
    const body = await readBodySafe(jr.response, 256 * 1024);
    if (body.length < 20) continue;
    const hits: Record<string, string[]> = {};
    for (const [name, re] of SECRET_PATTERNS) {
      const matches = body.match(new RegExp(re.source, "g"));
      if (matches?.length) hits[name] = [...new Set(matches.slice(0, 3))];
    }
    if (Object.keys(hits).length) {
      const types = Object.keys(hits).join(", ");
      out.push({
        title: `Secrets / tokens leaked in JS bundle (${types})`,
        severity: /private_key|aws_secret|stripe_live|gitlab_token|github_token|slack_token/.test(types) ? "critical" : "high",
        cvss_score: 8.6,
        finding_type: "secret_in_js", vuln_class: "info_disclosure",
        description: `Pattern matches for ${types} were found in ${jsUrl}. These are reachable by any browser visitor.`,
        remediation: "Rotate the leaked secrets immediately. Move secrets to server-side, never inline them in client bundles.",
        affected_url: jsUrl, poc: `curl -s ${jsUrl} | head -c 2000`, evidence: hits,
      });
    }
    // Source-map leak
    if (/\/\/[#@]\s*sourceMappingURL=/.test(body)) {
      out.push({
        title: `Source map reference in production JS: ${jsUrl}`,
        severity: "low", cvss_score: 3.5,
        finding_type: "source_map_exposed", vuln_class: "info_disclosure",
        description: `${jsUrl} contains a sourceMappingURL comment — original source/paths may be downloadable.`,
        remediation: "Strip sourceMappingURL from production bundles or restrict .map files at the edge.",
        affected_url: jsUrl,
      });
    }
  }
}

async function recordFindings(db: any, targetId: string, findings: Finding[]) {
  if (!findings.length) return 0;
  // Dedup against existing same-type/same-url to avoid spam.
  const inserts = findings.map((f) => ({
    target_id: targetId,
    title: f.title,
    severity: f.severity,
    cvss_score: f.cvss_score,
    finding_type: f.finding_type,
    vuln_class: f.vuln_class,
    description: f.description,
    remediation: f.remediation,
    affected_url: f.affected_url || null,
    poc: f.poc || null,
    confidence_score: 90,
    confidence_level: "high",
    validation_status: "confirmed",
    ai_verified: false,
    reachability_status: "reachable",
    source: "recon-juicy",
    evidence: f.evidence || {},
  }));
  // Bulk insert; ignore individual conflicts
  const { data, error } = await db.from("vulnerability_findings").insert(inserts).select("id");
  if (error) {
    // Fall back to per-row insert so a single conflict doesn't drop all
    let n = 0;
    for (const row of inserts) {
      const { error: e2 } = await db.from("vulnerability_findings").insert(row);
      if (!e2) n++;
    }
    return n;
  }
  return data?.length || 0;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  const ok = (b: Record<string, unknown>) =>
    new Response(JSON.stringify(b), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });

  try {
    const { targetId } = await req.json().catch(() => ({}));
    if (!targetId) return ok({ ok: false, error: "targetId required" });
    const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

    const guard = await checkLoopGuard(db, targetId, "recon-juicy", { maxRuns: 5, stallStreak: 3 });
    if (!guard.allow) return ok({ ok: false, skipped: true, reason: guard.reason });

    const { data: tgt } = await db.from("target_workspaces").select("domain,url").eq("id", targetId).maybeSingle();
    const apex = String(tgt?.domain || (tgt?.url ? new URL(tgt.url).hostname : "") || "").toLowerCase().trim();
    if (!apex) return ok({ ok: false, error: "no domain on target" });

    const { data: assetRows } = await db.from("scan_assets")
      .select("host,base_url").eq("target_id", targetId).limit(20);
    const assets: Array<{ host: string; base_url: string }> = (assetRows || []).length
      ? assetRows!.map((a: any) => ({ host: a.host, base_url: a.base_url }))
      : [{ host: apex, base_url: `https://${apex}` }];

    const findings: Finding[] = [];
    await db.from("scan_logs").insert({
      target_id: targetId, log_type: "action",
      message: `🔎 recon-juicy: auditing ${assets.length} asset(s) for DNS/TLS/header/leak findings`,
      metadata: { phase: "recon-juicy-start", assets: assets.length },
    }).catch(() => {});

    // DNS audit once per unique apex
    const apexes = new Set<string>();
    for (const a of assets) {
      const parts = a.host.split(".");
      const ax = parts.length >= 2 ? parts.slice(-2).join(".") : a.host;
      apexes.add(ax);
    }
    for (const a of apexes) await auditDns(a, findings);

    // Per-asset audits with bounded fan-out
    const subset = assets.slice(0, 8);
    await Promise.allSettled(subset.flatMap((a) => [
      auditTlsAndHeaders(a.base_url, a.host, findings),
      auditMethods(a.base_url, findings),
      auditPublicFiles(a.base_url, findings),
      auditOpenRedirect(a.base_url, findings),
      auditJsSecrets(a.base_url, findings),
    ]));

    const inserted = await recordFindings(db, targetId, findings);
    await db.from("scan_logs").insert({
      target_id: targetId,
      log_type: inserted > 0 ? "result" : "info",
      message: `🔎 recon-juicy: ${inserted}/${findings.length} findings recorded across ${assets.length} asset(s)`,
      metadata: { phase: "recon-juicy-end", findings: inserted, candidates: findings.length },
    }).catch(() => {});

    return ok({ ok: true, findings: inserted, candidates: findings.length, assets: assets.length });
  } catch (e) {
    return ok({ ok: false, error: e instanceof Error ? e.message : String(e) });
  }
});
