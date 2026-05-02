// recon-deep — Subdomain takeover, exposed files, public buckets, source maps
//
// Tests:
//  1. Subdomain takeover: CNAME → unclaimed S3/Heroku/GitHub Pages/Azure/etc.
//  2. Exposed files: /.git/HEAD, /.env, /.DS_Store, /actuator, /swagger.json
//  3. Source map leak: <bundle>.js.map exposed
//  4. Public S3/GCS bucket guesses based on target name
//
// All findings → confirmFinding (deterministic markers required).

import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.0";
import { safeFetch, readBodySafe, headersToObject } from "../_shared/safe-fetch.ts";
import { confirmFinding } from "../_shared/ai-confirm-gate.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};
const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

// Subdomain-takeover fingerprints (subset — most common services)
const TAKEOVER_FINGERPRINTS: { service: string; rx: RegExp }[] = [
  { service: "GitHub Pages", rx: /There isn't a GitHub Pages site here\.|For root URLs.*you must provide an index\.html/i },
  { service: "AWS S3",       rx: /NoSuchBucket|The specified bucket does not exist/i },
  { service: "Heroku",       rx: /no-such-app\.html|herokucdn\.com.*no-such-app/i },
  { service: "Azure",        rx: /404 Web Site not found.*azurewebsites/i },
  { service: "Fastly",       rx: /Fastly error: unknown domain/i },
  { service: "Shopify",      rx: /Sorry, this shop is currently unavailable/i },
  { service: "Tumblr",       rx: /Whatever you were looking for doesn't currently exist at this address/i },
  { service: "Unbounce",     rx: /The requested URL was not found on this server/i },
  { service: "Zendesk",      rx: /Help Center Closed/i },
  { service: "Pantheon",     rx: /The gods are wise.*but do not know of the site which you seek/i },
];

const EXPOSED_PATHS: { path: string; rx: RegExp; severity: "high"|"critical"|"medium" }[] = [
  { path: "/.git/HEAD",            rx: /^ref: refs\/heads\//,       severity: "high" },
  { path: "/.git/config",          rx: /\[core\]|\[remote /,        severity: "high" },
  { path: "/.env",                 rx: /^[A-Z_]+\s*=.+$/m,           severity: "critical" },
  { path: "/.DS_Store",            rx: /Bud1/,                       severity: "medium" },
  { path: "/actuator",             rx: /"_links"\s*:\s*\{|"href"\s*:/, severity: "high" },
  { path: "/actuator/env",         rx: /"propertySources"|"systemEnvironment"/, severity: "critical" },
  { path: "/actuator/heapdump",    rx: /^JAVA PROFILE/,              severity: "critical" },
  { path: "/swagger.json",         rx: /"swagger"\s*:\s*"|"openapi"\s*:\s*"/, severity: "medium" },
  { path: "/swagger-ui.html",      rx: /Swagger UI/i,                severity: "medium" },
  { path: "/_profiler",            rx: /Symfony Profiler/i,          severity: "high" },
  { path: "/server-status",        rx: /Apache Server Status/i,      severity: "medium" },
  { path: "/phpinfo.php",          rx: /<title>phpinfo\(\)<\/title>/i, severity: "high" },
  { path: "/.aws/credentials",     rx: /\[default\][\s\S]*aws_access_key_id/i, severity: "critical" },
  { path: "/wp-config.php.bak",    rx: /DB_PASSWORD|DB_USER/i,       severity: "critical" },
];

interface ReconInput { targetId: string; baseUrl: string; jsBundleUrls?: string[]; }

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  const supa = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
  let input: ReconInput;
  try { input = await req.json(); } catch { return j({ ok: false, error: "invalid json" }); }
  if (!input.baseUrl) return j({ ok: false, error: "baseUrl required" });

  const findings: any[] = [];

  // ── Subdomain takeover (probe the base URL itself for fingerprint)
  try {
    const r = await safeFetch(input.baseUrl, {}, 6000);
    const body = await readBodySafe(r, 6000);
    for (const fp of TAKEOVER_FINGERPRINTS) {
      if (fp.rx.test(body)) {
        const verdict = await confirmFinding({
          vulnClass: "subdomain-takeover", payload: input.baseUrl, endpoint: input.baseUrl,
          mutated: { status: r.status, bodySnippet: body.slice(0, 1500), length: body.length, headers: headersToObject(r.headers) },
          deterministicProof: true, proofType: `takeover_${fp.service.replace(/\W/g, "_")}`,
        });
        if (verdict.recommendedAction !== "drop_false_positive" && verdict.recommendedAction !== "drop_honeypot") {
          findings.push(await persist(supa, input.targetId, {
            kind: "subdomain-takeover", severity: "critical",
            title: `Subdomain takeover possible (${fp.service})`,
            url: input.baseUrl, payload: input.baseUrl, body, status: r.status, verdict,
          }));
        }
        break;
      }
    }
  } catch (_) {}

  // ── Exposed files
  for (const ep of EXPOSED_PATHS) {
    try {
      const url = new URL(ep.path, input.baseUrl).toString();
      const r = await safeFetch(url, {}, 5000);
      if (r.status !== 200) { await readBodySafe(r, 0); continue; }
      const body = await readBodySafe(r, 8000);
      if (!ep.rx.test(body)) continue;

      const verdict = await confirmFinding({
        vulnClass: "exposed-file", payload: ep.path, endpoint: url,
        mutated: { status: r.status, bodySnippet: body.slice(0, 1500), length: body.length, headers: headersToObject(r.headers) },
        deterministicProof: true, proofType: `exposed_${ep.path.replace(/\W/g, "_")}`,
      });
      if (verdict.recommendedAction === "drop_false_positive" || verdict.recommendedAction === "drop_honeypot") continue;
      findings.push(await persist(supa, input.targetId, {
        kind: "exposed-file", severity: ep.severity,
        title: `Sensitive file exposed: ${ep.path}`,
        url, payload: ep.path, body, status: r.status, verdict,
      }));
    } catch (_) {}
  }

  // ── Source map leak
  for (const bundle of input.jsBundleUrls || []) {
    try {
      const mapUrl = bundle + ".map";
      const r = await safeFetch(mapUrl, {}, 5000);
      if (r.status !== 200) { await readBodySafe(r, 0); continue; }
      const body = await readBodySafe(r, 4000);
      if (!/"version"\s*:\s*3.*"sources"\s*:\s*\[/s.test(body)) continue;
      const verdict = await confirmFinding({
        vulnClass: "source-map-leak", payload: mapUrl, endpoint: mapUrl,
        mutated: { status: r.status, bodySnippet: body.slice(0, 1500), length: body.length, headers: headersToObject(r.headers) },
        deterministicProof: true, proofType: "sourcemap_v3_exposed",
      });
      if (verdict.recommendedAction === "drop_false_positive" || verdict.recommendedAction === "drop_honeypot") continue;
      findings.push(await persist(supa, input.targetId, {
        kind: "source-map-leak", severity: "medium",
        title: `Source map exposes original code: ${mapUrl}`,
        url: mapUrl, payload: mapUrl, body, status: r.status, verdict,
      }));
    } catch (_) {}
  }

  // ── Public bucket guesses (S3 only — fast)
  const host = new URL(input.baseUrl).hostname.replace(/^www\./, "");
  const namePart = host.split(".")[0];
  const bucketGuesses = [namePart, `${namePart}-prod`, `${namePart}-assets`, `${namePart}-backup`, `${namePart}-uploads`];
  for (const b of bucketGuesses) {
    try {
      const url = `https://${b}.s3.amazonaws.com/?list-type=2&max-keys=2`;
      const r = await safeFetch(url, {}, 5000);
      const body = await readBodySafe(r, 4000);
      if (r.status === 200 && /<ListBucketResult/.test(body)) {
        const verdict = await confirmFinding({
          vulnClass: "public-s3-bucket", payload: b, endpoint: url,
          mutated: { status: r.status, bodySnippet: body.slice(0, 1500), length: body.length, headers: headersToObject(r.headers) },
          deterministicProof: true, proofType: "s3_list_succeeded",
        });
        if (verdict.recommendedAction !== "drop_false_positive" && verdict.recommendedAction !== "drop_honeypot") {
          findings.push(await persist(supa, input.targetId, {
            kind: "public-s3-bucket", severity: "high",
            title: `Public S3 bucket listing: ${b}`, url, payload: b, body, status: r.status, verdict,
          }));
        }
      }
    } catch (_) {}
  }

  return j({ ok: true, findings_count: findings.length, findings });
});

async function persist(supa: any, targetId: string, f: any) {
  const isApproval = f.verdict.recommendedAction === "insert_approval";
  const table = isApproval ? "pending_approvals" : "vulnerability_findings";
  const row = isApproval
    ? { target_id: targetId, finding_type: f.kind, severity: f.severity, title: f.title,
        description: f.verdict.reasoning, payload_used: f.payload,
        confidence_score: f.verdict.confidence, ai_verified: true, ai_verification_notes: f.verdict.reasoning,
        evidence: { url: f.url, status: f.status, body_snippet: (f.body || "").slice(0,2000), proofType: f.verdict.proofType } }
    : { target_id: targetId, title: f.title, severity: f.severity,
        description: f.verdict.reasoning, payload: f.payload,
        confidence_score: f.verdict.confidence, ai_verified: true,
        triage_reasoning: f.verdict.reasoning, validation_status: "verified" };
  const { data } = await supa.from(table).insert(row).select("id").single();
  return { id: data?.id, kind: f.kind, severity: f.severity, title: f.title };
}
function j(b: unknown, s = 200) { return new Response(JSON.stringify(b), { status: s, headers: { ...corsHeaders, "Content-Type": "application/json" } }); }
