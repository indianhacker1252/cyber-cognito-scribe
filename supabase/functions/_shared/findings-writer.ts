// Central writer for vulnerability findings + OWASP coverage + replay storage.
// All scanner modules MUST go through this so nothing gets dropped from the
// global findings queue (Part A of the plan).
import { createClient, SupabaseClient } from "https://esm.sh/@supabase/supabase-js@2";

const MAX_RAW = 32 * 1024; // 32 KB cap on raw req/resp blobs

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface RecordFindingInput {
  targetId: string;
  source: string;                  // e.g. "recon-secret", "param-brute-xss"
  category?: string;               // OWASP A0X-* slug; defaults to source
  severity: Severity;
  title: string;
  description?: string;
  payload?: string;
  poc?: string;
  proofTier?: "signal" | "reflected" | "exploited" | "suspected" | "indicator" | "advisory";
  evidence?: Record<string, unknown>;
  request?: { method: string; url: string; headers?: Record<string,string>; body?: string };
  response?: { status: number; headers?: Record<string,string>; body?: string };
  scanLogId?: string;
  endpointId?: string | null;
  vulnClass?: string;
  /** When true, queue a scan_jobs row of type "exploit" so the exploit engine picks this up. */
  autoEnqueueExploit?: boolean;
  runId?: string | null;
}

export interface RecordFindingResult {
  ok: boolean;
  findingId?: string;
  duplicate?: boolean;
  exploitJobId?: string;
  error?: string;
}


function db(): SupabaseClient {
  return createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
}

function clip(s: string | undefined, n = MAX_RAW): string | null {
  if (!s) return null;
  return s.length > n ? s.slice(0, n) + `\n…[truncated ${s.length - n} bytes]` : s;
}

function serializeRequest(r?: RecordFindingInput["request"]): string | null {
  if (!r) return null;
  const u = new URL(r.url);
  const lines: string[] = [`${r.method} ${u.pathname}${u.search} HTTP/1.1`, `Host: ${u.host}`];
  if (r.headers) for (const [k,v] of Object.entries(r.headers)) lines.push(`${k}: ${v}`);
  if (r.body) lines.push("", r.body);
  return clip(lines.join("\r\n"));
}

function serializeResponse(r?: RecordFindingInput["response"]): string | null {
  if (!r) return null;
  const lines: string[] = [`HTTP/1.1 ${r.status}`];
  if (r.headers) for (const [k,v] of Object.entries(r.headers)) lines.push(`${k}: ${v}`);
  if (r.body !== undefined) lines.push("", r.body);
  return clip(lines.join("\r\n"));
}

function computeDiff(req?: RecordFindingInput["request"], resp?: RecordFindingInput["response"]): Record<string, unknown> {
  return {
    status: resp?.status ?? null,
    response_length: resp?.body?.length ?? 0,
    has_request: !!req,
    has_response: !!resp,
  };
}

const OWASP_MAP: Record<string,string> = {
  "xss": "A03_injection",
  "param-brute-xss": "A03_injection",
  "sqli": "A03_injection",
  "ssti": "A03_injection",
  "ssrf": "A10_ssrf",
  "idor": "A01_broken_access_control",
  "bac": "A01_broken_access_control",
  "differential-oracle": "A01_broken_access_control",
  "symbolic-param-explorer": "A01_broken_access_control",
  "auth-confusion": "A07_auth_failures",
  "jwt": "A07_auth_failures",
  "oauth": "A07_auth_failures",
  "business-logic": "A04_insecure_design",
  "business-logic-fuzzer": "A04_insecure_design",
  "prototype-pollution": "A08_software_integrity",
  "desync-smuggling": "A05_misconfig",
  "ai-surface": "A03_injection",
  "recon-secret": "A02_crypto_failures",
  "secret-exposure": "A02_crypto_failures",
  "cve": "A06_vuln_components",
};

/**
 * Writes a finding, the replay row, and upserts OWASP coverage.
 * Idempotent on (target_id, source, payload) — duplicates return ok+duplicate=true.
 */
export async function recordFinding(input: RecordFindingInput): Promise<RecordFindingResult> {
  const supa = db();
  try {
    // ───── 3xx redirect guard ─────
    // A 301/302/303/307/308 response is almost always an auth/login redirect
    // or framework-level routing — NOT a vulnerability. Drop unless the
    // source is explicitly a redirect/smuggling/cache check that needs 3xx.
    const status = input.response?.status;
    if (status && status >= 300 && status < 400) {
      const allow3xx = /open[-_ ]?redirect|smuggl|cache|host[-_ ]?header|desync|auth[-_ ]?bypass|redirect/i
        .test(`${input.source} ${input.category ?? ""} ${input.vulnClass ?? ""} ${input.title}`);
      const loc = input.response?.headers?.["location"] || input.response?.headers?.["Location"] || "";
      const looksLikeLogin = /login|signin|sign-in|auth|sso|oauth|account/i.test(loc);
      if (!allow3xx || looksLikeLogin) {
        return { ok: true, duplicate: true, error: `suppressed: ${status} redirect${loc ? ` → ${loc.slice(0, 80)}` : ""}` };
      }
    }

    // ───── Hard proof gate (Gap #3) ─────
    // 'exploited' tier requires a deterministic marker. Otherwise downgrade.
    let tier = input.proofTier ?? "signal";
    if (tier === "exploited") {
      const blob = JSON.stringify(input.evidence || {}) + " " + (input.response?.body || "") + " " + (input.payload || "");
      const HARD_MARKERS = [
        /CYBERSCOPE_PROVEN/, /SPECTER_LLM_CONFIRMED/i,
        /root:.*:0:0:/, /\boob[_-]?(callback|hit|received)\b/i,
        /ami-id|instance-id|iam\/security-credentials/i,
        /serviceAccounts|projectNumber/i,
        /redis_version|connected_clients/i,
        /you have an error in your sql syntax/i,
        /ORA-\d{4,5}|PG::SyntaxError|psql: ERROR|PostgreSQL.*ERROR/i,
      ];
      if (!HARD_MARKERS.some(rx => rx.test(blob))) {
        tier = "reflected";
      }
    }

    // duplicate guard
    if (input.payload) {
      const { data: existing } = await supa.from("vulnerability_findings")
        .select("id").eq("target_id", input.targetId).eq("source", input.source)
        .eq("payload", input.payload).limit(1).maybeSingle();
      if (existing?.id) return { ok: true, findingId: existing.id, duplicate: true };
    }


    const requestRaw = serializeRequest(input.request);
    const responseRaw = serializeResponse(input.response);
    const responseDiff = computeDiff(input.request, input.response);

    const row = {
      target_id: input.targetId,
      endpoint_id: input.endpointId ?? null,
      title: input.title,
      severity: input.severity,
      description: input.description ?? null,
      payload: input.payload ?? null,
      poc: input.poc ?? null,
      proof_tier: tier,

      source: input.source,
      finding_type: input.category ?? input.source,
      hard_evidence: input.evidence ?? {},
      evidence: input.evidence ?? {},
      request_raw: requestRaw,
      response_raw: responseRaw,
      response_diff: responseDiff,
      ai_verified: false,
    };

    const { data: inserted, error } = await supa.from("vulnerability_findings")
      .insert(row).select("id").single();
    if (error) return { ok: false, error: error.message };

    // replay row (best-effort)
    if (input.request) {
      await supa.from("request_replays").insert({
        user_id: "00000000-0000-0000-0000-000000000000",
        target_id: input.targetId,
        finding_id: inserted.id,
        label: input.source,
        request: {
          method: input.request.method,
          url: input.request.url,
          headers: input.request.headers ?? {},
          body: input.request.body ?? null,
        },
        response: input.response ? {
          status: input.response.status,
          headers: input.response.headers ?? {},
          body: clip(input.response.body, 16384),
        } : null,
        diff: responseDiff,
        is_interesting: true,
      }).then(() => {}, () => {}); // ignore schema diffs
    }

    // OWASP coverage insert (best-effort). The table intentionally has no
    // uniqueness constraint, so insert a run breadcrumb instead of an upsert.
    const cat = OWASP_MAP[input.category ?? input.source] ?? OWASP_MAP[input.source] ?? "A03_injection";
    await supa.from("owasp_coverage").insert({
      target_id: input.targetId,
      owasp_category: cat,
      checks_run: 1,
      payloads_sent: input.payload ? 1 : 0,
      findings_count: 1,
      waf_blocked: 0,
      metadata: { source: input.source, finding_type: input.category ?? input.source },
    }).then(() => {}, () => {});

    // scan log breadcrumb
    if (input.scanLogId) {
      await supa.from("scan_logs").insert({
        target_id: input.targetId,
        task_id: input.scanLogId,
        log_type: "result",
        message: `[finding] ${input.source} ${input.severity} ${input.title}`,
        metadata: { finding_id: inserted.id, source: input.source },
      }).then(() => {}, () => {});
    }

    // Auto-enqueue exploit-engine job (Section 1 of plan).
    let exploitJobId: string | undefined;
    const shouldQueue = input.autoEnqueueExploit
      || ["high", "critical"].includes(input.severity)
      || ["indicator", "suspected", "reflected"].includes(input.proofTier || "");
    if (shouldQueue) {
      try {
        const { data: job } = await supa.from("scan_jobs").insert({
          target_id: input.targetId,
          job_type: "exploit",
          priority: input.severity === "critical" ? 9 : input.severity === "high" ? 8 : 5,
          payload: {
            findingId: inserted.id,
            vuln_class: input.vulnClass || input.category || input.source,
            url: input.request?.url,
            payload: input.payload,
            evidence: input.evidence || {},
            runId: input.runId || null,
          },
          status: "queued",
          next_run_at: new Date().toISOString(),
        }).select("id").single();
        exploitJobId = job?.id;
        if (exploitJobId) {
          await supa.from("scan_logs").insert({
            target_id: input.targetId,
            log_type: "action",
            message: `💀 Exploit Engine engaging — finding ${inserted.id} queued (${input.severity} ${input.source})`,
            metadata: { kind: "exploit_enqueued", finding_id: inserted.id, job_id: exploitJobId, run_id: input.runId },
          }).then(() => {}, () => {});
        }
      } catch { /* best-effort */ }
    }

    return { ok: true, findingId: inserted.id, exploitJobId };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

// ───────────────────────── Heuristic surface ranker (gap 11) ─────────────────────────
// Fallback used when AI-driven surface analysis is unavailable (credits exhausted).
export interface RankedEndpoint { url: string; method: string; parameters?: Record<string, unknown>; score: number; reason: string }
export function heuristicRankSurface(eps: Array<{ url: string; method?: string; parameters?: Record<string, unknown>; status_code?: number; response_length?: number }>, limit = 30): RankedEndpoint[] {
  const scored: RankedEndpoint[] = [];
  for (const e of eps) {
    if (!e.url) continue;
    let score = 0;
    const reasons: string[] = [];
    const params = e.parameters || {};
    const paramCount = Object.keys(params).length;
    if (paramCount > 0) { score += 20 + Math.min(paramCount, 5) * 3; reasons.push(`${paramCount} params`); }
    if (e.status_code === 200) { score += 10; }
    else if (e.status_code === 302 || e.status_code === 301) { score += 7; }
    else if (e.status_code === 401 || e.status_code === 403) { score += 8; reasons.push("auth-gated"); }
    if (/admin|api|login|upload|debug|graphql|console|actuator|swagger|internal/i.test(e.url)) { score += 15; reasons.push("juicy-path"); }
    if (/\?.*(?:url|redirect|callback|next|target|file|path|id|user|cmd)=/i.test(e.url)) { score += 12; reasons.push("dangerous-param"); }
    if ((e.method || "GET").toUpperCase() !== "GET") { score += 5; reasons.push(e.method!); }
    const rl = e.response_length || 0;
    if (rl > 5000) score += Math.min(8, Math.floor(rl / 5000));
    scored.push({ url: e.url, method: (e.method || "GET").toUpperCase(), parameters: params, score, reason: reasons.join("+") || "baseline" });
  }
  scored.sort((a, b) => b.score - a.score);
  return scored.slice(0, limit);
}

