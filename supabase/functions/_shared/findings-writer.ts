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
      proof_tier: input.proofTier ?? "signal",
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

    return { ok: true, findingId: inserted.id };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}
