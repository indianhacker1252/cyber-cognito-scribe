// Central writer for vulnerability findings + OWASP coverage + replay storage.
// All scanner modules MUST go through this so nothing gets dropped from the
// global findings queue (Part A of the plan).
import { createClient, SupabaseClient } from "https://esm.sh/@supabase/supabase-js@2";
import { buildDedupKey, inferParam } from "./dedup-key.ts";

const MAX_RAW = 32 * 1024; // 32 KB cap on raw req/resp blobs

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface RecordFindingInput {
  targetId: string;
  source: string; // e.g. "recon-secret", "param-brute-xss"
  category?: string; // OWASP A0X-* slug; defaults to source
  severity: Severity;
  title: string;
  description?: string;
  payload?: string;
  poc?: string;
  proofTier?: "signal" | "reflected" | "exploited" | "suspected" | "indicator" | "advisory";
  evidence?: Record<string, unknown>;
  request?: { method: string; url: string; headers?: Record<string, string>; body?: string };
  response?: { status: number; headers?: Record<string, string>; body?: string };
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
  if (r.headers) for (const [k, v] of Object.entries(r.headers)) lines.push(`${k}: ${v}`);
  if (r.body) lines.push("", r.body);
  return clip(lines.join("\r\n"));
}

function serializeResponse(r?: RecordFindingInput["response"]): string | null {
  if (!r) return null;
  const lines: string[] = [`HTTP/1.1 ${r.status}`];
  if (r.headers) for (const [k, v] of Object.entries(r.headers)) lines.push(`${k}: ${v}`);
  if (r.body !== undefined) lines.push("", r.body);
  return clip(lines.join("\r\n"));
}

function isUniqueViolation(error: unknown): boolean {
  const msg = JSON.stringify(error || {}).toLowerCase();
  return msg.includes("duplicate key") || msg.includes("23505") || msg.includes("unique");
}

function computeDiff(
  req?: RecordFindingInput["request"],
  resp?: RecordFindingInput["response"],
): Record<string, unknown> {
  return {
    status: resp?.status ?? null,
    response_length: resp?.body?.length ?? 0,
    has_request: !!req,
    has_response: !!resp,
  };
}

const OWASP_MAP: Record<string, string> = {
  xss: "A03_injection",
  "param-brute-xss": "A03_injection",
  sqli: "A03_injection",
  ssti: "A03_injection",
  ssrf: "A10_ssrf",
  idor: "A01_broken_access_control",
  bac: "A01_broken_access_control",
  "differential-oracle": "A01_broken_access_control",
  "symbolic-param-explorer": "A01_broken_access_control",
  "auth-confusion": "A07_auth_failures",
  jwt: "A07_auth_failures",
  oauth: "A07_auth_failures",
  "business-logic": "A04_insecure_design",
  "business-logic-fuzzer": "A04_insecure_design",
  "prototype-pollution": "A08_software_integrity",
  "desync-smuggling": "A05_misconfig",
  "ai-surface": "A03_injection",
  "recon-secret": "A02_crypto_failures",
  "secret-exposure": "A02_crypto_failures",
  cve: "A06_vuln_components",
};

/**
 * Writes a finding, the replay row, and upserts OWASP coverage.
 * Idempotent on (target_id, source, payload) — duplicates return ok+duplicate=true.
 */
export async function recordFinding(input: RecordFindingInput): Promise<RecordFindingResult> {
  const supa = db();
  try {
    // ───── 3xx redirect guard ─────
    const status = input.response?.status;
    if (status && status >= 300 && status < 400) {
      const allow3xx = /smuggl|cache|host[-_ ]?header|desync/i.test(
        `${input.source} ${input.category ?? ""} ${input.vulnClass ?? ""} ${input.title}`,
      );
      const loc = input.response?.headers?.["location"] || input.response?.headers?.["Location"] || "";
      const looksLikeLogin = /login|signin|sign-in|auth|sso|oauth|account|callback|redirect_uri/i.test(
        loc + " " + input.title,
      );
      if (!allow3xx || looksLikeLogin) {
        return {
          ok: true,
          duplicate: true,
          error: `suppressed: ${status} redirect${loc ? ` → ${loc.slice(0, 80)}` : ""}`,
        };
      }
    }

    // ───── Open-redirect / auth redirect_uri FP guard ─────
    // Same-origin Location (or to a known auth provider) is NOT an open redirect.
    {
      const cls = (input.vulnClass || input.category || "").toLowerCase();
      const isRedirectCheck = /redirect|oauth/.test(cls) || /redirect[_\s-]?uri|open[_\s-]?redirect/i.test(input.title);
      if (isRedirectCheck) {
        const loc = input.response?.headers?.["location"] || input.response?.headers?.["Location"] || "";
        const reqHost = (() => {
          try {
            return new URL(input.request?.url || "").host.toLowerCase();
          } catch {
            return "";
          }
        })();
        const locHost = (() => {
          try {
            return new URL(loc, input.request?.url || "https://x").host.toLowerCase();
          } catch {
            return "";
          }
        })();
        const apex = reqHost.split(".").slice(-2).join(".");
        const sameOrigin = !!locHost && (locHost === reqHost || (!!apex && locHost.endsWith("." + apex)));
        const trustedAuth =
          /accounts\.google|login\.microsoftonline|github\.com\/login|appleid\.apple|facebook\.com\/(login|dialog)|okta\.com|auth0\.com/i.test(
            locHost,
          );
        const proofMarker = /CYBERSCOPE_PROVEN|attacker\.com|evil\.com/i.test((input.response?.body || "") + " " + loc);
        if ((sameOrigin || trustedAuth) && !proofMarker) {
          return { ok: true, duplicate: true, error: `suppressed: same-origin/trusted auth redirect (${locHost})` };
        }
      }
    }

    // ───── Hard proof gate ─────
    let tier = input.proofTier ?? "signal";
    if (tier === "exploited") {
      const blob =
        JSON.stringify(input.evidence || {}) + " " + (input.response?.body || "") + " " + (input.payload || "");
      const HARD_MARKERS = [
        /CYBERSCOPE_PROVEN/,
        /SPECTER_LLM_CONFIRMED/i,
        /root:.*:0:0:/,
        /\boob[_-]?(callback|hit|received)\b/i,
        /ami-id|instance-id|iam\/security-credentials/i,
        /serviceAccounts|projectNumber/i,
        /redis_version|connected_clients/i,
        /you have an error in your sql syntax/i,
        /ORA-\d{4,5}|PG::SyntaxError|psql: ERROR|PostgreSQL.*ERROR/i,
      ];
      if (!HARD_MARKERS.some((rx) => rx.test(blob))) tier = "reflected";
    }

    // ───── 401/403 noise filter ─────
    if (status === 401 || status === 403) {
      const allowAuth = /bac|idor|auth|differential|priv|jwt|oauth|access/i.test(
        `${input.source} ${input.category ?? ""} ${input.vulnClass ?? ""}`,
      );
      if (!allowAuth) return { ok: true, duplicate: true, error: `suppressed: ${status} auth gate` };
    }

    // ───── Response-similarity filter ─────
    if (input.proofTier === "signal" || input.proofTier === "reflected" || !input.proofTier) {
      const ev = input.evidence as any;
      const baselineLen = Number(ev?.baseline_length ?? ev?.baselineLength ?? 0);
      const respLen = input.response?.body?.length ?? 0;
      const baselineStatus = Number(ev?.baseline_status ?? ev?.baselineStatus ?? 0);
      const hasHardMarker = /CYBERSCOPE_PROVEN|SPECTER_LLM_CONFIRMED/i.test(
        (input.response?.body || "") + " " + (input.payload || ""),
      );
      if (baselineLen > 0 && respLen > 0 && !hasHardMarker) {
        const delta = Math.abs(respLen - baselineLen) / Math.max(baselineLen, respLen);
        const statusChanged = baselineStatus > 0 && baselineStatus !== status;
        if (!statusChanged && delta < 0.05) {
          return { ok: true, duplicate: true, error: `suppressed: noise (Δ${(delta * 100).toFixed(1)}%)` };
        }
      }
    }

    // ───── Dedup + Grouping (master + evidence rows, mythos-style) ─────
    const param = inferParam(input.request, input.evidence as Record<string, unknown>);
    const vulnClass = (input.vulnClass || input.category || input.source || "generic").toLowerCase();
    const dedupKey = buildDedupKey({
      url: input.request?.url,
      method: input.request?.method,
      param,
      vulnClass,
      source: input.source,
    });
    let host = "";
    try {
      host = new URL(input.request?.url || "").host.toLowerCase();
    } catch {
      /* ignore */
    }
    const apex = host.split(".").slice(-2).join(".");
    const groupKey = [apex || host || input.targetId, vulnClass, (param || "").toLowerCase()].join("|");

    const requestRaw = serializeRequest(input.request);
    const responseRaw = serializeResponse(input.response);
    const responseDiff = computeDiff(input.request, input.response);

    // Existing master → append evidence and bump counters
    const { data: master } = await supa
      .from("vulnerability_findings")
      .select("id,evidence_count")
      .eq("target_id", input.targetId)
      .or(`group_key.eq."${groupKey}",dedup_key.eq."${dedupKey}"`)
      .order("created_at", { ascending: true })
      .limit(1)
      .maybeSingle();

    if (master?.id) {
      const { error: evidenceError } = await supa.from("finding_evidence").insert({
        finding_id: master.id,
        target_id: input.targetId,
        affected_url: input.request?.url ?? null,
        method: input.request?.method ?? null,
        param: param || null,
        payload: input.payload ?? null,
        status_code: status ?? null,
        request_raw: requestRaw,
        response_raw: responseRaw,
        evidence: input.evidence ?? {},
      });
      if (!evidenceError) {
        await supa
          .from("vulnerability_findings")
          .update({
            evidence_count: (master.evidence_count || 1) + 1,
            last_seen_at: new Date().toISOString(),
          })
          .eq("id", master.id);
      } else if (!isUniqueViolation(evidenceError)) {
        console.warn("finding_evidence insert failed", evidenceError.message || evidenceError);
      }
      return { ok: true, findingId: master.id, duplicate: true };
    }

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
      dedup_key: dedupKey,
      group_key: groupKey,
      evidence_count: 1,
      first_seen_at: new Date().toISOString(),
      last_seen_at: new Date().toISOString(),
    };

    const { data: inserted, error } = await supa.from("vulnerability_findings").insert(row).select("id").single();
    if (error) {
      if (/duplicate key|unique/i.test(error.message)) {
        const { data: row2 } = await supa
          .from("vulnerability_findings")
          .select("id")
          .eq("target_id", input.targetId)
          .eq("dedup_key", dedupKey)
          .maybeSingle();
        if (row2?.id) return { ok: true, findingId: row2.id, duplicate: true };
      }
      return { ok: false, error: error.message };
    }

    await supa
      .from("finding_evidence")
      .insert({
        finding_id: inserted.id,
        target_id: input.targetId,
        affected_url: input.request?.url ?? null,
        method: input.request?.method ?? null,
        param: param || null,
        payload: input.payload ?? null,
        status_code: status ?? null,
        request_raw: requestRaw,
        response_raw: responseRaw,
        evidence: input.evidence ?? {},
      })
      .then(
        () => {},
        (e) => {
          if (!isUniqueViolation(e)) console.warn("initial finding_evidence insert failed", e?.message || e);
        },
      );

    // replay row (best-effort)
    if (input.request) {
      await supa
        .from("request_replays")
        .insert({
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
          response: input.response
            ? {
                status: input.response.status,
                headers: input.response.headers ?? {},
                body: clip(input.response.body, 16384),
              }
            : null,
          diff: responseDiff,
          is_interesting: true,
        })
        .then(
          () => {},
          () => {},
        ); // ignore schema diffs
    }

    // OWASP coverage insert (best-effort). The table intentionally has no
    // uniqueness constraint, so insert a run breadcrumb instead of an upsert.
    const cat = OWASP_MAP[input.category ?? input.source] ?? OWASP_MAP[input.source] ?? "A03_injection";
    await supa
      .from("owasp_coverage")
      .insert({
        target_id: input.targetId,
        owasp_category: cat,
        checks_run: 1,
        payloads_sent: input.payload ? 1 : 0,
        findings_count: 1,
        waf_blocked: 0,
        metadata: { source: input.source, finding_type: input.category ?? input.source },
      })
      .then(
        () => {},
        () => {},
      );

    // scan log breadcrumb
    if (input.scanLogId) {
      await supa
        .from("scan_logs")
        .insert({
          target_id: input.targetId,
          task_id: input.scanLogId,
          log_type: "result",
          message: `[finding] ${input.source} ${input.severity} ${input.title}`,
          metadata: { finding_id: inserted.id, source: input.source },
        })
        .then(
          () => {},
          () => {},
        );
    }

    // Mark OWASP checklist row (best-effort, mapped by vuln_class/source).
    try {
      const checkKey = (input.vulnClass || input.category || input.source || "").toLowerCase();
      // Lightweight map → check_name; if no match, skip (arbiter still counts category coverage).
      // Broadened so every seeded checklist row has ≥1 detector that ticks it.
      const CHECK_MAP: Record<string, [string, string]> = {
        // A01
        idor: ["A01_broken_access_control", "idor_numeric_id"],
        idor_uuid: ["A01_broken_access_control", "idor_uuid"],
        bac: ["A01_broken_access_control", "horizontal_priv_escalation"],
        privilege_escalation: ["A01_broken_access_control", "vertical_priv_escalation"],
        forced_browsing: ["A01_broken_access_control", "forced_browsing"],
        path_traversal: ["A01_broken_access_control", "path_traversal"],
        lfi: ["A01_broken_access_control", "path_traversal"],
        method_override: ["A01_broken_access_control", "method_override"],
        cors: ["A01_broken_access_control", "cors_wildcard_creds"],
        // A02
        "secret-exposure": ["A02_crypto_failures", "exposed_secrets_in_js"],
        "recon-secret": ["A02_crypto_failures", "exposed_secrets_in_js"],
        exposed_secret: ["A02_crypto_failures", "exposed_secrets_in_js"],
        env_exposure: ["A02_crypto_failures", "env_file_exposure"],
        git_exposure: ["A02_crypto_failures", "git_exposure"],
        backup_file: ["A02_crypto_failures", "backup_files"],
        weak_tls: ["A02_crypto_failures", "tls_version"],
        weak_cipher: ["A02_crypto_failures", "weak_ciphers"],
        hsts: ["A02_crypto_failures", "hsts_missing"],
        api_key: ["A02_crypto_failures", "api_keys_in_html"],
        // A03
        xss: ["A03_injection", "reflected_xss"],
        stored_xss: ["A03_injection", "stored_xss"],
        dom_xss: ["A03_injection", "dom_xss"],
        sqli: ["A03_injection", "sqli_error_based"],
        sqli_blind: ["A03_injection", "sqli_boolean_blind"],
        sqli_time: ["A03_injection", "sqli_time_based"],
        nosql: ["A03_injection", "nosql_injection"],
        ssti: ["A03_injection", "ssti"],
        rce: ["A03_injection", "command_injection"],
        command_injection: ["A03_injection", "command_injection"],
        ldap: ["A03_injection", "ldap_injection"],
        xxe: ["A03_injection", "xxe"],
        header_injection: ["A03_injection", "header_injection"],
        crlf: ["A03_injection", "crlf_injection"],
        graphql: ["A03_injection", "graphql_injection"],
        template_injection: ["A03_injection", "template_injection"],
        // A04
        business_logic: ["A04_insecure_design", "business_logic_bypass"],
        race: ["A04_insecure_design", "race_conditions"],
        workflow: ["A04_insecure_design", "workflow_skip"],
        price: ["A04_insecure_design", "price_manipulation"],
        // A05
        default_creds: ["A05_misconfig", "default_credentials"],
        directory_listing: ["A05_misconfig", "directory_listing"],
        verbose_error: ["A05_misconfig", "verbose_errors"],
        security_headers: ["A05_misconfig", "security_headers_missing"],
        cors_misconfig: ["A05_misconfig", "cors_misconfig"],
        redirect: ["A05_misconfig", "cors_misconfig"],
        admin_panel: ["A05_misconfig", "admin_panel_exposed"],
        debug_endpoint: ["A05_misconfig", "debug_endpoints"],
        risky_method: ["A05_misconfig", "risky_http_methods"],
        clickjacking: ["A05_misconfig", "clickjacking_xfo"],
        csp: ["A05_misconfig", "csp_missing"],
        samesite: ["A05_misconfig", "samesite_cookie"],
        // A06
        outdated_tech: ["A06_vuln_components", "outdated_tech"],
        cve: ["A06_vuln_components", "known_cve_match"],
        jquery: ["A06_vuln_components", "jquery_outdated"],
        wp_plugin: ["A06_vuln_components", "wordpress_plugins"],
        nvd: ["A06_vuln_components", "nvd_recent_cve"],
        // A07
        jwt_none: ["A07_auth_failures", "jwt_none_alg"],
        jwt: ["A07_auth_failures", "jwt_weak_secret"],
        jwt_confusion: ["A07_auth_failures", "jwt_algorithm_confusion"],
        oauth: ["A07_auth_failures", "oauth_redirect"],
        session_fixation: ["A07_auth_failures", "session_fixation"],
        password_policy: ["A07_auth_failures", "password_policy"],
        mfa_bypass: ["A07_auth_failures", "no_mfa_bypass"],
        account_enum: ["A07_auth_failures", "account_enumeration"],
        credential_stuffing: ["A07_auth_failures", "credential_stuffing_gate"],
        // A08
        "prototype-pollution": ["A08_software_integrity", "prototype_pollution"],
        prototype_pollution: ["A08_software_integrity", "prototype_pollution"],
        dep_confusion: ["A08_software_integrity", "dependency_confusion"],
        sri: ["A08_software_integrity", "sri_missing"],
        deserialization: ["A08_software_integrity", "insecure_deserialization"],
        cache: ["A08_software_integrity", "cache_deception"],
        smuggling: ["A08_software_integrity", "http_smuggling"],
        // A09 Logging
        log_injection: ["A09_logging_failures", "log_injection"],
        // A10 SSRF
        ssrf: ["A10_ssrf", "ssrf_basic"],
      };
      for (const k of Object.keys(CHECK_MAP)) {
        if (checkKey.includes(k)) {
          const [cat2, cname] = CHECK_MAP[k];
          await supa
            .from("owasp_checklist")
            .upsert(
              {
                target_id: input.targetId,
                category: cat2,
                check_name: cname,
                status: "evidence",
                last_run_at: new Date().toISOString(),
              },
              { onConflict: "target_id,category,check_name" },
            )
            .then(
              () => {},
              () => {},
            );
          break;
        }
      }
    } catch {
      /* ignore */
    }

    // Auto-enqueue exploit-engine job — broader trigger.
    let exploitJobId: string | undefined;
    const cls = (input.vulnClass || input.category || input.source || "").toLowerCase();
    const HIGH_VALUE_CLASSES = [
      "xss",
      "sqli",
      "ssrf",
      "ssti",
      "rce",
      "lfi",
      "idor",
      "xxe",
      "redirect",
      "command_injection",
      "ldap_injection",
      "jwt",
      "oauth",
    ];
    const isHighValue = HIGH_VALUE_CLASSES.some((k) => cls.includes(k));
    const shouldQueue =
      input.autoEnqueueExploit ||
      ["high", "critical"].includes(input.severity) ||
      ["indicator", "suspected", "reflected", "exploited"].includes(input.proofTier || "") ||
      isHighValue;
    if (shouldQueue) {
      try {
        const { data: job } = await supa
          .from("scan_jobs")
          .insert({
            target_id: input.targetId,
            job_type: "exploit",
            priority: input.severity === "critical" ? 9 : input.severity === "high" ? 8 : isHighValue ? 7 : 5,
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
          })
          .select("id")
          .single();
        exploitJobId = job?.id;
        if (exploitJobId) {
          await supa
            .from("scan_logs")
            .insert({
              target_id: input.targetId,
              log_type: "action",
              message: `💀 Exploit Engine engaging — finding ${inserted.id} queued (${input.severity} ${input.source})`,
              metadata: {
                kind: "exploit_enqueued",
                finding_id: inserted.id,
                job_id: exploitJobId,
                run_id: input.runId,
              },
            })
            .then(
              () => {},
              () => {},
            );
        }
      } catch {
        /* best-effort */
      }
    }

    // Proof Engine — promotes proof_tier (signal → reflected → exploited) based on
    // OOB callbacks, sandbox execution evidence, and live probe reflection.
    // Fired ~25s after exploit-engine so OOB callbacks / sandbox runs have time to land.
    // Without this, findings never advance past "signal" and debate phases stay
    // permanently inconclusive (the proof-engine module existed but was never queued).
    if (shouldQueue) {
      try {
        await supa.from("scan_jobs").insert({
          target_id: input.targetId,
          job_type: "proof",
          priority: input.severity === "critical" ? 8 : 6,
          payload: { findingId: inserted.id },
          status: "queued",
          next_run_at: new Date(Date.now() + 25_000).toISOString(),
        });
      } catch {
        /* best-effort */
      }
    }

    // Triple Verify — independent statistical confirmation: baseline → mutated
    // → rebaseline (target drift check) → replay x2 (determinism check).
    // This module was fully built (rigorous exec-evidence detectors, timing
    // signals, open-redirect proof, confidence scoring 0-100) but had ZERO
    // callers anywhere in the codebase — no job route, no direct invocation.
    // It runs independently of proof-engine (which checks OOB/sandbox) since
    // this checks something different: whether the finding is reproducible
    // and whether the target's baseline was actually stable when we probed it.
    // Fires for every finding regardless of severity — false positives hide
    // in "medium" findings just as often as "critical" ones.
    try {
      await supa.from("scan_jobs").insert({
        target_id: input.targetId,
        job_type: "triple_verify",
        priority: input.severity === "critical" ? 8 : 5,
        payload: { findingId: inserted.id },
        status: "queued",
        next_run_at: new Date(Date.now() + 15_000).toISOString(),
      });
    } catch {
      /* best-effort */
    }

    return { ok: true, findingId: inserted.id, exploitJobId };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
}

// ───────────────────────── Heuristic surface ranker (gap 11) ─────────────────────────
// Fallback used when AI-driven surface analysis is unavailable (credits exhausted).
export interface RankedEndpoint {
  url: string;
  method: string;
  parameters?: Record<string, unknown>;
  score: number;
  reason: string;
}
export function heuristicRankSurface(
  eps: Array<{
    url: string;
    method?: string;
    parameters?: Record<string, unknown>;
    status_code?: number;
    response_length?: number;
  }>,
  limit = 30,
): RankedEndpoint[] {
  const scored: RankedEndpoint[] = [];
  for (const e of eps) {
    if (!e.url) continue;
    let score = 0;
    const reasons: string[] = [];
    const params = e.parameters || {};
    const paramCount = Object.keys(params).length;
    if (paramCount > 0) {
      score += 20 + Math.min(paramCount, 5) * 3;
      reasons.push(`${paramCount} params`);
    }
    if (e.status_code === 200) {
      score += 10;
    } else if (e.status_code === 302 || e.status_code === 301) {
      score += 7;
    } else if (e.status_code === 401 || e.status_code === 403) {
      score += 8;
      reasons.push("auth-gated");
    }
    if (/admin|api|login|upload|debug|graphql|console|actuator|swagger|internal/i.test(e.url)) {
      score += 15;
      reasons.push("juicy-path");
    }
    if (/\?.*(?:url|redirect|callback|next|target|file|path|id|user|cmd)=/i.test(e.url)) {
      score += 12;
      reasons.push("dangerous-param");
    }
    if ((e.method || "GET").toUpperCase() !== "GET") {
      score += 5;
      reasons.push(e.method!);
    }
    const rl = e.response_length || 0;
    if (rl > 5000) score += Math.min(8, Math.floor(rl / 5000));
    scored.push({
      url: e.url,
      method: (e.method || "GET").toUpperCase(),
      parameters: params,
      score,
      reason: reasons.join("+") || "baseline",
    });
  }
  scored.sort((a, b) => b.score - a.score);
  return scored.slice(0, limit);
}
