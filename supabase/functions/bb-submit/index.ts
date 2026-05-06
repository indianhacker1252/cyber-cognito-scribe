// Bug Bounty Submission — submits a validated finding to HackerOne / Bugcrowd
// via stored API tokens. If no token is configured for the platform, returns an
// "exported" Markdown bundle instead so the user can paste it into the platform.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

function db() {
  return createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
}

interface Body {
  findingId: string;
  platform: "hackerone" | "bugcrowd" | "export";
  programHandle?: string;
}

const SEVERITY_MAP: Record<string, string> = {
  critical: "critical", high: "high", medium: "medium", low: "low", info: "none",
};

function buildMarkdown(f: any, target: any): string {
  return `# ${f.title}

**Severity:** ${f.severity?.toUpperCase() || "MEDIUM"}  
**CVSS:** ${f.cvss_score ?? "N/A"}  
**Target:** ${target?.domain || target?.name || "n/a"}  
**Confidence:** ${f.confidence_score ?? 0}/100 (${f.confidence_level || "medium"})

## Summary
${f.description || "—"}

## Steps to Reproduce / Proof of Concept
\`\`\`
${f.poc || f.payload || "—"}
\`\`\`

## Impact
${f.triage_reasoning || "See description."}

## Remediation
${f.remediation || "Apply standard hardening for this vulnerability class."}

## Evidence
- Validation status: ${f.validation_status}
- AI verified: ${f.ai_verified ? "yes" : "no"}
- Reachability: ${f.reachability_status}

---
_Submitted via CyberScope_`;
}

async function submitH1(token: string, username: string, programHandle: string, f: any, target: any) {
  const body = {
    data: {
      type: "report",
      attributes: {
        team_handle: programHandle,
        title: f.title.slice(0, 250),
        vulnerability_information: buildMarkdown(f, target),
        severity_rating: SEVERITY_MAP[f.severity] || "medium",
        impact: f.triage_reasoning || f.description || "See report",
      },
    },
  };
  const r = await fetch("https://api.hackerone.com/v1/reports", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Accept": "application/json",
      "Authorization": "Basic " + btoa(`${username}:${token}`),
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(20000),
  });
  const data = await r.json().catch(() => ({}));
  return { ok: r.ok, status: r.status, data, remoteId: data?.data?.id };
}

async function submitBC(token: string, programHandle: string, f: any, target: any) {
  const body = {
    submission: {
      title: f.title.slice(0, 250),
      description: buildMarkdown(f, target),
      severity: SEVERITY_MAP[f.severity] === "none" ? "P5" :
                f.severity === "critical" ? "P1" :
                f.severity === "high" ? "P2" :
                f.severity === "medium" ? "P3" : "P4",
      vrt_id: "other",
      bug_url: target?.domain || "",
    },
  };
  const r = await fetch(`https://api.bugcrowd.com/submissions?program=${encodeURIComponent(programHandle)}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/vnd.bugcrowd.v4+json",
      "Accept": "application/vnd.bugcrowd.v4+json",
      "Authorization": `Token ${token}`,
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(20000),
  });
  const data = await r.json().catch(() => ({}));
  return { ok: r.ok, status: r.status, data, remoteId: data?.data?.id };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const auth = req.headers.get("Authorization") || "";
    const jwt = auth.replace(/^Bearer\s+/i, "");
    const supa = db();
    const { data: userData } = await supa.auth.getUser(jwt);
    const user = userData?.user;
    if (!user) {
      return new Response(JSON.stringify({ ok: false, error: "unauthorized" }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const body = await req.json() as Body;
    if (!body.findingId || !body.platform) {
      return new Response(JSON.stringify({ ok: false, error: "findingId and platform required" }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { data: f } = await supa.from("vulnerability_findings").select("*").eq("id", body.findingId).maybeSingle();
    if (!f) {
      return new Response(JSON.stringify({ ok: false, error: "finding not found" }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    // PROOF GATE — only "exploited" tier may be submitted to live platforms.
    if (body.platform !== "export" && (f as any).proof_tier !== "exploited") {
      return new Response(JSON.stringify({
        ok: false,
        error: "proof_gate_blocked",
        message: `This finding is at proof_tier="${(f as any).proof_tier || "signal"}". Run the Proof Engine and capture an OOB callback, sandbox-proven RCE, or data-exfil artifact before submitting to ${body.platform}. You can still export Markdown.`,
      }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const { data: target } = await supa.from("target_workspaces").select("*").eq("id", f.target_id).maybeSingle();
    const { data: tokens } = await supa.from("bug_bounty_tokens").select("*").eq("user_id", user.id).maybeSingle();

    let result: any = { ok: false };
    let status: "submitted" | "exported" | "failed" = "failed";
    let remoteId: string | undefined;

    const md = buildMarkdown(f, target);

    if (body.platform === "export") {
      status = "exported";
      result = { ok: true, markdown: md };
    } else if (body.platform === "hackerone") {
      const program = body.programHandle || tokens?.h1_program_handle;
      if (tokens?.h1_api_token && tokens?.h1_username && program) {
        try {
          const r = await submitH1(tokens.h1_api_token, tokens.h1_username, program, f, target);
          result = r; remoteId = r.remoteId;
          status = r.ok ? "submitted" : "failed";
        } catch (e) {
          result = { ok: false, error: e instanceof Error ? e.message : "submit failed" };
        }
      } else {
        status = "exported";
        result = { ok: true, markdown: md, exportReason: "no_token_or_program" };
      }
    } else if (body.platform === "bugcrowd") {
      const program = body.programHandle || tokens?.bc_program_handle;
      if (tokens?.bc_api_token && program) {
        try {
          const r = await submitBC(tokens.bc_api_token, program, f, target);
          result = r; remoteId = r.remoteId;
          status = r.ok ? "submitted" : "failed";
        } catch (e) {
          result = { ok: false, error: e instanceof Error ? e.message : "submit failed" };
        }
      } else {
        status = "exported";
        result = { ok: true, markdown: md, exportReason: "no_token_or_program" };
      }
    }

    await supa.from("bug_bounty_submissions").insert({
      user_id: user.id,
      finding_id: body.findingId,
      target_id: f.target_id,
      platform: body.platform,
      program_handle: body.programHandle || tokens?.h1_program_handle || tokens?.bc_program_handle,
      remote_id: remoteId,
      status,
      title: f.title,
      severity: f.severity,
      request_payload: { md_preview: md.slice(0, 500) },
      response_payload: result,
      error_message: result?.ok ? null : (result?.error || null),
    } as any);

    return new Response(JSON.stringify({ ok: true, status, remoteId, result }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: e instanceof Error ? e.message : "err" }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
