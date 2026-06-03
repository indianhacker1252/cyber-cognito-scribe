// Chain Finder — invoked after a finding reaches `exploited` tier.
// Asks the LLM: given this confirmed primitive on the target, what is the
// most likely NEXT step in the kill-chain? (e.g. IDOR → leak admin token
// → privilege escalation → RCE). The proposed next step is stored, and a
// fresh exploit-engine run is queued to attack the next step automatically.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};
const db = () => createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

async function log(supa: any, target_id: string | null, t: string, m: string, meta: any = {}) {
  try { await supa.from("scan_logs").insert({ target_id, log_type: t, message: m, metadata: meta }); } catch { /* ignore */ }
}

interface NextStep {
  next_vuln_class: string;
  next_target_url: string;
  next_payload_hint: string;
  primitive_used: string;
  rationale: string;
  expected_evidence: string;
}

async function proposeNextStep(seedFinding: any, neighbours: any[], endpoints: any[]): Promise<NextStep | null> {
  const key = Deno.env.get("LOVABLE_API_KEY");
  if (!key) return null;
  const sys = `You are XBOW — an autonomous offensive AI that links primitives into kill-chains.
Given ONE just-proven finding plus context (neighbouring findings + discovered endpoints), propose the SINGLE most valuable next step that escalates impact.
Output STRICT JSON ONLY (no prose, no markdown):
{
  "next_vuln_class": "e.g. privilege_escalation | rce | account_takeover | sensitive_data_exfil | ssrf_to_metadata | jwt_forgery",
  "next_target_url": "concrete URL to attack next (must exist in endpoints OR be a plausible admin/internal route)",
  "next_payload_hint": "1-line payload or technique to try first",
  "primitive_used": "the primitive you are reusing from the proven finding (e.g. valid session cookie, leaked admin id, SQLi read)",
  "rationale": "1-2 sentences on why this is the next logical step",
  "expected_evidence": "what proof would confirm this next step"
}
Rules:
- READ-ONLY only; never propose DROP/DELETE/INSERT/UPDATE.
- Prefer steps that compound: stolen-cookie → /admin, leaked-id → IDOR on /users/<id>, SQLi-read → dump auth_table.
- If no meaningful escalation exists, return {"next_vuln_class": "none", "next_target_url": "", "next_payload_hint": "", "primitive_used": "", "rationale": "dead-end", "expected_evidence": ""}.`;

  const user = `PROVEN FINDING:
title=${seedFinding.title}
severity=${seedFinding.severity}
vuln_class=${(seedFinding.hard_evidence as any)?.templateId || (seedFinding.hard_evidence as any)?.vuln_class || "unknown"}
affected_url=${seedFinding.affected_url}
poc=${(seedFinding.poc || "").slice(0, 400)}
hard_evidence (first 1200b)=${JSON.stringify(seedFinding.hard_evidence || {}).slice(0, 1200)}

NEIGHBOURING FINDINGS (max 5):
${neighbours.slice(0, 5).map((n) => `- ${n.severity}/${n.title} @ ${n.affected_url}`).join("\n") || "(none)"}

KNOWN ENDPOINTS ON THIS TARGET (max 12):
${endpoints.slice(0, 12).map((e) => `- ${e.method} ${e.url}`).join("\n") || "(none)"}

Propose the next step.`;

  try {
    const r = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": `Bearer ${key}` },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash",
        messages: [{ role: "system", content: sys }, { role: "user", content: user }],
        max_tokens: 600,
      }),
      signal: AbortSignal.timeout(25000),
    });
    if (!r.ok) return null;
    const j = await r.json();
    const txt = j.choices?.[0]?.message?.content || "";
    const m = txt.match(/\{[\s\S]*\}/);
    if (!m) return null;
    const obj = JSON.parse(m[0]);
    if (!obj?.next_vuln_class) return null;
    return obj as NextStep;
  } catch { return null; }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  const respond = (b: any, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { ...corsHeaders, "Content-Type": "application/json" } });

  try {
    const supa = db();
    const auth = req.headers.get("Authorization") || "";
    const token = auth.replace(/^Bearer\s+/i, "");
    const isServiceRole = token && token === Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    const { data: ud } = await supa.auth.getUser(token);
    if (!isServiceRole && !ud?.user?.id) return respond({ ok: false, error: "unauthorized" }, 401);

    const { seedFindingId, autoQueue = true } = await req.json();
    if (!seedFindingId) return respond({ ok: false, error: "seedFindingId required" });

    const { data: f } = await supa.from("vulnerability_findings").select("*").eq("id", seedFindingId).maybeSingle();
    if (!f) return respond({ ok: false, error: "finding not found" });
    if (f.proof_tier !== "exploited") {
      return respond({ ok: false, error: "seed finding must be proof_tier=exploited", tier: f.proof_tier });
    }

    await log(supa, f.target_id, "thought", `🔗 Chain-Finder analysing "${f.title}" for next kill-chain step`);

    const [neighRes, epRes] = await Promise.all([
      supa.from("vulnerability_findings")
        .select("title,severity,affected_url,hard_evidence")
        .eq("target_id", f.target_id).neq("id", seedFindingId)
        .order("created_at", { ascending: false }).limit(15),
      supa.from("discovered_endpoints")
        .select("url,method").eq("target_id", f.target_id).limit(40),
    ]);

    const step = await proposeNextStep(f, neighRes.data || [], epRes.data || []);
    if (!step || step.next_vuln_class === "none") {
      const { data: row } = await supa.from("chain_finder_runs").insert({
        target_id: f.target_id, seed_finding_id: seedFindingId,
        primitive: (f.hard_evidence as any)?.templateId || null,
        proposed_next_step: {}, reasoning: step?.rationale || "no_escalation_found", status: "dead_end",
      } as any).select().single();
      await log(supa, f.target_id, "info", `🪦 Chain-Finder: no escalation path from "${f.title}"`);
      return respond({ ok: true, deadEnd: true, runId: row?.id });
    }

    // Persist proposal
    const { data: chainRow } = await supa.from("chain_finder_runs").insert({
      target_id: f.target_id,
      seed_finding_id: seedFindingId,
      primitive: step.primitive_used,
      proposed_next_step: step,
      reasoning: step.rationale,
      status: "proposed",
    } as any).select().single();

    await log(supa, f.target_id, "action",
      `🎯 Chain step proposed → ${step.next_vuln_class} @ ${step.next_target_url} (primitive: ${step.primitive_used})`,
      { rationale: step.rationale });

    // Also record into exploit_chains so the UI can show kill-chain narratives
    try {
      await supa.from("exploit_chains").insert({
        target_id: f.target_id,
        chain_name: `${(f.hard_evidence as any)?.templateId || f.title} → ${step.next_vuln_class}`,
        chain_steps: [
          { kind: "proven", finding_id: seedFindingId, title: f.title, vuln_class: (f.hard_evidence as any)?.templateId },
          { kind: "proposed", vuln_class: step.next_vuln_class, target_url: step.next_target_url, payload_hint: step.next_payload_hint, primitive_used: step.primitive_used },
        ],
        severity: f.severity,
        status: "queued",
      } as any);
    } catch { /* ignore */ }

    let queuedRunId: string | null = null;
    if (autoQueue) {
      // Insert a synthetic seed finding for the next step so the exploit-engine
      // has something to attack — proof_tier=signal so it is eligible.
      try {
        const { data: nextFinding } = await supa.from("vulnerability_findings").insert({
          target_id: f.target_id,
          title: `[Chain] ${step.next_vuln_class} via ${step.primitive_used}`,
          description: `Auto-queued by chain-finder from "${f.title}". ${step.rationale}`,
          severity: f.severity === "critical" ? "critical" : "high",
          proof_tier: "signal",
          validation_status: "chain_proposed",
          affected_url: step.next_target_url,
          poc: step.next_payload_hint,
          payload: step.next_payload_hint,
          hard_evidence: {
            chain_seed_finding_id: seedFindingId,
            chain_run_id: chainRow?.id,
            primitive_inherited: step.primitive_used,
            expected_evidence: step.expected_evidence,
            vuln_class: step.next_vuln_class,
            templateId: step.next_vuln_class,
          },
          sensitive: true,
        } as any).select().single();

        if (nextFinding?.id) {
          // Fire-and-forget exploit-engine run on the new step
          fetch(`${Deno.env.get("SUPABASE_URL")}/functions/v1/exploit-engine`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Authorization": `Bearer ${Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")}`,
            },
            body: JSON.stringify({ findingId: nextFinding.id }),
            signal: AbortSignal.timeout(2000),
          }).catch(() => { /* fire-and-forget */ });
          queuedRunId = nextFinding.id;
          await supa.from("chain_finder_runs").update({
            queued_exploit_run_id: nextFinding.id, status: "queued",
          } as any).eq("id", chainRow!.id);
          await log(supa, f.target_id, "action", `🚀 Chain step auto-queued → exploit-engine attacking ${step.next_target_url}`);
        }
      } catch (e) {
        await log(supa, f.target_id, "warning", `Chain auto-queue failed: ${e instanceof Error ? e.message : "err"}`);
      }
    }

    return respond({ ok: true, runId: chainRow?.id, step, queuedRunId });
  } catch (e) {
    return respond({ ok: false, error: e instanceof Error ? e.message : "err" });
  }
});
