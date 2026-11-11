// Gap #10: Report-quality LLM rewrite.
// Polishes a finding's title/description into bug-bounty report quality:
// crisp summary, reproduction steps (curl), impact, remediation. Writes
// back to vulnerability_findings.{title,description,poc} only when the
// LLM returns valid structured output. Safe-no-op on AI errors.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

const LOVABLE_API = "https://ai.gateway.lovable.dev/v1/chat/completions";

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  const ok = (b: any, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { ...corsHeaders, "Content-Type": "application/json" } });

  try {
    const { targetId, findingId, limit = 10 } = await req.json().catch(() => ({}));
    const supa = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

    let q = supa.from("vulnerability_findings")
      .select("id,title,description,severity,affected_url,payload,evidence,proof_tier,source,response_raw")
      .in("proof_tier", ["exploited", "reflected"])
      .is("rewritten_at" as any, null as any)   // optional column; ignored if missing
      .limit(limit);
    if (findingId) q = supa.from("vulnerability_findings").select("*").eq("id", findingId).limit(1);
    else if (targetId) q = q.eq("target_id", targetId);

    const { data: findings } = await q;
    if (!findings || findings.length === 0) return ok({ ok: true, rewritten: 0, reason: "no candidates" });

    const apiKey = Deno.env.get("LOVABLE_API_KEY");
    if (!apiKey) return ok({ ok: false, error: "missing LOVABLE_API_KEY" });

    let rewritten = 0;
    for (const f of findings) {
      const prompt = `You are a senior bug-bounty triage engineer. Rewrite the finding below as a high-quality H1-style report.

Return STRICT JSON only with these keys:
{
  "title": "concise <80 chars",
  "summary": "1-2 sentence impact statement",
  "reproduction": "step-by-step incl. curl command",
  "impact": "what an attacker can do",
  "remediation": "specific fix"
}

Finding:
- Title: ${f.title}
- Severity: ${f.severity}
- URL: ${f.affected_url || "n/a"}
- Source: ${f.source}
- Proof tier: ${f.proof_tier}
- Payload: ${(f.payload || "").slice(0, 400)}
- Evidence: ${JSON.stringify(f.evidence || {}).slice(0, 800)}
- Raw response head: ${(f.response_raw || "").slice(0, 400)}`;

      try {
        const r = await fetch(LOVABLE_API, {
          method: "POST",
          headers: { "Content-Type": "application/json", "Authorization": `Bearer ${apiKey}` },
          body: JSON.stringify({
            model: "google/gemini-3.8-flash",
            messages: [{ role: "user", content: prompt }],
            temperature: 0.2,
          }),
          signal: AbortSignal.timeout(15000),
        });
        if (!r.ok) continue;
        const j = await r.json();
        const text = j?.choices?.[0]?.message?.content || "";
        const jsonMatch = text.match(/\{[\s\S]*\}/);
        if (!jsonMatch) continue;
        let parsed: any;
        try { parsed = JSON.parse(jsonMatch[0]); } catch { continue; }
        if (!parsed.title || !parsed.summary) continue;

        const newDesc = [
          `## Summary`, parsed.summary,
          ``, `## Reproduction`, parsed.reproduction,
          ``, `## Impact`, parsed.impact,
          ``, `## Remediation`, parsed.remediation,
        ].join("\n");

        await supa.from("vulnerability_findings").update({
          title: String(parsed.title).slice(0, 200),
          description: newDesc,
          poc: parsed.reproduction || f.payload,
        }).eq("id", f.id);
        rewritten++;
      } catch { /* skip */ }
    }

    if (targetId) {
      await supa.from("scan_logs").insert({
        target_id: targetId, log_type: "info",
        message: `📝 report-rewrite: polished ${rewritten}/${findings.length} findings`,
        metadata: { rewritten, total: findings.length },
      }).then(() => {}, () => {});
    }

    return ok({ ok: true, rewritten, examined: findings.length });
  } catch (e) {
    return ok({ ok: false, error: e instanceof Error ? e.message : "err" });
  }
});
