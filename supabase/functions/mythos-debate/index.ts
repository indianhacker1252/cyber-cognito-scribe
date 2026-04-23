// Two black-hat agents debate a parameter, agree on a payload, test it,
// then debate whether the result is a real bug or a false positive.
// Agent A = Recon Analyst (sees param, hypothesizes vuln class)
// Agent B = Exploit Strategist (proposes payload, refines based on response)
// Both learn from outcomes and self-correlate.
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");

async function callAgent(role: "A" | "B", systemPrompt: string, userMsg: string, history: any[]): Promise<string> {
  if (!LOVABLE_API_KEY) return `[${role}] (no LLM key) — heuristic mode`;
  try {
    const r = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${LOVABLE_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash",
        messages: [
          { role: "system", content: systemPrompt },
          ...history,
          { role: "user", content: userMsg },
        ],
        max_tokens: 400,
      }),
      signal: AbortSignal.timeout(15000),
    });
    if (!r.ok) return `[${role}] LLM error ${r.status}`;
    const d = await r.json();
    return d.choices?.[0]?.message?.content?.trim() || `[${role}] (empty)`;
  } catch (e) {
    return `[${role}] error: ${e instanceof Error ? e.message : "unknown"}`;
  }
}

async function probe(url: string, paramName: string, payload: string): Promise<{ status: number; bodyLen: number; bodySnippet: string; reflected: boolean; errorSig: boolean }> {
  try {
    const u = new URL(url);
    u.searchParams.set(paramName, payload);
    const r = await fetch(u.toString(), { signal: AbortSignal.timeout(8000) });
    const body = await r.text();
    return {
      status: r.status,
      bodyLen: body.length,
      bodySnippet: body.slice(0, 400),
      reflected: body.includes(payload),
      errorSig: /SQL syntax|mysql_|pg_query|SQLSTATE|ORA-|stack trace|TypeError|undefined method|fatal error/i.test(body),
    };
  } catch {
    return { status: 0, bodyLen: 0, bodySnippet: "", reflected: false, errorSig: false };
  }
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
  try {
    const { targetId, runId, endpointUrl, paramName, paramValue, vulnClassHint } = await req.json();
    if (!targetId || !endpointUrl || !paramName) throw new Error("targetId, endpointUrl, paramName required");

    const db = createClient(SUPABASE_URL, SERVICE_KEY);
    const transcript: any[] = [];
    const history: any[] = [];

    const sysA = `You are Agent A — black-hat recon analyst. You analyze HTTP parameters and hypothesize what vulnerability classes (SQLi, XSS, SSRF, IDOR, RCE, SSTI, LFI, etc) might apply. Be SPECIFIC, terse (≤80 words). Talk to Agent B as a teammate.`;
    const sysB = `You are Agent B — black-hat exploit strategist. You propose CONCRETE payloads given a hypothesis. Be SPECIFIC (raw payload), terse (≤80 words). Talk to Agent A as a teammate.`;

    // Round 1: A analyzes the param
    const a1 = await callAgent("A", sysA, `Param: ${paramName}=${paramValue}\nURL: ${endpointUrl}\nHint: ${vulnClassHint || "none"}\n\nWhat vuln class fits best? Why?`, []);
    transcript.push({ agent: "A", round: 1, msg: a1 });
    history.push({ role: "user", content: `Agent A says: ${a1}` });

    // Round 2: B proposes payload
    const b1 = await callAgent("B", sysB, `Agent A analysis: ${a1}\n\nPropose ONE concrete payload to test. Output ONLY the raw payload on the first line, then 1-line rationale.`, []);
    transcript.push({ agent: "B", round: 2, msg: b1 });
    const proposedPayload = b1.split("\n")[0].trim().replace(/^[`"']|[`"']$/g, "");

    // Execute the agreed payload
    const probe1 = await probe(endpointUrl, paramName, proposedPayload);
    transcript.push({ agent: "system", round: 3, msg: `EXECUTED: status=${probe1.status} len=${probe1.bodyLen} reflected=${probe1.reflected} errSig=${probe1.errorSig}` });

    // Round 4: A debates if this is a real bug or FP
    const a2 = await callAgent("A", sysA, `Result of payload "${proposedPayload}": status=${probe1.status}, length=${probe1.bodyLen}, reflected=${probe1.reflected}, error_signature=${probe1.errorSig}.\nBody snippet: ${probe1.bodySnippet.slice(0, 200)}\n\nIs this a TRUE bug or FALSE POSITIVE? Be skeptical. State verdict + 1-line reason.`, history);
    transcript.push({ agent: "A", round: 4, msg: a2 });

    // Round 5: B challenges A
    const b2 = await callAgent("B", sysB, `Agent A's verdict: ${a2}\n\nDo you AGREE or DISAGREE? If FP, explain why. If real bug, what would be the next escalation step? ≤60 words.`, history);
    transcript.push({ agent: "B", round: 5, msg: b2 });

    // Final FP verdict (heuristic + agent consensus)
    const aSaysFP = /false positive|not a bug|FP|not vulnerable|no vuln/i.test(a2);
    const bSaysFP = /false positive|not a bug|FP|agree.*FP|agree.*false/i.test(b2);
    const bothAgreeFP = aSaysFP && bSaysFP;
    const strongSignal = probe1.errorSig || (probe1.reflected && /<|script|onerror|alert/i.test(proposedPayload));

    let fpVerdict: "true_positive" | "false_positive" | "inconclusive";
    let confidence: number;
    if (bothAgreeFP && !strongSignal) {
      fpVerdict = "false_positive";
      confidence = 85;
    } else if (strongSignal && !bothAgreeFP) {
      fpVerdict = "true_positive";
      confidence = 80;
    } else if (probe1.status === 0) {
      fpVerdict = "inconclusive";
      confidence = 30;
    } else {
      fpVerdict = aSaysFP || bSaysFP ? "inconclusive" : "true_positive";
      confidence = 55;
    }

    // Self-correlation learnings
    const learnA = `Param ${paramName}: my hypothesis was "${a1.slice(0, 80)}…". Verdict: ${fpVerdict} (conf ${confidence}). Adjusting prior weight for this vuln class on similar params.`;
    const learnB = `Payload "${proposedPayload.slice(0, 60)}" → ${fpVerdict}. ${strongSignal ? "Strong signal — promote this payload pattern." : "Weak signal — deprioritize blind variants of this template."}`;

    const { data: debateRow } = await db.from("mythos_debates").insert({
      target_id: targetId,
      run_id: runId ?? null,
      endpoint_url: endpointUrl,
      param_name: paramName,
      param_value: paramValue ?? null,
      vuln_class: vulnClassHint ?? null,
      transcript,
      agreed_payload: proposedPayload,
      agreed_rationale: b1,
      test_result: probe1,
      fp_verdict: fpVerdict,
      fp_reasoning: `${a2}\n---\n${b2}`,
      confidence_score: confidence,
      agent_a_learning: learnA,
      agent_b_learning: learnB,
    }).select().single();

    // Stream phase logs
    await db.from("scan_logs").insert([
      { target_id: targetId, log_type: "thought", message: `🥷 Agent A: ${a1.slice(0, 120)}`, metadata: { run_id: runId, debate_id: debateRow?.id, phase: "debate-a1" } },
      { target_id: targetId, log_type: "thought", message: `🥷 Agent B: ${b1.slice(0, 120)}`, metadata: { run_id: runId, debate_id: debateRow?.id, phase: "debate-b1" } },
      { target_id: targetId, log_type: "action", message: `⚔️ Executed: ${proposedPayload.slice(0, 80)} → ${probe1.status} (${probe1.bodyLen}b)`, metadata: { run_id: runId, debate_id: debateRow?.id, phase: "debate-exec" } },
      { target_id: targetId, log_type: fpVerdict === "true_positive" ? "result" : "info", message: `🧐 Verdict: ${fpVerdict} (${confidence}% conf)`, metadata: { run_id: runId, debate_id: debateRow?.id, phase: "debate-verdict" } },
    ]);

    // If true positive, persist as a low-confidence finding for triage
    if (fpVerdict === "true_positive" && debateRow?.id) {
      await db.from("vulnerability_findings").insert({
        target_id: targetId,
        title: `[Debate] ${vulnClassHint || "potential"} via ${paramName}`,
        severity: "medium",
        description: `Two agents debated and agreed: ${a2}`,
        payload: proposedPayload,
        confidence_score: confidence,
        confidence_level: confidence >= 70 ? "high" : "medium",
        triage_reasoning: `Agent A: ${a1}\nAgent B: ${b1}\nResult: ${JSON.stringify(probe1)}\nDebate: ${a2} | ${b2}`,
        validation_status: "debate_confirmed",
      });
    }

    return new Response(JSON.stringify({
      debateId: debateRow?.id,
      fpVerdict,
      confidence,
      agreedPayload: proposedPayload,
      transcript,
    }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (e) {
    console.error("mythos-debate error:", e);
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : String(e) }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
