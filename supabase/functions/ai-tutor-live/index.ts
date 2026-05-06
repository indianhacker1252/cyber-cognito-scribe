// AI Tutor — Live tutoring on hard cases.
// Body: { localOutput, prompt, vulnClass?, findingId?, targetId? }
// Calls Gemini, returns the corrected answer, logs delta to ai_tutoring_sessions,
// and (if delta is meaningful) appends the lesson to rag_corpus.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};
const db = () => createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const { localOutput = "", prompt = "", vulnClass, findingId, targetId } = await req.json();
    if (!prompt) {
      return new Response(JSON.stringify({ ok: false, error: "prompt required" }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const sys = `You are a senior pentester reviewing a junior model's reasoning.
1) Decide if the junior's answer is CORRECT, PARTIAL, or WRONG.
2) Provide the corrected, exploitation-grade answer with exact proof artifact.
3) Output as JSON: {"verdict":"...","correction":"...","lesson":"<=200 words generalisable rule>"}.`;

    const r = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${Deno.env.get("LOVABLE_API_KEY")}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash",
        messages: [
          { role: "system", content: sys },
          { role: "user", content: `PROMPT:\n${prompt}\n\nJUNIOR ANSWER:\n${localOutput}` },
        ],
        temperature: 0.2,
      }),
      signal: AbortSignal.timeout(30000),
    });
    if (!r.ok) {
      return new Response(JSON.stringify({ ok: false, error: `gemini ${r.status}` }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const j = await r.json();
    const raw = j?.choices?.[0]?.message?.content || "";
    let parsed: any = {}; try { parsed = JSON.parse(raw.match(/\{[\s\S]*\}/)?.[0] || "{}"); } catch {}
    const verdict = parsed.verdict || "PARTIAL";
    const correction = parsed.correction || raw;
    const lesson = parsed.lesson || "";
    const delta = verdict === "WRONG" ? 80 : verdict === "PARTIAL" ? 40 : 5;

    const supa = db();
    await supa.from("ai_tutoring_sessions").insert({
      target_id: targetId, finding_id: findingId,
      local_model_output: localOutput, gemini_correction: correction,
      delta_score: delta, saved_to_corpus: !!lesson && delta >= 40,
    } as any);

    if (lesson && delta >= 40) {
      await supa.from("rag_corpus").insert({
        topic: vulnClass || "live-lesson",
        vuln_class: vulnClass || null,
        phase: "live-tutoring",
        content: lesson, source: "gemini-tutor", tags: ["lesson", verdict.toLowerCase()],
      } as any);
    }

    return new Response(JSON.stringify({ ok: true, verdict, correction, lesson, delta }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: e instanceof Error ? e.message : "err" }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
