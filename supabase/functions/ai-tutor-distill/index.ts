// AI Tutor — Distillation
// Asks Gemini (Lovable AI) to write phase-by-phase VAPT playbooks and stores
// them as RAG corpus rows that the local Ollama queries during scans.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};
const db = () => createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

const PHASES = [
  { phase: "recon",        topic: "passive + active recon" },
  { phase: "fingerprint",  topic: "tech stack + WAF + auth model fingerprinting" },
  { phase: "auth",         topic: "auth attacks (BAC, IDOR, JWT, OAuth)" },
  { phase: "injection",    topic: "SQLi/NoSQLi/CMDi/SSTI/XXE detection + exploit" },
  { phase: "xss",          topic: "Reflected/Stored/DOM XSS proof + chain to ATO" },
  { phase: "ssrf",         topic: "SSRF discovery, blind OOB, cloud metadata exfil" },
  { phase: "logic",        topic: "business-logic flaws and race conditions" },
  { phase: "chain",        topic: "vuln chaining for full account takeover / RCE" },
  { phase: "report",       topic: "writing real-world PoCs that pass H1/BC triage" },
];

async function ask(model: string, system: string, user: string) {
  const r = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
    method: "POST",
    headers: { Authorization: `Bearer ${Deno.env.get("LOVABLE_API_KEY")}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      model,
      messages: [{ role: "system", content: system }, { role: "user", content: user }],
      temperature: 0.4,
    }),
    signal: AbortSignal.timeout(40000),
  });
  if (!r.ok) return null;
  const j = await r.json().catch(() => null);
  return j?.choices?.[0]?.message?.content as string | undefined;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const supa = db();
    const auth = req.headers.get("Authorization") || "";
    const { data: ud } = await supa.auth.getUser(auth.replace(/^Bearer\s+/i, ""));
    const isAdmin = ud?.user
      ? !!(await supa.from("user_roles").select("role").eq("user_id", ud.user.id).eq("role","admin").maybeSingle()).data
      : false;
    if (!isAdmin) {
      return new Response(JSON.stringify({ ok: false, error: "admin only" }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const body = await req.json().catch(() => ({}));
    const model = body.model || "google/gemini-2.5-flash";
    const sys = `You are a senior offensive-security tutor writing a VAPT playbook
for a junior model running locally. Output Markdown, dense and concrete.
For each phase include: goal, exact tools/commands, payload patterns,
common WAF bypasses, and the EXACT proof artifact required to be considered
"exploited" (not just "signal"). Bug bounty rejection-proof reasoning only.`;

    let inserted = 0;
    for (const p of PHASES) {
      const text = await ask(model, sys, `Write the VAPT playbook for the "${p.phase}" phase: ${p.topic}.`);
      if (!text) continue;
      await supa.from("rag_corpus").insert({
        topic: p.topic, vuln_class: null, phase: p.phase, content: text,
        source: "gemini-distill", tags: [p.phase, "playbook"],
      } as any);
      inserted++;
    }

    return new Response(JSON.stringify({ ok: true, inserted, phases: PHASES.length }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: e instanceof Error ? e.message : "err" }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
