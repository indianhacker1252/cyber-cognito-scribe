import { streamText, generateText, stepCountIs } from "ai";
import { emit, heartbeat, updateSession, getTarget, getWorldModel, type Session } from "./db.js";
import { pickProvider } from "./llm.js";
import { buildTools, closeBrowser } from "./tools/index.js";
import { closeOracleBrowser } from "./oracles.js";

const SYSTEM_PROMPT = `You are CyberScope Operator, an autonomous VAPT agent modeled on XBOW.

METHODOLOGY:
1. Recon — map the attack surface (subfinder → httpx → katana). Persist every URL with endpoints.upsert.
2. Hypothesize — read prior notes.search + endpoints.list before choosing the next class to test.
3. Probe — use http.request/browser.visit with an explicit \`as\` auth context.
4. Verify — never record without concrete proof (SQLi timing/error, XSS DOM alert, SSRF OOB, IDOR cross-context read, redirect to attacker host). The runtime re-runs a deterministic oracle and REJECTS unproven findings.
5. Chain — for multi-step exploits (auth → CSRF token → privileged action, or IDOR sequences) use chain.run: it shares a cookie jar across steps, captures values with regex/header/set_cookie, and interpolates \${var} into later steps.
6. Auth roles — before IDOR/BAC testing, create at least two contexts via auth.login_form or auth.set_bearer (e.g. "userA" and "userB"), then probe the same resource under each with \`as\`.
7. Persist — memory.write for beliefs; notes.write for durable hypotheses / dead-ends; endpoints.upsert for every URL touched.
8. Move on — if 3 probes on the same class fail, switch class and note the dead-end.

RULES:
- One tool call per step; wait for the observation before deciding next.
- Never guess payloads blindly — reason from tech stack, endpoint catalog, and prior notes.
- Never call findings.record without evidence in the result of a previous tool call.
- Ignore self-redirects (301/302 to same host+path with query stripped) — that is the redirect trap, not a vuln.
- When budget < 20 credits or 300 seconds remain, wrap up and call finish.
`;

export async function runSession(session: Session) {
  const target = await getTarget(session.target_id);
  if (!target) {
    await updateSession(session.id, { status: "failed", error_message: "target not found", completed_at: new Date().toISOString() });
    return;
  }

  const worldModel = await getWorldModel(session.target_id);
  const goal = session.goal ?? `Perform a full VAPT scan of ${target.domain || target.url || target.name}. Find and prove real vulnerabilities across OWASP A01-A10.`;

  const model = pickProvider(session.provider, session.model);

  // --- P1 PLANNER: produce ranked sub-goals before executor starts ---
  let planText = "";
  try {
    const pr = await generateText({
      model,
      system: "You are the PLANNER for a VAPT agent. Output a numbered list (max 8) of concrete, testable sub-goals ranked by ROI, each with a one-line success criterion. No prose before/after.",
      prompt: `TARGET: ${JSON.stringify({ domain: target.domain, url: target.url, tech: target.tech_stack ?? target.detected_tech ?? null })}\nWORLD MODEL: ${JSON.stringify(worldModel).slice(0, 2000)}\nGOAL: ${goal}`,
    });
    planText = pr.text;
  } catch (e: any) {
    planText = `(planner failed: ${String(e?.message ?? e)}) — executor will improvise from goal.`;
  }
  await emit(session.id, session.target_id, "plan", {
    msg: "session started",
    goal,
    target: { id: target.id, domain: target.domain, url: target.url },
    world_model: worldModel,
    sub_goals: planText,
  });

  const tools = buildTools({ sessionId: session.id, targetId: session.target_id });

  const startTs = Date.now();
  let stepCount = 0;
  const hb = setInterval(() => heartbeat(session.id).catch(() => {}), 15000);

  try {
    const result = streamText({
      model,
      system: SYSTEM_PROMPT,
      messages: [{
        role: "user",
        content:
`GOAL:
${goal}

PLAN (ranked sub-goals — attack in this order, tick each off before moving on):
${planText}

TARGET:
${JSON.stringify({ domain: target.domain, url: target.url, tech: target.tech_stack ?? target.detected_tech ?? null }, null, 2)}

WORLD MODEL (prior beliefs):
${JSON.stringify(worldModel).slice(0, 4000)}

BUDGET: ${session.budget_credits} credits, ${session.budget_seconds}s.

For each sub-goal: hypothesize → probe → verify with an oracle. Use ONE tool per turn. Persist beliefs with memory.write. Only call findings.record after concrete proof — the runtime WILL re-verify with a deterministic oracle and reject unproven findings.`,
      }],
      tools,
      stopWhen: stepCountIs(200),
      onStepFinish: async ({ toolCalls, toolResults, text }) => {
        stepCount += 1;
        if (text) await emit(session.id, session.target_id, "thought", { text }, stepCount);
        for (const tc of toolCalls ?? []) {
          await emit(session.id, session.target_id, "act", { tool: tc.toolName, args: tc.args }, stepCount);
        }
        for (const tr of toolResults ?? []) {
          const r = (tr as any).result ?? (tr as any).output ?? {};
          const summary = JSON.stringify(r).slice(0, 2000);
          await emit(session.id, session.target_id, "observe", { tool: (tr as any).toolName, summary }, stepCount);
        }
        await updateSession(session.id, { steps_taken: stepCount });

        // Budget check
        const secs = (Date.now() - startTs) / 1000;
        if (secs > session.budget_seconds) {
          await emit(session.id, session.target_id, "decision", { msg: "budget_time_exhausted, ending" }, stepCount);
          throw new Error("budget_time_exhausted");
        }
      },
    });

    // Drain the stream
    for await (const _chunk of result.textStream) { /* drain */ }
    const finalText = await result.text;

    // --- P1 CRITIC: post-session review over plan vs findings ---
    try {
      const { data: findings } = await (await import("./db.js")).db
        .from("vulnerability_findings")
        .select("vuln_class,severity,proof_tier,affected_url")
        .eq("target_id", session.target_id)
        .order("created_at", { ascending: false })
        .limit(30);
      const cr = await generateText({
        model,
        system: "You are the CRITIC. Compare the plan's sub-goals against confirmed findings. For each sub-goal: state COVERED / PARTIAL / MISSED with one-line justification. End with 2 concrete next-session recommendations. Terse.",
        prompt: `PLAN:\n${planText}\n\nFINDINGS (recent):\n${JSON.stringify(findings ?? [], null, 2)}\n\nAGENT FINAL SUMMARY:\n${finalText.slice(0, 1500)}`,
      });
      await emit(session.id, session.target_id, "critique", { stage: "post_session", review: cr.text }, stepCount);
    } catch (e: any) {
      await emit(session.id, session.target_id, "critique", { stage: "post_session", error: String(e?.message ?? e) }, stepCount);
    }

    await emit(session.id, session.target_id, "decision", { msg: "session complete", final: finalText.slice(0, 2000) }, stepCount);
    await updateSession(session.id, { status: "completed", completed_at: new Date().toISOString(), steps_taken: stepCount });
  } catch (err: any) {
    const msg = String(err?.message ?? err);
    await emit(session.id, session.target_id, "error", { msg }, stepCount);
    await updateSession(session.id, {
      status: msg === "budget_time_exhausted" ? "completed" : "failed",
      error_message: msg,
      completed_at: new Date().toISOString(),
      steps_taken: stepCount,
    });
  } finally {
    clearInterval(hb);
  }
}

export { closeBrowser, closeOracleBrowser };
