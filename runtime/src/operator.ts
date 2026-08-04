import { streamText, generateText, stepCountIs } from "ai";
import { emit, heartbeat, updateSession, getTarget, getWorldModel, type Session } from "./db.js";
import { pickProvider } from "./llm.js";
import { buildTools, closeBrowser } from "./tools/index.js";
import { closeOracleBrowser } from "./oracles.js";

const SYSTEM_PROMPT = `You are CyberScope Operator, an autonomous VAPT agent modeled on XBOW.

METHODOLOGY:
1. Recon — map the attack surface (subdomains, endpoints, forms, tech stack, auth model).
2. Hypothesize — from the world model, pick the highest-value bug class to test next.
3. Probe — use http.request or browser.visit to test ONE hypothesis at a time.
4. Verify — never record a finding without concrete proof:
   - SQLi: error string or measurable time delta on baseline
   - XSS: alert() executed in browser.exec_js OR script tag in reflected HTML
   - SSRF: OOB callback OR 500 + response-length delta > 200 bytes
   - IDOR: same resource accessible under a different auth token
   - Redirect: Location header points to attacker-controlled host
5. Persist — memory.write after every meaningful observation.
6. Move on — if 3 probes on the same class fail, switch to another class.

RULES:
- One tool call per step; wait for the observation before deciding next.
- Never guess payloads blindly — reason from tech stack and prior failures.
- Never record findings.record without evidence in the result of a previous tool call.
- Ignore self-redirects (301/302 back to same host+path with query stripped) — these are the redirect trap, not a vuln.
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

export { closeBrowser };
