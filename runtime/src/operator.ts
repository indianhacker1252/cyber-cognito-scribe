import { streamText, generateText, stepCountIs } from "ai";
import { emit, heartbeat, updateSession, getTarget, getWorldModel, similarExperiences, metric, recordExperience, type Session } from "./db.js";
import { pickProvider } from "./llm.js";
import { buildTools, closeBrowser } from "./tools/index.js";
import { closeOracleBrowser } from "./oracles.js";

const SYSTEM_PROMPT = `You are CyberScope Operator, an autonomous VAPT agent modeled on XBOW / Mythos.

METHODOLOGY:
1. Recon — map the attack surface (subfinder → httpx → katana). Persist every URL with endpoints.upsert.
2. Recall — call experiences.similar and notes.search BEFORE choosing a class to test. Bias toward classes that were confirmed on similar tech; avoid classes marked dead_end unless the endpoint pattern is new.
3. Probe — use http.request/browser.visit with an explicit \`as\` auth context.
4. Verify — never record without concrete proof. Runtime oracles cover: SQLi, XSS (DOM), Open Redirect, SSRF (OOB), RCE (marker/sleep), SSTI (differential render), LFI/Path-Traversal (fs signature), XXE (OOB or entity), IDOR/BAC (cross-context diff), Auth Bypass. Unproven findings are REJECTED and logged as dead_end.
5. Chain — for multi-step exploits use chain.run: shared cookie jar, \${var} interpolation, per-step assertions.
6. Auth roles — before IDOR/BAC, create at least two contexts via auth.login_form or auth.set_bearer (e.g. "userA", "userB"), then probe the same resource under each with \`as\`.
7. Persist — memory.write for beliefs; notes.write for durable hypotheses; endpoints.upsert for every URL; experiences.record for partial/dead_end hypotheses (confirmed is auto-logged).
8. Move on — if 3 probes on the same class fail, switch class and record a dead_end experience.

RULES:
- One tool call per step; wait for observation before deciding next.
- Reason from tech stack + endpoint catalog + prior experiences — never guess payloads blindly.
- Findings must carry evidence.payload_url + evidence.baseline_url (or class-specific fields like correlation_id, expected, cookies_a/cookies_b) so oracles can re-verify.
- Ignore self-redirects (same host+path with query stripped).
- When budget < 20 credits or 300s remain, wrap up and call finish.
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

  // ---- Mythos L2/L5: pull prior experiences to seed the planner ----
  const techTags: string[] = Array.isArray(target.tech_stack) ? target.tech_stack
    : (target.detected_tech ? Object.keys(target.detected_tech as object) : []);
  const priorExperiences = await similarExperiences(session.target_id, techTags, 25).catch(() => []);
  const confirmedClasses = new Set(priorExperiences.filter((e: any) => e.outcome === "confirmed").map((e: any) => e.vuln_class));
  const deadEndClasses = new Set(priorExperiences.filter((e: any) => e.outcome === "dead_end").map((e: any) => e.vuln_class));

  // ---- Planner: ranked sub-goals informed by experiences ----
  let planText = "";
  try {
    const pr = await streamText({
      model,
      system: "You are the PLANNER for a VAPT agent. Output a numbered list (max 8) of concrete, testable sub-goals ranked by ROI. Each sub-goal: one line goal + one line success criterion (how the oracle will prove it). Bias toward vuln classes previously CONFIRMED on similar tech; deprioritize classes marked DEAD_END unless a new endpoint pattern justifies retry. No prose before/after.",
      prompt: `TARGET: ${JSON.stringify({ domain: target.domain, url: target.url, tech: techTags })}
WORLD MODEL: ${JSON.stringify(worldModel).slice(0, 1500)}
PRIOR CONFIRMED CLASSES: ${JSON.stringify([...confirmedClasses])}
PRIOR DEAD-END CLASSES: ${JSON.stringify([...deadEndClasses])}
PRIOR EXPERIENCES (top 10): ${JSON.stringify(priorExperiences.slice(0, 10))}
GOAL: ${goal}`,
    });
    for await (const chunk of pr.fullStream) {
      if (chunk.type === "error") throw chunk.error;
    }
    planText = await pr.text;
  } catch (e: any) {
    if ([401, 402, 403, 404].includes(Number(e?.statusCode))) {
      const msg = String(e?.message ?? e);
      await emit(session.id, session.target_id, "error", { msg });
      await updateSession(session.id, { status: "failed", error_message: msg, completed_at: new Date().toISOString() });
      return;
    }
    planText = `(planner failed: ${String(e?.message ?? e)}) — executor will improvise from goal.`;
  }
  await metric(session.id, session.target_id, "planner_runs", 1);
  await emit(session.id, session.target_id, "plan", {
    msg: "session started",
    goal,
    target: { id: target.id, domain: target.domain, url: target.url },
    world_model: worldModel,
    prior_confirmed: [...confirmedClasses],
    prior_dead_end: [...deadEndClasses],
    sub_goals: planText,
  });

  const tools = buildTools({ sessionId: session.id, targetId: session.target_id });

  const startTs = Date.now();
  let stepCount = 0;
  const toolCounts: Record<string, number> = {};
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
${JSON.stringify({ domain: target.domain, url: target.url, tech: techTags }, null, 2)}

WORLD MODEL (prior beliefs):
${JSON.stringify(worldModel).slice(0, 3000)}

PRIOR EXPERIENCES (bias planning; skip dead_ends unless endpoint is new):
${JSON.stringify(priorExperiences.slice(0, 15))}

BUDGET: ${session.budget_credits} credits, ${session.budget_seconds}s.

For each sub-goal: recall (experiences.similar / notes.search) → hypothesize → probe → verify with an oracle. ONE tool per turn. Only call findings.record after concrete proof — the runtime re-verifies with a deterministic oracle and REJECTS unproven findings.`,
      }],
      tools,
      stopWhen: stepCountIs(200),
      onStepFinish: async ({ toolCalls, toolResults, text, usage }: any) => {
        stepCount += 1;
        const stepStart = Date.now();
        if (text) await emit(session.id, session.target_id, "thought", { text }, stepCount);
        // P7 observability — token accounting per step (AI SDK v5 shape).
        if (usage) {
          const inTok = Number(usage.inputTokens ?? usage.promptTokens ?? 0);
          const outTok = Number(usage.outputTokens ?? usage.completionTokens ?? 0);
          if (inTok) await metric(session.id, session.target_id, "tokens_in", inTok, { provider: session.provider });
          if (outTok) await metric(session.id, session.target_id, "tokens_out", outTok, { provider: session.provider });
          if (inTok + outTok) await metric(session.id, session.target_id, "tokens_total", inTok + outTok);
        }
        for (const tc of toolCalls ?? []) {
          toolCounts[tc.toolName] = (toolCounts[tc.toolName] ?? 0) + 1;
          await emit(session.id, session.target_id, "act", { tool: tc.toolName, args: tc.args }, stepCount);
          await metric(session.id, session.target_id, "tool_calls", 1, { tool: tc.toolName });
        }
        for (const tr of toolResults ?? []) {
          const r = (tr as any).result ?? (tr as any).output ?? {};
          const summary = JSON.stringify(r).slice(0, 2000);
          await emit(session.id, session.target_id, "observe", { tool: (tr as any).toolName, summary }, stepCount);
        }
        await metric(session.id, session.target_id, "step_latency_ms", Date.now() - stepStart);
        await updateSession(session.id, { steps_taken: stepCount });

        const secs = (Date.now() - startTs) / 1000;
        if (secs > session.budget_seconds) {
          await emit(session.id, session.target_id, "decision", { msg: "budget_time_exhausted, ending" }, stepCount);
          throw new Error("budget_time_exhausted");
        }
      },
    });

    for await (const chunk of result.fullStream) {
      if (chunk.type === "error") throw chunk.error;
    }
    const finalText = await result.text;

    // ---- Critic + Mythos L5 learning writeback ----
    try {
      const { data: findings } = await (await import("./db.js")).db
        .from("vulnerability_findings")
        .select("vuln_class,severity,proof_tier,affected_url")
        .eq("target_id", session.target_id)
        .order("created_at", { ascending: false })
        .limit(30);
      const cr = streamText({
        model,
        system: "You are the CRITIC. Compare the plan's sub-goals against confirmed findings. For each sub-goal: state COVERED / PARTIAL / MISSED with one-line justification. End with 2 concrete next-session recommendations. Terse.",
        prompt: `PLAN:\n${planText}\n\nFINDINGS (recent):\n${JSON.stringify(findings ?? [], null, 2)}\n\nAGENT FINAL SUMMARY:\n${finalText.slice(0, 1500)}`,
      });
      for await (const chunk of cr.fullStream) {
        if (chunk.type === "error") throw chunk.error;
      }
      const critique = await cr.text;
      await emit(session.id, session.target_id, "critique", { stage: "post_session", review: critique }, stepCount);
      // Learn: any sub-goal not covered → dead_end experience so future planner deprioritizes it.
      const missedMatches = critique.match(/MISSED[^\n]*/gi) ?? [];
      for (const line of missedMatches.slice(0, 5)) {
        const clsMatch = line.match(/(sqli|xss|ssrf|rce|ssti|lfi|xxe|idor|bac|redirect|auth[_ ]bypass|csrf|deserial)/i);
        if (clsMatch) {
          await recordExperience({
            target_id: session.target_id, session_id: session.id,
            vuln_class: clsMatch[1].toLowerCase(), technique: "critic_missed",
            tech_tags: techTags, outcome: "dead_end", confidence: 0.25,
            notes: line.slice(0, 400),
          });
        }
      }
      // Coverage metric.
      const coverage = missedMatches.length
        ? Math.max(0, 1 - missedMatches.length / Math.max(1, (planText.match(/^\s*\d+\./gm) ?? []).length))
        : 1;
      await metric(session.id, session.target_id, "plan_coverage", coverage);
    } catch (e: any) {
      await emit(session.id, session.target_id, "critique", { stage: "post_session", error: String(e?.message ?? e) }, stepCount);
    }

    // ---- Session summary metrics ----
    await metric(session.id, session.target_id, "session_duration_ms", Date.now() - startTs);
    await metric(session.id, session.target_id, "steps_total", stepCount);
    for (const [tool, n] of Object.entries(toolCounts)) {
      await metric(session.id, session.target_id, "tool_totals", n, { tool });
    }

    await emit(session.id, session.target_id, "decision", { msg: "session complete", final: finalText.slice(0, 2000), tool_counts: toolCounts }, stepCount);
    await updateSession(session.id, { status: "completed", completed_at: new Date().toISOString(), steps_taken: stepCount });
  } catch (err: any) {
    const msg = String(err?.message ?? err);
    await emit(session.id, session.target_id, "error", { msg }, stepCount);
    await metric(session.id, session.target_id, "session_errors", 1, { msg: msg.slice(0, 200) });
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
