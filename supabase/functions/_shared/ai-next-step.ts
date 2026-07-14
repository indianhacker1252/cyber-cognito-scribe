export async function logAiNextStep(
  db: any,
  input: {
    targetId: string;
    decisionType: string;
    debating: string;
    reasoningSummary: string;
    nextStep?: Record<string, unknown> | null;
    extra?: Record<string, unknown>;
  },
): Promise<void> {
  try {
    await db.from("scan_logs").insert({
      target_id: input.targetId,
      log_type: "thought",
      message: `🧠 AI next-step: ${input.reasoningSummary}`,
      metadata: {
        kind: "ai_next_step",
        decision_type: input.decisionType,
        debating: input.debating,
        next_step: input.nextStep ?? null,
        ...(input.extra || {}),
      },
    });
  } catch {
    /* telemetry must never break scanner flow */
  }
}