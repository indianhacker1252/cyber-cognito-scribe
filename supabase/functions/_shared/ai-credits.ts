// Tiny helper to detect & propagate Lovable AI credit exhaustion.
// Writes a single sentinel scan_log row that other functions can poll.

export class AiCreditsExhaustedError extends Error {
  status: number = 402;
  constructor(msg = "AI credits exhausted", status = 402) {
    super(msg);
    this.status = status;
    this.name = "AiCreditsExhaustedError";
  }
}

/** True if HTTP status + (optional) body indicates Lovable AI is out of credits or rate-limited terminally. */
export function isCreditExhaustionResponse(status: number, body?: string): boolean {
  if (status === 402) return true;
  if (status === 429 && body && /credits|quota|exhaust|insufficient/i.test(body)) return true;
  if (body && /credits.{0,12}exhaust|insufficient.{0,12}credit|out of credit/i.test(body)) return true;
  return false;
}

/** Write one sentinel error row. Callers should then exit cleanly. */
export async function markCreditsExhausted(
  db: any,
  opts: { targetId?: string | null; runId?: string | null; phase?: string; reason?: string },
) {
  try {
    await db.from("scan_logs").insert({
      target_id: opts.targetId ?? null,
      log_type: "error",
      message: `🪫 AI credits exhausted — scan paused. Add credits in Workspace → Usage and re-run. (${opts.reason || "402"})`,
      metadata: {
        kind: "ai_credits_exhausted",
        phase: opts.phase || "unknown",
        run_id: opts.runId ?? null,
        until: new Date(Date.now() + 10 * 60_000).toISOString(),
      },
    });
  } catch { /* best-effort */ }
}

/** Return true if a credit-exhaustion sentinel was written for this target in the last `minutes` minutes. */
export async function areCreditsRecentlyExhausted(
  db: any,
  targetId: string | null | undefined,
  minutes = 10,
): Promise<boolean> {
  if (!targetId) return false;
  try {
    const since = new Date(Date.now() - minutes * 60_000).toISOString();
    const { data } = await db
      .from("scan_logs")
      .select("id, metadata")
      .eq("target_id", targetId)
      .eq("log_type", "error")
      .gte("created_at", since)
      .order("created_at", { ascending: false })
      .limit(20);
    for (const row of data || []) {
      if ((row.metadata as any)?.kind === "ai_credits_exhausted") return true;
    }
    return false;
  } catch {
    return false;
  }
}

/** Check credits and throw if exhausted. Helper for LLM call sites. */
export async function checkCreditsAndFailFast(db: any, targetId?: string | null) {
  if (!db || !targetId) return;
  if (await areCreditsRecentlyExhausted(db, targetId, 10)) {
    throw new AiCreditsExhaustedError("AI credits exhausted (cached sentinel)");
  }
}
