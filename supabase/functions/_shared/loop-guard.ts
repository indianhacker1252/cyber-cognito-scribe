// loop-guard — prevents modules from re-running indefinitely without new evidence.
//
// Contract per module:
//   const guard = await checkLoopGuard(db, targetId, "recon-juicy");
//   if (!guard.allow) return earlyExit(guard.reason);
//   ... do work, count findings ...
//   await recordLoopRun(db, targetId, "recon-juicy", { findingsCreated });
//
// Detection strategy:
//   Read the last N loop_guard entries for (module,target) from scan_logs.
//   If runs in window >= maxRuns AND the last `stallStreak` runs all wrote
//   zero new findings, refuse and log a stop marker.

export interface LoopGuardOpts {
  windowMinutes?: number; // sliding window (default 60)
  maxRuns?: number;       // hard ceiling in the window (default 6)
  stallStreak?: number;   // consecutive zero-finding runs that stop us (default 3)
}

export interface LoopGuardResult {
  allow: boolean;
  reason?: string;
  runIndex: number; // how many runs already in-window (excluding this one)
}

export async function checkLoopGuard(
  db: any,
  targetId: string,
  module: string,
  opts: LoopGuardOpts = {},
): Promise<LoopGuardResult> {
  const windowMinutes = opts.windowMinutes ?? 60;
  const maxRuns = opts.maxRuns ?? 6;
  const stallStreak = opts.stallStreak ?? 3;

  const since = new Date(Date.now() - windowMinutes * 60_000).toISOString();
  try {
    const { data } = await db
      .from("scan_logs")
      .select("metadata,created_at")
      .eq("target_id", targetId)
      .eq("log_type", "loop_guard")
      .gte("created_at", since)
      .order("created_at", { ascending: false })
      .limit(20);

    const runs = (data || []).filter((r: any) => r?.metadata?.module === module);
    const runIndex = runs.length;

    if (runIndex >= maxRuns) {
      await stopLog(db, targetId, module, `loop-guard: ${runIndex} runs in ${windowMinutes}min exceeds cap ${maxRuns}`);
      return { allow: false, reason: `max_runs_exceeded (${runIndex}/${maxRuns})`, runIndex };
    }

    if (runs.length >= stallStreak) {
      const recent = runs.slice(0, stallStreak);
      const allZero = recent.every((r: any) => Number(r?.metadata?.findings_created ?? 0) === 0);
      if (allZero) {
        await stopLog(db, targetId, module, `loop-guard: no new evidence for ${stallStreak} consecutive runs`);
        return { allow: false, reason: `stalled_no_new_evidence (${stallStreak} runs)`, runIndex };
      }
    }
    return { allow: true, runIndex };
  } catch {
    // On any read failure, fail-open (allow) — never let telemetry block work.
    return { allow: true, runIndex: 0 };
  }
}

export async function recordLoopRun(
  db: any,
  targetId: string,
  module: string,
  info: { findingsCreated?: number; probes?: number; note?: string } = {},
): Promise<void> {
  try {
    await db.from("scan_logs").insert({
      target_id: targetId,
      log_type: "loop_guard",
      message: `🔁 ${module} run complete — ${info.findingsCreated ?? 0} finding(s)`,
      metadata: {
        module,
        findings_created: info.findingsCreated ?? 0,
        probes: info.probes ?? null,
        note: info.note ?? null,
        ts: new Date().toISOString(),
      },
    });
  } catch { /* ignore */ }
}

async function stopLog(db: any, targetId: string, module: string, reason: string) {
  try {
    await db.from("scan_logs").insert({
      target_id: targetId,
      log_type: "warning",
      message: `🛑 ${module} skipped: ${reason}`,
      metadata: { module, kind: "loop_guard_stop", reason },
    });
  } catch { /* ignore */ }
}
