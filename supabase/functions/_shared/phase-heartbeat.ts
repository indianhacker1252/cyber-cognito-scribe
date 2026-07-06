// phase-heartbeat.ts — every scanner module writes a heartbeat so the
// arbiter can detect silent stalls and move the pipeline forward.

export type PhaseName = "recon" | "discovery" | "owasp_matrix" | "deep_modules" | "exploit" | "chain" | "report";

export async function beginPhase(db: any, targetId: string, phase: PhaseName, meta: Record<string, unknown> = {}) {
  try {
    await db.from("scan_phase_state").upsert(
      {
        target_id: targetId,
        phase,
        status: "running",
        started_at: new Date().toISOString(),
        last_heartbeat: new Date().toISOString(),
        metadata: meta,
      },
      { onConflict: "target_id,phase" },
    );
  } catch {
    /* ignore */
  }
}

export async function heartbeat(
  db: any,
  targetId: string,
  phase: PhaseName,
  deltas: { checks_attempted?: number; checks_passed?: number; findings_count?: number } = {},
) {
  try {
    // Best-effort increment + heartbeat (read-then-write because no RPC).
    const { data: row } = await db
      .from("scan_phase_state")
      .select("checks_attempted,checks_passed,findings_count")
      .eq("target_id", targetId)
      .eq("phase", phase)
      .maybeSingle();
    await db.from("scan_phase_state").upsert(
      {
        target_id: targetId,
        phase,
        status: "running",
        last_heartbeat: new Date().toISOString(),
        checks_attempted: (row?.checks_attempted ?? 0) + (deltas.checks_attempted ?? 0),
        checks_passed: (row?.checks_passed ?? 0) + (deltas.checks_passed ?? 0),
        findings_count: (row?.findings_count ?? 0) + (deltas.findings_count ?? 0),
      },
      { onConflict: "target_id,phase" },
    );
  } catch {
    /* ignore */
  }
}

export async function completePhase(
  db: any,
  targetId: string,
  phase: PhaseName,
  status: "complete" | "failed" = "complete",
) {
  try {
    await db
      .from("scan_phase_state")
      .update({
        status,
        completed_at: new Date().toISOString(),
        last_heartbeat: new Date().toISOString(),
      })
      .eq("target_id", targetId)
      .eq("phase", phase);
  } catch {
    /* ignore */
  }
}

export async function markChecklist(
  db: any,
  targetId: string,
  category: string,
  checkName: string,
  opts: { foundEvidence?: boolean } = {},
) {
  try {
    const { data: row } = await db
      .from("owasp_checklist")
      .select("evidence_count")
      .eq("target_id", targetId)
      .eq("category", category)
      .eq("check_name", checkName)
      .maybeSingle();
    await db.from("owasp_checklist").upsert(
      {
        target_id: targetId,
        category,
        check_name: checkName,
        status: opts.foundEvidence ? "evidence" : "attempted",
        evidence_count: (row?.evidence_count ?? 0) + (opts.foundEvidence ? 1 : 0),
        last_run_at: new Date().toISOString(),
      },
      { onConflict: "target_id,category,check_name" },
    );
  } catch {
    /* ignore */
  }
}
