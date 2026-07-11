// Central enqueue helper — populates scan_jobs.idempotency_key so the unique
// partial index (idempotency_key WHERE status IN queued/running) actually
// dedupes. Before this helper, every insert left the key NULL and the index
// was a no-op, causing 100+ duplicate jobs per (target, job_type).
//
// dedupWindowMs: only two jobs computed within the SAME window bucket collide.
// Use a short window (5m) for hot paths (mythos_step), longer (30m) for
// discovery/recon.

export interface EnqueueJob {
  target_id: string;
  job_type: string;
  status?: string;           // default 'queued'
  priority?: number;         // default 5
  payload?: any;             // default {}
  next_run_at?: string;      // default now()
  dedupWindowMs?: number;    // default 15 min
  dedupExtraKey?: string;    // optional discriminator (e.g. runId, host)
}

async function sha1Hex(s: string): Promise<string> {
  const buf = new TextEncoder().encode(s);
  const digest = await crypto.subtle.digest("SHA-1", buf);
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function stableStringify(v: any): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(stableStringify).join(",") + "]";
  const keys = Object.keys(v).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + stableStringify(v[k])).join(",") + "}";
}

export async function buildIdempotencyKey(job: EnqueueJob): Promise<string> {
  const win = job.dedupWindowMs ?? 15 * 60_000;
  const bucket = Math.floor(Date.now() / win);
  const payloadHash = stableStringify(job.payload ?? {});
  const raw = `${job.target_id}|${job.job_type}|${bucket}|${payloadHash}|${job.dedupExtraKey ?? ""}`;
  return await sha1Hex(raw);
}

/**
 * Insert one job, deduped via idempotency_key. Returns true if inserted,
 * false if a duplicate already existed (conflict swallowed).
 */
export async function enqueueJob(db: any, job: EnqueueJob): Promise<boolean> {
  const key = await buildIdempotencyKey(job);
  const row = {
    target_id: job.target_id,
    job_type: job.job_type,
    status: job.status ?? "queued",
    priority: job.priority ?? 5,
    payload: job.payload ?? {},
    next_run_at: job.next_run_at ?? new Date().toISOString(),
    idempotency_key: key,
  };
  try {
    const { error } = await db.from("scan_jobs").insert(row);
    if (!error) return true;
    // 23505 = unique_violation from the partial idempotency index → dedupe hit
    if ((error as any).code === "23505" || /duplicate|unique/i.test((error as any).message || "")) {
      return false;
    }
    return false;
  } catch {
    return false;
  }
}

/** Bulk variant. Each job is deduped independently. */
export async function enqueueJobs(db: any, jobs: EnqueueJob[]): Promise<number> {
  let inserted = 0;
  for (const j of jobs) if (await enqueueJob(db, j)) inserted++;
  return inserted;
}
