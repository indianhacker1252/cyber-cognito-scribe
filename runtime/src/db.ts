// Gateway client — the runtime never holds the service role key.
// All DB access goes through the runtime-gateway edge function,
// authenticated with a shared RUNTIME_SECRET.

const BASE = `${process.env.SUPABASE_URL ?? ""}/functions/v1/runtime-gateway`;
const SECRET = process.env.RUNTIME_SECRET ?? "";
if (!process.env.SUPABASE_URL || !SECRET) {
  throw new Error("SUPABASE_URL and RUNTIME_SECRET are required");
}

type Filter = { op: string; col: string; val: unknown };
type Order = { col: string; asc?: boolean };

async function call(body: Record<string, unknown>): Promise<{ data: any; error: any; count?: number | null }> {
  try {
    const r = await fetch(BASE, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-runtime-secret": SECRET },
      body: JSON.stringify(body),
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) return { data: null, error: { message: j.error ?? `gateway HTTP ${r.status}` } };
    if (j.error) return { data: null, error: { message: j.error } };
    return { data: j.data ?? null, error: null, count: j.count ?? null };
  } catch (e) {
    return { data: null, error: { message: String((e as Error).message) } };
  }
}

// Minimal supabase-js-style chain builder over the gateway.
class Query {
  private filters: Filter[] = [];
  private orders: Order[] = [];
  private _limit?: number;
  private _single?: "maybe" | "one";
  private _select?: string;
  private _or?: string;

  constructor(
    private table: string,
    private op: "query" | "insert" | "upsert" | "update",
    private payload?: unknown,
    private opts?: { onConflict?: string; count?: string },
  ) {}

  select(cols = "*") { this._select = cols; return this; }
  eq(col: string, val: unknown) { this.filters.push({ op: "eq", col, val }); return this; }
  neq(col: string, val: unknown) { this.filters.push({ op: "neq", col, val }); return this; }
  in(col: string, val: unknown[]) { this.filters.push({ op: "in", col, val }); return this; }
  ilike(col: string, val: string) { this.filters.push({ op: "ilike", col, val }); return this; }
  overlaps(col: string, val: unknown[]) { this.filters.push({ op: "overlaps", col, val }); return this; }
  gt(col: string, val: unknown) { this.filters.push({ op: "gt", col, val }); return this; }
  lt(col: string, val: unknown) { this.filters.push({ op: "lt", col, val }); return this; }
  or(expr: string) { this._or = expr; return this; }
  order(col: string, o?: { ascending?: boolean }) { this.orders.push({ col, asc: o?.ascending !== false }); return this; }
  limit(n: number) { this._limit = n; return this; }
  maybeSingle() { this._single = "maybe"; return this; }
  single() { this._single = "one"; return this; }

  then<TResult1 = any, TResult2 = never>(
    onfulfilled?: ((v: any) => TResult1 | PromiseLike<TResult1>) | null,
    onrejected?: ((r: any) => TResult2 | PromiseLike<TResult2>) | null,
  ) {
    const body: Record<string, unknown> = { op: this.op, table: this.table };
    if (this.op === "query") {
      Object.assign(body, {
        select: this._select, filters: this.filters, or: this._or,
        order: this.orders, limit: this._limit, single: this._single,
      });
    } else if (this.op === "insert") {
      Object.assign(body, { rows: this.payload, select: this._select, single: this._single });
    } else if (this.op === "upsert") {
      Object.assign(body, {
        rows: this.payload, onConflict: this.opts?.onConflict,
        count: this.opts?.count === "exact", select: this._select, single: this._single,
      });
    } else {
      Object.assign(body, { patch: this.payload, filters: this.filters });
    }
    return call(body).then(onfulfilled, onrejected);
  }
}

export const db = {
  from(table: string) {
    return {
      select: (cols = "*") => new Query(table, "query").select(cols),
      insert: (rows: unknown) => new Query(table, "insert", rows),
      upsert: (rows: unknown, opts?: { onConflict?: string; count?: string }) => new Query(table, "upsert", rows, opts),
      update: (patch: unknown) => new Query(table, "update", patch),
    };
  },
  rpc(fn: string, args?: Record<string, unknown>) {
    return call({ op: "rpc", fn, args });
  },
};

export type Session = {
  id: string;
  target_id: string;
  status: string;
  goal: string | null;
  model: string;
  provider: string;
  budget_credits: number;
  budget_seconds: number;
  credits_used: number;
  steps_taken: number;
  started_at: string | null;
  metadata: Record<string, unknown>;
};

export async function claimSession(host: string): Promise<Session | null> {
  const { data, error } = await db.rpc("claim_agent_session", { _host: host });
  if (error) {
    console.error("[db] claim_agent_session error:", error.message);
    return null;
  }
  const s = data as Session | null;
  if (!s || !s.id) return null;
  return s;
}

export async function emit(
  sessionId: string,
  targetId: string,
  kind: string,
  payload: Record<string, unknown>,
  step?: number,
) {
  await db.from("agent_events").insert({
    session_id: sessionId,
    target_id: targetId,
    kind,
    step: step ?? null,
    payload,
  });
}

export async function logToolInvocation(row: {
  session_id: string;
  target_id: string;
  step: number;
  tool: string;
  args: unknown;
  result: unknown;
  ok: boolean;
  latency_ms: number;
  cost_credits?: number;
}) {
  await db.from("tool_invocations").insert(row);
}

export async function updateSession(id: string, patch: Record<string, unknown>) {
  await db.from("agent_sessions").update(patch).eq("id", id);
}

export async function heartbeat(id: string) {
  await db.from("agent_sessions").update({ last_heartbeat: new Date().toISOString() }).eq("id", id);
}

export async function getTarget(id: string) {
  const { data } = await db.from("target_workspaces").select("*").eq("id", id).maybeSingle();
  return data;
}

export async function mergeWorldModel(targetId: string, patch: Record<string, unknown>) {
  await db.rpc("merge_world_model", { _target_id: targetId, _patch: patch });
}

export async function getWorldModel(targetId: string) {
  const { data } = await db.from("target_world_model").select("model").eq("target_id", targetId).maybeSingle();
  return (data?.model as Record<string, unknown>) ?? {};
}

// -------- Mythos L2 (experience replay) --------
export async function recordExperience(row: {
  target_id: string; session_id?: string | null;
  vuln_class: string; technique?: string | null; endpoint_pattern?: string | null;
  tech_tags?: string[]; outcome: "confirmed" | "rejected" | "partial" | "dead_end";
  confidence?: number; proof_snippet?: string | null; notes?: string | null;
}) {
  const { error } = await db.from("agent_experiences").insert(row);
  if (error) console.error("[db] recordExperience:", error.message);
}
export async function similarExperiences(targetId: string, techTags: string[] = [], limit = 20) {
  const { data } = await db.from("agent_experiences")
    .select("vuln_class,technique,endpoint_pattern,outcome,confidence,proof_snippet,notes,created_at,target_id")
    .eq("target_id", targetId)
    .order("created_at", { ascending: false }).limit(limit);
  if (data && data.length) return data;
  if (techTags.length) {
    const { data: cross } = await db.from("agent_experiences")
      .select("vuln_class,technique,endpoint_pattern,outcome,confidence,proof_snippet,notes,created_at,target_id")
      .overlaps("tech_tags", techTags)
      .order("created_at", { ascending: false }).limit(limit);
    return cross ?? [];
  }
  return [];
}

// -------- Mythos L3 (metrics) --------
export async function metric(sessionId: string, targetId: string, name: string, value = 1, tags: Record<string, unknown> = {}) {
  const { error } = await db.from("agent_metrics").insert({
    session_id: sessionId, target_id: targetId, metric: name, value, tags,
  });
  if (error) console.error("[db] metric:", error.message);
}
