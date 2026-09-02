import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Badge } from "@/components/ui/badge";
import { Brain, Zap, Eye, ChevronRight, Cpu, Gauge } from "lucide-react";

type AgentEvent = { id: string; kind: string; step: number | null; payload: any; created_at: string };


// Three-lane Live Brain panel:
//   PLAN    = latest agent-planner turns (reasoning + proposed actions)
//   ACT     = currently running phases + running scan jobs
//   OBSERVE = latest oracle results + AI-confidence gate decisions
export function BrainPanel({ targetId }: { targetId: string | null }) {
  const plan = useQuery({
    queryKey: ["brain-plan", targetId],
    queryFn: async () => {
      if (!targetId) return [];
      const { data } = await supabase
        .from("planner_traces" as any)
        .select("id, trace_id, reasoning, actions, open_findings, provider, created_at")
        .eq("target_id", targetId)
        .order("created_at", { ascending: false })
        .limit(4);
      return (data || []) as any[];
    },
    refetchInterval: 5000,
    enabled: !!targetId,
  });

  const act = useQuery({
    queryKey: ["brain-act", targetId],
    queryFn: async () => {
      if (!targetId) return { phases: [], running: [], queued: [] };
      const [ph, jb, qd] = await Promise.all([
        supabase.from("scan_phase_state" as any).select("phase,status,last_heartbeat").eq("target_id", targetId).eq("status", "running"),
        supabase.from("scan_jobs" as any).select("job_type,started_at").eq("target_id", targetId).eq("status", "running").order("started_at", { ascending: false }).limit(8),
        supabase.from("scan_jobs" as any).select("job_type,priority").eq("target_id", targetId).eq("status", "queued").order("priority", { ascending: false }).limit(6),
      ]);
      return { phases: (ph.data || []) as any[], running: (jb.data || []) as any[], queued: (qd.data || []) as any[] };
    },
    refetchInterval: 4000,
    enabled: !!targetId,
  });

  const observe = useQuery({
    queryKey: ["brain-observe", targetId],
    queryFn: async () => {
      if (!targetId) return { oracles: [], gates: [] };
      const [orc, gt] = await Promise.all([
        supabase
          .from("scan_logs" as any)
          .select("id, message, metadata, created_at")
          .eq("target_id", targetId)
          .contains("metadata", { kind: "oracle_result" })
          .order("created_at", { ascending: false }).limit(6),
        supabase
          .from("scan_logs" as any)
          .select("id, message, metadata, created_at")
          .eq("target_id", targetId)
          .contains("metadata", { kind: "ai_confidence_suppressed" })
          .order("created_at", { ascending: false }).limit(6),
      ]);
      return { oracles: (orc.data || []) as any[], gates: (gt.data || []) as any[] };
    },
    refetchInterval: 5000,
    enabled: !!targetId,
  });

  if (!targetId) {
    return (
      <div className="rounded-lg border border-border bg-card p-4 text-sm text-muted-foreground">
        Select a target to see the AI brain live.
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-primary/30 bg-card p-4 space-y-4 shadow-[0_0_20px_hsl(var(--primary)/0.15)]">
      <div className="flex items-center gap-2">
        <Brain className="h-4 w-4 text-primary animate-pulse" />
        <span className="font-mono text-sm text-primary">NEURAL BRAIN — LIVE</span>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        {/* PLAN */}
        <section className="rounded border border-border bg-background/40 p-3 space-y-2">
          <div className="flex items-center gap-1.5 text-xs text-primary/80 font-mono">
            <Brain className="h-3.5 w-3.5" /> PLAN
          </div>
          {plan.data && plan.data.length > 0 ? (
            plan.data.map((t) => (
              <div key={t.id} className="text-xs space-y-1 border-l-2 border-primary/40 pl-2">
                <div className="text-muted-foreground font-mono">
                  #{String(t.trace_id).slice(0, 8)} · {Array.isArray(t.actions) ? t.actions.length : 0} actions · {t.provider}
                </div>
                <div className="text-foreground line-clamp-3">{t.reasoning || "(no reasoning)"}</div>
                {Array.isArray(t.actions) && t.actions.slice(0, 3).map((a: any, i: number) => (
                  <div key={i} className="flex items-center gap-1 text-[10px] text-muted-foreground">
                    <ChevronRight className="h-3 w-3" />
                    <span className="text-primary">{a.module}</span>
                    <span className="truncate">{a.expected_signal || a.rationale}</span>
                  </div>
                ))}
              </div>
            ))
          ) : (
            <div className="text-xs text-muted-foreground">No planner turns yet.</div>
          )}
        </section>

        {/* ACT */}
        <section className="rounded border border-border bg-background/40 p-3 space-y-2">
          <div className="flex items-center gap-1.5 text-xs text-primary/80 font-mono">
            <Zap className="h-3.5 w-3.5" /> ACT
          </div>
          {act.data?.phases?.length ? (
            <div className="flex flex-wrap gap-1">
              {act.data.phases.map((p: any) => (
                <Badge key={p.phase} variant="secondary" className="text-[10px]">{p.phase}</Badge>
              ))}
            </div>
          ) : null}
          <div className="text-[11px] text-muted-foreground">Running:</div>
          {act.data?.running?.length ? (
            <div className="flex flex-wrap gap-1">
              {act.data.running.map((j: any, i: number) => (
                <Badge key={i} variant="outline" className="text-[10px] font-mono border-primary/40">{j.job_type}</Badge>
              ))}
            </div>
          ) : <div className="text-xs text-muted-foreground">idle</div>}
          {act.data?.queued?.length ? (
            <>
              <div className="text-[11px] text-muted-foreground pt-1">Queued:</div>
              <div className="flex flex-wrap gap-1">
                {act.data.queued.map((j: any, i: number) => (
                  <Badge key={i} variant="outline" className="text-[10px] font-mono opacity-60">{j.job_type}</Badge>
                ))}
              </div>
            </>
          ) : null}
        </section>

        {/* OBSERVE */}
        <section className="rounded border border-border bg-background/40 p-3 space-y-2">
          <div className="flex items-center gap-1.5 text-xs text-primary/80 font-mono">
            <Eye className="h-3.5 w-3.5" /> OBSERVE
          </div>
          {observe.data?.oracles?.length ? observe.data.oracles.map((o: any) => (
            <div key={o.id} className="text-[11px] text-foreground border-l-2 border-green-500/50 pl-2">
              <span className="text-green-500 font-mono">ORACLE</span> {String(o.message).slice(0, 100)}
            </div>
          )) : null}
          {observe.data?.gates?.length ? observe.data.gates.map((g: any) => (
            <div key={g.id} className="text-[11px] text-muted-foreground border-l-2 border-yellow-500/40 pl-2 line-clamp-2">
              <span className="text-yellow-500 font-mono">GATE</span> {String(g.message).slice(0, 100)}
            </div>
          )) : null}
          {!observe.data?.oracles?.length && !observe.data?.gates?.length && (
            <div className="text-xs text-muted-foreground">No proof events yet.</div>
          )}
        </section>
      </div>

      <AgentRuntimeLane targetId={targetId} />
      <ObservabilityLane targetId={targetId} />
    </div>
  );
}

// P7 observability — tokens, step latency, tool mix for the latest agent session.
function ObservabilityLane({ targetId }: { targetId: string }) {
  const q = useQuery({
    queryKey: ["brain-observability", targetId],
    queryFn: async () => {
      const { data: s } = await supabase
        .from("agent_sessions" as any)
        .select("id,status,provider,model,steps_taken,started_at,completed_at")
        .eq("target_id", targetId)
        .order("created_at", { ascending: false })
        .limit(1)
        .maybeSingle();
      if (!s) return null;
      const sid = (s as any).id as string;
      const { data: m } = await supabase
        .from("agent_metrics" as any)
        .select("metric,value,tags,created_at")
        .eq("session_id", sid)
        .order("created_at", { ascending: false })
        .limit(500);
      const rows = (m || []) as any[];
      const sum = (name: string) => rows.filter(r => r.metric === name).reduce((a, r) => a + Number(r.value || 0), 0);
      const perTool: Record<string, { calls: number }> = {};
      for (const r of rows.filter(r => r.metric === "tool_calls")) {
        const t = String(r.tags?.tool ?? "unknown");
        perTool[t] = perTool[t] || { calls: 0 };
        perTool[t].calls += Number(r.value || 0);
      }
      const latencies = rows.filter(r => r.metric === "step_latency_ms").map(r => Number(r.value || 0));
      const p50 = latencies.length ? latencies.sort((a,b)=>a-b)[Math.floor(latencies.length/2)] : 0;
      const p95 = latencies.length ? latencies.sort((a,b)=>a-b)[Math.floor(latencies.length*0.95)] : 0;
      return {
        session: s,
        tokens_in: sum("tokens_in"),
        tokens_out: sum("tokens_out"),
        tool_calls: sum("tool_calls"),
        errors: sum("session_errors"),
        coverage: rows.find(r => r.metric === "plan_coverage")?.value ?? null,
        perTool: Object.entries(perTool).sort((a,b) => b[1].calls - a[1].calls).slice(0, 8),
        p50, p95,
      };
    },
    refetchInterval: 6000,
    enabled: !!targetId,
  });

  if (!q.data) return null;
  const { session, tokens_in, tokens_out, tool_calls, errors, coverage, perTool, p50, p95 } = q.data as any;
  const dur = session.completed_at && session.started_at
    ? Math.round((+new Date(session.completed_at) - +new Date(session.started_at)) / 1000) : null;

  return (
    <section className="rounded border border-primary/30 bg-background/60 p-3 space-y-2">
      <div className="flex items-center gap-1.5 text-xs text-primary font-mono">
        <Gauge className="h-3.5 w-3.5" /> OBSERVABILITY · {session.provider}/{session.model} · {session.status}
        {dur !== null && <span className="ml-auto text-muted-foreground">{dur}s</span>}
      </div>
      <div className="grid grid-cols-2 md:grid-cols-6 gap-2 text-[11px] font-mono">
        <Stat label="steps" value={session.steps_taken ?? 0} />
        <Stat label="tokens in" value={tokens_in.toLocaleString()} />
        <Stat label="tokens out" value={tokens_out.toLocaleString()} />
        <Stat label="tool calls" value={tool_calls} />
        <Stat label="p50 / p95 ms" value={`${p50} / ${p95}`} />
        <Stat label="coverage" value={coverage !== null ? `${Math.round(Number(coverage)*100)}%` : "—"}
              tone={coverage !== null && Number(coverage) < 0.5 ? "warn" : "ok"} />
      </div>
      {perTool.length > 0 && (
        <div className="flex flex-wrap gap-1 pt-1">
          {perTool.map(([t, v]: any) => (
            <Badge key={t} variant="outline" className="text-[10px] font-mono border-primary/30">
              {t} <span className="ml-1 text-primary">{v.calls}</span>
            </Badge>
          ))}
        </div>
      )}
      {errors > 0 && <div className="text-[11px] text-red-400 font-mono">{errors} session error(s)</div>}
    </section>
  );
}

function Stat({ label, value, tone = "ok" }: { label: string; value: any; tone?: "ok" | "warn" }) {
  return (
    <div className="rounded border border-border bg-background/40 px-2 py-1.5">
      <div className="text-muted-foreground text-[10px] uppercase">{label}</div>
      <div className={tone === "warn" ? "text-yellow-400" : "text-foreground"}>{value}</div>
    </div>
  );
}

// Option-B lane: live stream of agent_events (Plan/Act/Observe from the VPS runtime).
function AgentRuntimeLane({ targetId }: { targetId: string }) {
  const [events, setEvents] = useState<AgentEvent[]>([]);
  const [sessionId, setSessionId] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      const { data: s } = await supabase
        .from("agent_sessions" as any)
        .select("id")
        .eq("target_id", targetId)
        .order("created_at", { ascending: false })
        .limit(1)
        .maybeSingle();
      if (cancelled || !s) return;
      const sid = (s as any).id as string;
      setSessionId(sid);
      const { data: ev } = await supabase
        .from("agent_events" as any)
        .select("id,kind,step,payload,created_at")
        .eq("session_id", sid)
        .order("created_at", { ascending: false })
        .limit(50);
      if (!cancelled) setEvents(((ev || []) as any[]).reverse());
    })();
    return () => { cancelled = true; };
  }, [targetId]);

  useEffect(() => {
    if (!sessionId) return;
    const channel = supabase
      .channel(`agent-events-${sessionId}`)
      .on("postgres_changes",
        { event: "INSERT", schema: "public", table: "agent_events", filter: `session_id=eq.${sessionId}` },
        (payload) => setEvents((prev) => [...prev.slice(-99), payload.new as AgentEvent]))
      .subscribe();
    return () => { supabase.removeChannel(channel); };
  }, [sessionId]);

  if (!sessionId) {
    return (
      <div className="rounded border border-dashed border-border bg-background/40 p-3 text-xs text-muted-foreground">
        <Cpu className="inline h-3.5 w-3.5 mr-1 opacity-60" />
        Agent runtime idle — click <span className="text-primary">Start Agent Scan</span> to launch the VPS operator loop.
      </div>
    );
  }

  const color = (k: string) =>
    k === "thought" ? "text-blue-400 border-blue-500/40"
    : k === "tool_call" ? "text-yellow-400 border-yellow-500/40"
    : k === "tool_result" ? "text-green-400 border-green-500/40"
    : k === "decision" ? "text-primary border-primary/40"
    : k === "error" ? "text-red-400 border-red-500/40"
    : "text-muted-foreground border-border";

  return (
    <section className="rounded border border-primary/30 bg-background/60 p-3 space-y-2">
      <div className="flex items-center gap-1.5 text-xs text-primary font-mono">
        <Cpu className="h-3.5 w-3.5 animate-pulse" /> AGENT RUNTIME · session {sessionId.slice(0, 8)}
        <span className="ml-auto text-muted-foreground">{events.length} events</span>
      </div>
      <div className="max-h-64 overflow-y-auto space-y-1 font-mono text-[11px]">
        {events.length === 0 && <div className="text-muted-foreground">Waiting for VPS worker…</div>}
        {events.slice().reverse().map((e) => (
          <div key={e.id} className={`border-l-2 pl-2 ${color(e.kind)}`}>
            <span className="opacity-60">#{e.step ?? "-"}</span>{" "}
            <span className="uppercase">{e.kind}</span>{" "}
            <span className="text-foreground/80">
              {e.payload?.msg || e.payload?.tool || e.payload?.text || e.payload?.summary || JSON.stringify(e.payload).slice(0, 160)}
            </span>
          </div>
        ))}
      </div>
    </section>
  );
}

