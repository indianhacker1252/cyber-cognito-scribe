import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { Badge } from "@/components/ui/badge";
import { Brain, Zap, Eye, ChevronRight } from "lucide-react";

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
    </div>
  );
}
