import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { useEffect } from "react";
import { Badge } from "@/components/ui/badge";
import { Brain, Zap, ChevronRight } from "lucide-react";

// Live "AI brain" strip that shows:
//   NOW    = currently running phase(s) + running job types
//   NEXT   = top queued job types
//   THINK  = latest attack_hypotheses (AI strategist output)
// Reads scan_phase_state, scan_jobs, attack_hypotheses. Realtime.
export function BrainPanel({ targetId }: { targetId: string | null }) {
  const now = useQuery({
    queryKey: ["brain-now", targetId],
    queryFn: async () => {
      if (!targetId) return { phases: [], running: [] };
      const [ph, jb] = await Promise.all([
        supabase.from("scan_phase_state" as any).select("phase,status,last_heartbeat").eq("target_id", targetId).eq("status", "running"),
        supabase.from("scan_jobs" as any).select("job_type,started_at").eq("target_id", targetId).eq("status", "running").order("started_at", { ascending: false }).limit(10),
      ]);
      return { phases: (ph.data || []) as any[], running: (jb.data || []) as any[] };
    },
    refetchInterval: 4000,
    enabled: !!targetId,
  });

  const next = useQuery({
    queryKey: ["brain-next", targetId],
    queryFn: async () => {
      if (!targetId) return [];
      const { data } = await supabase
        .from("scan_jobs" as any)
        .select("job_type,priority")
        .eq("target_id", targetId).eq("status", "queued")
        .order("priority", { ascending: false }).limit(8);
      return (data || []) as any[];
    },
    refetchInterval: 4000,
    enabled: !!targetId,
  });

  const hypotheses = useQuery({
    queryKey: ["brain-hypo", targetId],
    queryFn: async () => {
      if (!targetId) return [];
      const { data } = await supabase
        .from("attack_hypotheses" as any)
        .select("id,round,vuln_class,endpoint_url,hypothesis,status,created_at")
        .eq("target_id", targetId)
        .order("created_at", { ascending: false }).limit(6);
      return (data || []) as any[];
    },
    refetchInterval: 6000,
    enabled: !!targetId,
  });

  useEffect(() => {
    if (!targetId) return;
    const ch = supabase
      .channel(`brain-${targetId}`)
      .on("postgres_changes", { event: "*", schema: "public", table: "scan_jobs", filter: `target_id=eq.${targetId}` }, () => { now.refetch(); next.refetch(); })
      .on("postgres_changes", { event: "*", schema: "public", table: "attack_hypotheses", filter: `target_id=eq.${targetId}` }, () => hypotheses.refetch())
      .subscribe();
    return () => { supabase.removeChannel(ch); };
  }, [targetId, now, next, hypotheses]);

  if (!targetId) {
    return <div className="text-[10px] text-muted-foreground font-mono p-2">Select a target to see the AI brain state.</div>;
  }

  return (
    <div className="rounded border border-border bg-background/60 p-2 space-y-2 font-mono text-[11px]">
      <div>
        <div className="flex items-center gap-1 text-cyber-cyan mb-1">
          <Zap className="h-3 w-3" /> <span className="uppercase text-[9px]">Now</span>
        </div>
        {now.data && (now.data.phases.length || now.data.running.length) ? (
          <div className="flex flex-wrap gap-1">
            {now.data.phases.map((p: any) => (
              <Badge key={p.phase} variant="outline" className="text-[9px] border-cyber-cyan/50 text-cyber-cyan animate-pulse">{p.phase}</Badge>
            ))}
            {now.data.running.map((j: any, i: number) => (
              <Badge key={i} variant="outline" className="text-[9px] border-cyber-green/40 text-cyber-green">{j.job_type}</Badge>
            ))}
          </div>
        ) : <span className="text-muted-foreground text-[10px]">idle</span>}
      </div>

      <div>
        <div className="flex items-center gap-1 text-cyber-amber mb-1">
          <ChevronRight className="h-3 w-3" /> <span className="uppercase text-[9px]">Next Up</span>
        </div>
        {next.data && next.data.length ? (
          <div className="flex flex-wrap gap-1">
            {next.data.map((j: any, i: number) => (
              <Badge key={i} variant="outline" className="text-[9px] border-cyber-amber/40 text-cyber-amber">{j.job_type}<span className="opacity-50 ml-1">·{j.priority}</span></Badge>
            ))}
          </div>
        ) : <span className="text-muted-foreground text-[10px]">queue empty</span>}
      </div>

      <div>
        <div className="flex items-center gap-1 text-primary mb-1">
          <Brain className="h-3 w-3" /> <span className="uppercase text-[9px]">AI Hypotheses</span>
        </div>
        {hypotheses.data && hypotheses.data.length ? (
          <div className="space-y-1 max-h-40 overflow-auto">
            {hypotheses.data.map((h: any) => (
              <div key={h.id} className="border-l-2 border-primary/40 pl-2 py-0.5">
                <div className="flex items-center gap-1 text-[9px]">
                  <span className="text-primary">R{h.round}</span>
                  <span className="text-cyber-cyan">{h.vuln_class}</span>
                  <span className={`ml-auto ${h.status === "confirmed" ? "text-cyber-green" : h.status === "failed" ? "text-destructive" : "text-muted-foreground"}`}>{h.status}</span>
                </div>
                <p className="text-[10px] text-card-foreground truncate">{h.hypothesis}</p>
                {h.endpoint_url && <p className="text-[9px] text-muted-foreground truncate">→ {h.endpoint_url}</p>}
              </div>
            ))}
          </div>
        ) : <span className="text-muted-foreground text-[10px]">no hypotheses yet — AI strategist runs after owasp_matrix</span>}
      </div>
    </div>
  );
}
