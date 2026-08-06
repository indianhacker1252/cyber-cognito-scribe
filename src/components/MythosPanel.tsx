import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Brain, CheckCircle2, XCircle, Activity, TrendingUp } from "lucide-react";

type Experience = {
  vuln_class: string;
  technique: string | null;
  endpoint_pattern: string | null;
  outcome: "confirmed" | "rejected" | "partial" | "dead_end";
  confidence: number | null;
  proof_snippet: string | null;
  notes: string | null;
  created_at: string;
};

type Metric = { metric: string; value: number; tags: any; created_at: string };

export function MythosPanel({ targetId }: { targetId: string | null }) {
  const [experiences, setExperiences] = useState<Experience[]>([]);
  const [metrics, setMetrics] = useState<Metric[]>([]);

  useEffect(() => {
    if (!targetId) return;
    let alive = true;
    const load = async () => {
      const [{ data: exps }, { data: mts }] = await Promise.all([
        supabase.from("agent_experiences").select("*").eq("target_id", targetId)
          .order("created_at", { ascending: false }).limit(30),
        supabase.from("agent_metrics").select("*").eq("target_id", targetId)
          .order("created_at", { ascending: false }).limit(200),
      ]);
      if (!alive) return;
      setExperiences((exps as Experience[]) ?? []);
      setMetrics((mts as Metric[]) ?? []);
    };
    load();
    const ch = supabase.channel(`mythos-${targetId}`)
      .on("postgres_changes", { event: "INSERT", schema: "public", table: "agent_experiences", filter: `target_id=eq.${targetId}` }, load)
      .on("postgres_changes", { event: "INSERT", schema: "public", table: "agent_metrics", filter: `target_id=eq.${targetId}` }, load)
      .subscribe();
    return () => { alive = false; supabase.removeChannel(ch); };
  }, [targetId]);

  const sum = (name: string) => metrics.filter(m => m.metric === name).reduce((a, b) => a + Number(b.value), 0);
  const confirmed = experiences.filter(e => e.outcome === "confirmed").length;
  const deadEnds = experiences.filter(e => e.outcome === "dead_end").length;
  const rejectedByOracle = sum("findings_rejected_by_oracle");
  const toolCalls = sum("tool_calls");
  const oracleCalls = sum("oracle_calls");
  const planCovXs = metrics.filter(m => m.metric === "plan_coverage").map(m => Number(m.value));
  const planCov = planCovXs.length ? (planCovXs.reduce((a, b) => a + b, 0) / planCovXs.length) : 0;

  if (!targetId) return null;

  return (
    <Card className="p-2 border-primary/20 bg-background/60 space-y-2">
      <div className="flex items-center gap-2 text-[11px] font-mono text-primary">
        <Brain className="h-3 w-3" />
        <span>MYTHOS · Experience Replay + Proof Metrics</span>
      </div>

      <div className="grid grid-cols-3 gap-1 text-[10px]">
        <Stat icon={<CheckCircle2 className="h-3 w-3 text-green-500" />} label="confirmed" value={confirmed} />
        <Stat icon={<XCircle className="h-3 w-3 text-destructive" />} label="oracle-rejected" value={rejectedByOracle} />
        <Stat icon={<XCircle className="h-3 w-3 text-muted-foreground" />} label="dead-ends" value={deadEnds} />
        <Stat icon={<Activity className="h-3 w-3 text-cyan-400" />} label="tool calls" value={toolCalls} />
        <Stat icon={<Activity className="h-3 w-3 text-cyan-400" />} label="oracle runs" value={oracleCalls} />
        <Stat icon={<TrendingUp className="h-3 w-3 text-primary" />} label="plan cov" value={`${Math.round(planCov * 100)}%`} />
      </div>

      {experiences.length > 0 && (
        <div className="space-y-0.5 max-h-40 overflow-auto font-mono text-[10px]">
          <div className="text-muted-foreground uppercase tracking-wide">Recent experiences</div>
          {experiences.slice(0, 12).map((e, i) => (
            <div key={i} className="flex gap-1 items-start">
              <Badge variant="outline" className={`text-[9px] py-0 px-1 ${
                e.outcome === "confirmed" ? "border-green-500/40 text-green-500"
                : e.outcome === "dead_end" ? "border-muted text-muted-foreground"
                : "border-yellow-500/40 text-yellow-500"
              }`}>{e.outcome}</Badge>
              <span className="text-primary">{e.vuln_class}</span>
              <span className="text-muted-foreground truncate flex-1">
                {e.technique ? `[${e.technique}] ` : ""}{e.endpoint_pattern ?? e.notes ?? e.proof_snippet ?? ""}
              </span>
            </div>
          ))}
        </div>
      )}
    </Card>
  );
}

function Stat({ icon, label, value }: { icon: React.ReactNode; label: string; value: number | string }) {
  return (
    <div className="flex items-center gap-1 px-1 py-0.5 rounded bg-background/40 border border-border/40">
      {icon}
      <span className="text-muted-foreground">{label}</span>
      <span className="ml-auto text-foreground font-mono">{value}</span>
    </div>
  );
}
