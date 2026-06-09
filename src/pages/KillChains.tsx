import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import { Loader2, GitBranch, Play, ChevronRight } from "lucide-react";

type Target = { id: string; name: string; domain: string };
type Chain = {
  id: string;
  target_id: string;
  goal: string;
  total_cost: number;
  severity: string;
  step_plan: Array<{ order: number; node: string; node_type: string; technique: string; finding_id: string | null }>;
  status: string;
  created_at: string;
};
type NodeRow = { id: string; node_type: string; label: string; capability_tags: string[] };
type EdgeRow = { id: string; from_node: string; to_node: string; technique: string; cost: number };

export default function KillChains() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [selected, setSelected] = useState<string>("");
  const [chains, setChains] = useState<Chain[]>([]);
  const [nodes, setNodes] = useState<NodeRow[]>([]);
  const [edges, setEdges] = useState<EdgeRow[]>([]);
  const [building, setBuilding] = useState(false);

  useEffect(() => {
    supabase.from("target_workspaces").select("id,name,domain").order("created_at", { ascending: false }).then(({ data }) => {
      const t = (data || []) as Target[];
      setTargets(t);
      if (t.length && !selected) setSelected(t[0].id);
    });
  }, []);

  const load = async (tid: string) => {
    const [c, n, e] = await Promise.all([
      supabase.from("kill_chains").select("*").eq("target_id", tid).order("total_cost"),
      supabase.from("attack_graph_nodes").select("id,node_type,label,capability_tags").eq("target_id", tid),
      supabase.from("attack_graph_edges").select("id,from_node,to_node,technique,cost").eq("target_id", tid),
    ]);
    setChains((c.data || []) as Chain[]);
    setNodes((n.data || []) as NodeRow[]);
    setEdges((e.data || []) as EdgeRow[]);
  };

  useEffect(() => { if (selected) load(selected); }, [selected]);

  const build = async () => {
    if (!selected) return;
    setBuilding(true);
    try {
      const { data, error } = await supabase.functions.invoke("kill-chain-graph", { body: { targetId: selected } });
      if (error) throw error;
      toast.success(`Graph built: ${data?.nodes ?? 0} nodes, ${data?.edges ?? 0} edges, ${data?.chains ?? 0} chains`);
      await load(selected);
    } catch (e: any) {
      toast.error(e.message || "Failed");
    } finally { setBuilding(false); }
  };

  const runChain = async (c: Chain) => {
    toast.info(`Queuing chain "${c.goal.slice(0, 40)}"…`);
    const steps = c.step_plan.filter(s => s.order > 0).map((s, i) => ({
      name: `step-${i}`, method: "GET", url: "{{base}}",
    }));
    await supabase.functions.invoke("exploit-chain-runner", {
      body: { targetId: c.target_id, chainName: c.goal.slice(0, 80), steps },
    });
    toast.success("Chain dispatched — check Neural Log");
  };

  const sevColor = (s: string) => s === "critical" ? "bg-destructive/20 text-destructive border-destructive/40"
    : s === "high" ? "bg-orange-500/20 text-orange-400 border-orange-500/40"
    : "bg-yellow-500/20 text-yellow-400 border-yellow-500/40";

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold font-mono text-primary text-glow-green flex items-center gap-2">
            <GitBranch className="h-6 w-6" /> KILL-CHAIN GRAPH
          </h1>
          <p className="text-xs text-muted-foreground font-mono mt-1">
            Dijkstra-shortest exploit paths from anonymous attacker → critical impact, fused across every finding
          </p>
        </div>
        <div className="flex gap-2">
          <select className="bg-background border border-border rounded px-3 py-2 text-sm font-mono"
            value={selected} onChange={e => setSelected(e.target.value)}>
            {targets.map(t => <option key={t.id} value={t.id}>{t.name} — {t.domain}</option>)}
          </select>
          <Button onClick={build} disabled={!selected || building} className="font-mono">
            {building ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <GitBranch className="h-4 w-4 mr-2" />}
            Rebuild Graph
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <Card className="border-primary/30">
          <CardHeader className="pb-2"><CardTitle className="text-xs font-mono text-muted-foreground">NODES</CardTitle></CardHeader>
          <CardContent><div className="text-3xl font-bold text-primary font-mono">{nodes.length}</div></CardContent>
        </Card>
        <Card className="border-primary/30">
          <CardHeader className="pb-2"><CardTitle className="text-xs font-mono text-muted-foreground">EDGES</CardTitle></CardHeader>
          <CardContent><div className="text-3xl font-bold text-primary font-mono">{edges.length}</div></CardContent>
        </Card>
        <Card className="border-destructive/40">
          <CardHeader className="pb-2"><CardTitle className="text-xs font-mono text-muted-foreground">EXPLOIT PATHS</CardTitle></CardHeader>
          <CardContent><div className="text-3xl font-bold text-destructive font-mono">{chains.length}</div></CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader><CardTitle className="font-mono text-sm">RANKED KILL-CHAINS (lowest cost = easiest exploit)</CardTitle></CardHeader>
        <CardContent>
          {chains.length === 0 && (
            <div className="text-sm text-muted-foreground font-mono py-8 text-center">
              No chains yet. Click "Rebuild Graph" after running a scan to synthesize attack paths.
            </div>
          )}
          <div className="space-y-3">
            {chains.map(c => (
              <div key={c.id} className="border border-border rounded p-4 hover:border-primary/50 transition-colors">
                <div className="flex items-start justify-between mb-2">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <Badge className={`${sevColor(c.severity)} font-mono uppercase text-[10px]`}>{c.severity}</Badge>
                      <span className="font-mono text-xs text-muted-foreground">cost {c.total_cost}</span>
                      <span className="font-mono text-xs text-muted-foreground">• {c.step_plan.length} steps</span>
                    </div>
                    <div className="font-mono text-sm text-foreground">{c.goal}</div>
                  </div>
                  <Button size="sm" variant="outline" onClick={() => runChain(c)} className="font-mono text-xs">
                    <Play className="h-3 w-3 mr-1" /> Execute
                  </Button>
                </div>
                <div className="mt-3 flex flex-wrap items-center gap-1 text-xs font-mono">
                  {c.step_plan.map((s, i) => (
                    <div key={i} className="flex items-center gap-1">
                      <span className="px-2 py-1 rounded bg-primary/10 border border-primary/30 text-primary">
                        {s.node_type}: {s.node.slice(0, 50)}
                      </span>
                      {i < c.step_plan.length - 1 && <ChevronRight className="h-3 w-3 text-muted-foreground" />}
                    </div>
                  ))}
                </div>
                {c.step_plan.length > 1 && (
                  <div className="mt-2 text-[11px] text-muted-foreground font-mono">
                    techniques: {c.step_plan.slice(1).map(s => s.technique).join(" → ")}
                  </div>
                )}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
