import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Activity, Wifi, WifiOff, RefreshCw, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { useState } from "react";

interface AgentStatus {
  id: string;
  target_id: string;
  task_type: string;
  status: string;
  created_at: string;
  updated_at: string;
  target_name?: string;
}

export default function SystemHealth() {
  const [refreshing, setRefreshing] = useState<Set<string>>(new Set());

  const { data: agents, isLoading, refetch } = useQuery({
    queryKey: ["agent-health"],
    queryFn: async () => {
      const { data } = await supabase
        .from("agent_tasks")
        .select("*, target_workspaces(name)")
        .order("updated_at", { ascending: false });
      return (data || []).map((a: any) => ({
        ...a,
        target_name: a.target_workspaces?.name,
      })) as AgentStatus[];
    },
    refetchInterval: 10000,
  });

  const { data: evidenceCount } = useQuery({
    queryKey: ["evidence-count"],
    queryFn: async () => {
      const { count } = await supabase.from("evidence_packages").select("*", { count: "exact", head: true });
      return count || 0;
    },
  });

  const getHeartbeat = (updatedAt: string) => {
    const diff = Date.now() - new Date(updatedAt).getTime();
    if (diff < 60000) return { label: "Active", color: "bg-cyber-green", textColor: "text-cyber-green" };
    if (diff < 300000) return { label: "Idle", color: "bg-cyber-amber", textColor: "text-cyber-amber" };
    return { label: "Stale", color: "bg-muted-foreground", textColor: "text-muted-foreground" };
  };

  const terminateAgent = async (id: string) => {
    const { error } = await supabase.from("agent_tasks").update({ status: "failed" as any }).eq("id", id);
    if (error) {
      toast.error("Failed to terminate agent");
    } else {
      toast.success("Agent terminated");
      refetch();
    }
  };

  const statusBadge: Record<string, string> = {
    pending: "bg-cyber-amber/20 text-cyber-amber border-cyber-amber/30",
    running: "bg-cyber-cyan/20 text-cyber-cyan border-cyber-cyan/30",
    completed: "bg-cyber-green/20 text-cyber-green border-cyber-green/30",
    failed: "bg-destructive/20 text-destructive border-destructive/30",
  };

  const runningCount = agents?.filter((a) => a.status === "running").length || 0;
  const completedCount = agents?.filter((a) => a.status === "completed").length || 0;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold font-mono text-primary text-glow-green">System Health</h1>
          <p className="text-xs font-mono text-muted-foreground">Agent management & audit endpoint monitoring</p>
        </div>
        <Button variant="outline" size="sm" className="font-mono text-xs gap-1" onClick={() => refetch()}>
          <RefreshCw className="h-3 w-3" /> Refresh
        </Button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="rounded-lg border border-border bg-card p-4">
          <p className="text-[10px] font-mono uppercase text-muted-foreground">Active Agents</p>
          <p className="text-2xl font-bold font-mono text-cyber-cyan">{runningCount}</p>
        </div>
        <div className="rounded-lg border border-border bg-card p-4">
          <p className="text-[10px] font-mono uppercase text-muted-foreground">Completed Tasks</p>
          <p className="text-2xl font-bold font-mono text-cyber-green">{completedCount}</p>
        </div>
        <div className="rounded-lg border border-border bg-card p-4">
          <p className="text-[10px] font-mono uppercase text-muted-foreground">Evidence Packages</p>
          <p className="text-2xl font-bold font-mono text-cyber-amber">{evidenceCount || 0}</p>
        </div>
      </div>

      {/* Agent List */}
      {isLoading ? (
        <p className="text-xs font-mono text-muted-foreground">Loading agents...</p>
      ) : agents && agents.length > 0 ? (
        <div className="space-y-2">
          {agents.map((agent) => {
            const heartbeat = getHeartbeat(agent.updated_at);
            return (
              <div
                key={agent.id}
                className="rounded-lg border border-border bg-card p-4 flex items-center justify-between hover:border-primary/30 transition-colors"
              >
                <div className="flex items-center gap-3">
                  <div className="relative">
                    {heartbeat.label === "Active" ? (
                      <Wifi className={`h-4 w-4 ${heartbeat.textColor}`} />
                    ) : (
                      <WifiOff className={`h-4 w-4 ${heartbeat.textColor}`} />
                    )}
                    <span className={`absolute -top-0.5 -right-0.5 h-2 w-2 rounded-full ${heartbeat.color} ${heartbeat.label === "Active" ? "animate-pulse" : ""}`} />
                  </div>
                  <div>
                    <p className="text-sm font-mono font-semibold text-card-foreground">
                      {agent.task_type}
                    </p>
                    <p className="text-[10px] font-mono text-muted-foreground">
                      {agent.target_name || "Unknown"} • {new Date(agent.updated_at).toLocaleTimeString()}
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant="outline" className={`text-[9px] font-mono ${heartbeat.label === "Active" ? "bg-cyber-green/20 text-cyber-green border-cyber-green/30" : heartbeat.label === "Idle" ? "bg-cyber-amber/20 text-cyber-amber border-cyber-amber/30" : "text-muted-foreground"}`}>
                    {heartbeat.label}
                  </Badge>
                  <Badge variant="outline" className={`text-[9px] font-mono ${statusBadge[agent.status]}`}>
                    {agent.status}
                  </Badge>
                  {(agent.status === "running" || agent.status === "pending") && (
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7 text-muted-foreground hover:text-destructive"
                      onClick={() => terminateAgent(agent.id)}
                    >
                      <Trash2 className="h-3 w-3" />
                    </Button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <div className="text-center py-12 border border-dashed border-border rounded-lg">
          <Activity className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
          <p className="text-xs font-mono text-muted-foreground">No agent tasks yet. Run scans to create agents.</p>
        </div>
      )}
    </div>
  );
}
