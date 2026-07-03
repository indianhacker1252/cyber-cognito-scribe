import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Activity, Wifi, WifiOff, RefreshCw, Trash2, TestTube2, StopCircle, ListChecks } from "lucide-react";
import { toast } from "sonner";
import { useState } from "react";

interface ScanJob {
  id: string;
  target_id: string;
  job_type: string;
  status: string;
  priority: number;
  attempts: number;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
  target_name?: string;
}

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
  const queryClient = useQueryClient();

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

  const clearTasks = useMutation({
    mutationFn: async () => {
      const { error } = await supabase.from("agent_tasks").delete().neq("id", "00000000-0000-0000-0000-000000000000");
      if (error) throw error;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["agent-health"] });
      toast.success("All task history cleared");
    },
  });

  const clearEvidence = useMutation({
    mutationFn: async () => {
      const { error } = await supabase.from("evidence_packages").delete().neq("id", "00000000-0000-0000-0000-000000000000");
      if (error) throw error;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["evidence-count"] });
      toast.success("All evidence packages cleared");
    },
  });

  const { data: scanJobs, refetch: refetchJobs } = useQuery({
    queryKey: ["scan-jobs-active"],
    queryFn: async () => {
      const { data } = await supabase
        .from("scan_jobs" as any)
        .select("id,target_id,job_type,status,priority,attempts,created_at,started_at,completed_at,error_message, target_workspaces(name,domain)")
        .in("status", ["queued", "running"])
        .order("priority", { ascending: false })
        .order("created_at", { ascending: true })
        .limit(500);
      return ((data as any[]) || []).map((j) => ({
        ...j,
        target_name: j.target_workspaces?.name || j.target_workspaces?.domain,
      })) as ScanJob[];
    },
    refetchInterval: 5000,
  });

  const { data: jobCounts } = useQuery({
    queryKey: ["scan-job-counts"],
    queryFn: async () => {
      const { data } = await supabase
        .from("scan_jobs" as any)
        .select("target_id,status,target_workspaces(name,domain)")
        .limit(20000);
      const map: Record<string, { name: string; queued: number; running: number; done: number; failed: number; total: number }> = {};
      for (const row of (data as any[]) || []) {
        const id = row.target_id;
        if (!map[id]) map[id] = { name: row.target_workspaces?.name || row.target_workspaces?.domain || id.slice(0, 8), queued: 0, running: 0, done: 0, failed: 0, total: 0 };
        map[id].total++;
        if (row.status === "queued") map[id].queued++;
        else if (row.status === "running") map[id].running++;
        else if (row.status === "completed") map[id].done++;
        else if (row.status === "failed") map[id].failed++;
      }
      return map;
    },
    refetchInterval: 8000,
  });

  const cancelJob = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await supabase.from("scan_jobs" as any).update({ status: "failed", completed_at: new Date().toISOString(), error_message: "cancelled by user" }).eq("id", id);
      if (error) throw error;
    },
    onSuccess: () => { toast.success("Job cancelled"); refetchJobs(); queryClient.invalidateQueries({ queryKey: ["scan-job-counts"] }); },
    onError: (e: any) => toast.error(`Cancel failed: ${e.message}`),
  });

  const deleteJob = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await supabase.from("scan_jobs" as any).delete().eq("id", id);
      if (error) throw error;
    },
    onSuccess: () => { toast.success("Job deleted — AI credits saved"); refetchJobs(); queryClient.invalidateQueries({ queryKey: ["scan-job-counts"] }); },
    onError: (e: any) => toast.error(`Delete failed: ${e.message}`),
  });

  const cancelTargetJobs = useMutation({
    mutationFn: async (targetId: string) => {
      const { error } = await supabase.from("scan_jobs" as any)
        .update({ status: "failed", completed_at: new Date().toISOString(), error_message: "cancelled by user (bulk)" })
        .eq("target_id", targetId).in("status", ["queued", "running"]);
      if (error) throw error;
    },
    onSuccess: () => { toast.success("Cancelled all pending jobs for target"); refetchJobs(); queryClient.invalidateQueries({ queryKey: ["scan-job-counts"] }); },
    onError: (e: any) => toast.error(`Bulk cancel failed: ${e.message}`),
  });

  const purgeAll = useMutation({
    mutationFn: async () => {
      const { data, error } = await supabase.rpc("purge_history" as any, { _target_id: null, _scope: "all" });
      if (error) throw error;
      return data as any;
    },
    onSuccess: (data: any) => {
      queryClient.invalidateQueries();
      const totals = data?.deleted ? Object.entries(data.deleted).slice(0, 6).map(([k, v]) => `${k}:${v}`).join(", ") : "";
      toast.success(`🧹 Purged. ${totals}`);
    },
    onError: (e: any) => toast.error(`Purge failed: ${e.message}`),
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

  const deleteAgent = async (id: string) => {
    const { error } = await supabase.from("agent_tasks").delete().eq("id", id);
    if (error) {
      toast.error("Failed to delete task");
    } else {
      toast.success("Task deleted");
      queryClient.invalidateQueries({ queryKey: ["agent-health"] });
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
        <div className="flex gap-2">
          <Button
            variant="outline" size="sm"
            className="font-mono text-xs gap-1 text-cyber-cyan border-cyber-cyan/30 hover:bg-cyber-cyan/10"
            onClick={async () => {
              toast.info("Running E2E SelfTest against testphp.vulnweb.com…");
              const { data, error } = await supabase.functions.invoke("e2e-selftest", { body: {} });
              if (error) { toast.error(`SelfTest failed: ${error.message}`); return; }
              const pass = (data as any)?.allPass;
              toast[pass ? "success" : "error"](pass
                ? "✅ All 5 assertions passed — pipeline is alive"
                : `❌ Some assertions failed — see Neural Log`);
            }}
          >
            <TestTube2 className="h-3 w-3" /> Run E2E SelfTest
          </Button>
          <Button variant="outline" size="sm" className="font-mono text-xs gap-1" onClick={() => refetch()}>
            <RefreshCw className="h-3 w-3" /> Refresh
          </Button>
          <Button
            variant="outline" size="sm"
            className="font-mono text-[10px] gap-1 text-destructive border-destructive/50 hover:bg-destructive/10"
            onClick={() => {
              if (confirm("🔥 PURGE EVERYTHING from database (logs, jobs, debates, variants, evidence, findings, chat)? This frees memory but cannot be undone.")) {
                purgeAll.mutate();
              }
            }}
            disabled={purgeAll.isPending}
          >
            <Trash2 className="h-3 w-3" /> {purgeAll.isPending ? "Purging…" : "Purge All History"}
          </Button>
          {agents && agents.length > 0 && (
            <Button
              variant="outline" size="sm"
              className="font-mono text-[10px] gap-1 text-destructive border-destructive/30 hover:bg-destructive/10"
              onClick={() => { if (confirm("Clear all task history?")) clearTasks.mutate(); }}
            >
              <Trash2 className="h-3 w-3" /> Clear Tasks
            </Button>
          )}
          {(evidenceCount || 0) > 0 && (
            <Button
              variant="outline" size="sm"
              className="font-mono text-[10px] gap-1 text-destructive border-destructive/30 hover:bg-destructive/10"
              onClick={() => { if (confirm("Clear all evidence packages?")) clearEvidence.mutate(); }}
            >
              <Trash2 className="h-3 w-3" /> Clear Evidence
            </Button>
          )}
        </div>
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

      {/* Per-Target Scan Progress */}
      {jobCounts && Object.keys(jobCounts).length > 0 && (
        <div className="rounded-lg border border-border bg-card p-4 space-y-3">
          <div className="flex items-center gap-2">
            <ListChecks className="h-4 w-4 text-cyber-cyan" />
            <p className="text-xs font-mono uppercase text-cyber-cyan">Scan Progress by Target</p>
          </div>
          <div className="space-y-2">
            {Object.entries(jobCounts).map(([tid, c]) => {
              const pending = c.queued + c.running;
              const finished = c.done + c.failed;
              const pct = c.total ? Math.round((finished / c.total) * 100) : 0;
              const state = c.running > 0 ? "running" : c.queued > 0 ? "queued" : "idle";
              return (
                <div key={tid} className="border border-border rounded p-2 space-y-1">
                  <div className="flex items-center justify-between text-[11px] font-mono">
                    <span className="truncate">{c.name}</span>
                    <div className="flex items-center gap-1 shrink-0">
                      <Badge variant="outline" className={`text-[9px] ${state === "running" ? "text-cyber-cyan border-cyber-cyan/40" : state === "queued" ? "text-cyber-amber border-cyber-amber/40" : "text-muted-foreground"}`}>
                        {state}
                      </Badge>
                      <span className="text-muted-foreground">{finished}/{c.total} ({pct}%)</span>
                      {pending > 0 && (
                        <Button
                          size="sm" variant="ghost"
                          className="h-6 px-2 text-[10px] text-destructive hover:bg-destructive/10"
                          onClick={() => { if (confirm(`Cancel ${pending} pending job(s) for ${c.name}? Frees AI credits.`)) cancelTargetJobs.mutate(tid); }}
                        >
                          <StopCircle className="h-3 w-3 mr-1" /> Cancel {pending}
                        </Button>
                      )}
                    </div>
                  </div>
                  <Progress value={pct} className="h-1.5" />
                  <div className="flex gap-3 text-[10px] font-mono text-muted-foreground">
                    <span className="text-cyber-cyan">▶ {c.running} running</span>
                    <span className="text-cyber-amber">⏳ {c.queued} queued</span>
                    <span className="text-cyber-green">✓ {c.done} done</span>
                    <span className="text-destructive">✗ {c.failed} failed</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Live Job Queue */}
      {scanJobs && scanJobs.length > 0 && (
        <div className="rounded-lg border border-border bg-card p-4 space-y-2">
          <div className="flex items-center justify-between">
            <p className="text-xs font-mono uppercase text-cyber-cyan">Live Job Queue ({scanJobs.length})</p>
            <p className="text-[10px] font-mono text-muted-foreground">Delete unwanted jobs to save AI credits</p>
          </div>
          <div className="space-y-1 max-h-96 overflow-y-auto">
            {scanJobs.map((j) => (
              <div key={j.id} className="flex items-center justify-between gap-2 border border-border rounded px-2 py-1 text-[11px] font-mono">
                <div className="flex items-center gap-2 min-w-0">
                  <Badge variant="outline" className={`text-[9px] ${j.status === "running" ? "text-cyber-cyan border-cyber-cyan/40 animate-pulse" : "text-cyber-amber border-cyber-amber/40"}`}>
                    {j.status}
                  </Badge>
                  <span className="text-cyber-green">{j.job_type}</span>
                  <span className="text-muted-foreground truncate">· {j.target_name || j.target_id.slice(0, 8)}</span>
                  {j.attempts > 0 && <span className="text-[10px] text-cyber-amber">×{j.attempts}</span>}
                </div>
                <div className="flex items-center gap-1 shrink-0">
                  <span className="text-[10px] text-muted-foreground">{new Date(j.created_at).toLocaleTimeString()}</span>
                  {j.status === "running" && (
                    <Button size="icon" variant="ghost" className="h-6 w-6 text-cyber-amber hover:bg-cyber-amber/10"
                            onClick={() => cancelJob.mutate(j.id)} title="Cancel (mark failed)">
                      <StopCircle className="h-3 w-3" />
                    </Button>
                  )}
                  <Button size="icon" variant="ghost" className="h-6 w-6 text-destructive hover:bg-destructive/10"
                          onClick={() => deleteJob.mutate(j.id)} title="Delete job">
                    <Trash2 className="h-3 w-3" />
                  </Button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

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
                    <p className="text-sm font-mono font-semibold text-card-foreground">{agent.task_type}</p>
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
                      variant="ghost" size="icon"
                      className="h-7 w-7 text-muted-foreground hover:text-destructive"
                      onClick={() => terminateAgent(agent.id)}
                    >
                      <Trash2 className="h-3 w-3" />
                    </Button>
                  )}
                  {(agent.status === "completed" || agent.status === "failed") && (
                    <Button
                      variant="ghost" size="icon"
                      className="h-7 w-7 text-muted-foreground hover:text-destructive"
                      onClick={() => deleteAgent(agent.id)}
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
