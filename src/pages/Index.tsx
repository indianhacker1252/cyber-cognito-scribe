import { Crosshair, Globe, Clock, ShieldAlert } from "lucide-react";
import { StatCard } from "@/components/StatCard";
import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { Badge } from "@/components/ui/badge";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, ResponsiveContainer, Cell } from "recharts";

const severityColors: Record<string, string> = {
  critical: "hsl(0, 100%, 60%)",
  high: "hsl(20, 100%, 55%)",
  medium: "hsl(40, 100%, 55%)",
  low: "hsl(160, 100%, 45%)",
  info: "hsl(200, 100%, 50%)",
};

export default function Index() {
  const { data: targets } = useQuery({
    queryKey: ["targets"],
    queryFn: async () => {
      const { data } = await supabase.from("target_workspaces").select("*");
      return data || [];
    },
  });

  const { data: endpoints } = useQuery({
    queryKey: ["endpoints-count"],
    queryFn: async () => {
      const { count } = await supabase.from("discovered_endpoints").select("*", { count: "exact", head: true });
      return count || 0;
    },
  });

  const { data: findings } = useQuery({
    queryKey: ["findings"],
    queryFn: async () => {
      const { data } = await supabase.from("vulnerability_findings").select("*");
      return data || [];
    },
  });

  const { data: pendingTasks } = useQuery({
    queryKey: ["pending-tasks"],
    queryFn: async () => {
      const { count } = await supabase.from("agent_tasks").select("*", { count: "exact", head: true }).eq("status", "pending");
      return count || 0;
    },
  });

  const { data: recentLogs } = useQuery({
    queryKey: ["recent-logs"],
    queryFn: async () => {
      const { data } = await supabase.from("scan_logs").select("*").order("created_at", { ascending: false }).limit(10);
      return data || [];
    },
  });

  const activeTargets = targets?.filter((t) => t.status === "scanning").length || 0;
  const criticalFindings = findings?.filter((f) => f.severity === "critical").length || 0;

  const severityData = ["critical", "high", "medium", "low", "info"].map((sev) => ({
    name: sev.charAt(0).toUpperCase() + sev.slice(1),
    count: findings?.filter((f) => f.severity === sev).length || 0,
    color: severityColors[sev],
  }));

  const logTypeColor: Record<string, string> = {
    thought: "text-cyber-cyan",
    action: "text-cyber-green",
    result: "text-cyber-amber",
    error: "text-destructive",
    info: "text-muted-foreground",
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold font-mono text-primary text-glow-green">Command Center</h1>
        <p className="text-xs font-mono text-muted-foreground">Real-time operational overview</p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard title="Active Targets" value={activeTargets} icon={Crosshair} variant="green" />
        <StatCard title="Endpoints Mapped" value={endpoints || 0} icon={Globe} variant="cyan" />
        <StatCard title="Pending Tasks" value={pendingTasks || 0} icon={Clock} variant="amber" />
        <StatCard title="Critical Vulns" value={criticalFindings} icon={ShieldAlert} variant="red" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity Chart */}
        <div className="rounded-lg border border-border bg-card p-4">
          <h2 className="text-xs font-mono uppercase tracking-wider text-muted-foreground mb-4">Vulnerability Breakdown</h2>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityData}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(220, 15%, 12%)" />
                <XAxis dataKey="name" tick={{ fill: "hsl(220, 10%, 50%)", fontSize: 10, fontFamily: "JetBrains Mono" }} />
                <YAxis tick={{ fill: "hsl(220, 10%, 50%)", fontSize: 10, fontFamily: "JetBrains Mono" }} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {severityData.map((entry, index) => (
                    <Cell key={index} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Recent Activity */}
        <div className="rounded-lg border border-border bg-card p-4">
          <h2 className="text-xs font-mono uppercase tracking-wider text-muted-foreground mb-4">Recent Activity</h2>
          <div className="space-y-2 max-h-48 overflow-auto">
            {recentLogs && recentLogs.length > 0 ? (
              recentLogs.map((log) => (
                <div key={log.id} className="flex items-start gap-2 text-xs font-mono border-b border-border/50 pb-2">
                  <Badge variant="outline" className={`text-[9px] ${logTypeColor[log.log_type] || "text-muted-foreground"}`}>
                    {log.log_type}
                  </Badge>
                  <span className="text-card-foreground truncate">{log.message}</span>
                </div>
              ))
            ) : (
              <p className="text-xs font-mono text-muted-foreground">No recent activity. Add targets to begin scanning.</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
