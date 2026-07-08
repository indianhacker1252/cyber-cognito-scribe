import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { useEffect } from "react";
import { Activity } from "lucide-react";

// Header chip that shows global scan_jobs counts (running / queued / failed last hour).
// Updates every 8s + on realtime INSERT/UPDATE.
export function GlobalJobChip() {
  const q = useQuery({
    queryKey: ["global-job-counts"],
    queryFn: async () => {
      const hourAgo = new Date(Date.now() - 3600_000).toISOString();
      const [{ count: running }, { count: queued }, { count: failed }] = await Promise.all([
        supabase.from("scan_jobs" as any).select("id", { count: "exact", head: true }).eq("status", "running"),
        supabase.from("scan_jobs" as any).select("id", { count: "exact", head: true }).eq("status", "queued"),
        supabase.from("scan_jobs" as any).select("id", { count: "exact", head: true }).eq("status", "failed").gte("completed_at", hourAgo),
      ]);
      return { running: running || 0, queued: queued || 0, failed: failed || 0 };
    },
    refetchInterval: 8000,
  });

  useEffect(() => {
    const ch = supabase
      .channel("global-jobs-rt")
      .on("postgres_changes", { event: "*", schema: "public", table: "scan_jobs" }, () => q.refetch())
      .subscribe();
    return () => { supabase.removeChannel(ch); };
  }, [q]);

  const { running = 0, queued = 0, failed = 0 } = q.data || {};
  const active = running > 0 || queued > 0;
  return (
    <div
      className={`hidden md:flex items-center gap-1.5 rounded border px-2 py-0.5 font-mono text-[10px] ${
        active ? "border-cyber-cyan/40 text-cyber-cyan" : "border-border text-muted-foreground"
      }`}
      title={`${running} running · ${queued} queued · ${failed} failed (1h)`}
    >
      <Activity className={`h-3 w-3 ${active ? "animate-pulse" : ""}`} />
      <span className="text-cyber-green">{running}▶</span>
      <span className="text-cyber-amber">{queued}⏳</span>
      {failed > 0 && <span className="text-destructive">{failed}✗</span>}
    </div>
  );
}
