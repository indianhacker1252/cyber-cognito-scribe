import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Play, Square, RefreshCw, Loader2 } from "lucide-react";
import { toast } from "sonner";

const PHASES = ["recon", "discovery", "owasp_matrix", "deep_modules", "exploit", "chain", "report"] as const;

const phaseColor: Record<string, string> = {
  complete: "bg-cyber-green/20 text-cyber-green border-cyber-green/40",
  running: "bg-cyber-cyan/20 text-cyber-cyan border-cyber-cyan/40 animate-pulse",
  failed: "bg-destructive/20 text-destructive border-destructive/40",
  pending: "bg-muted text-muted-foreground border-border",
};

// Per-target scan control: phase progress + job counts + start/abort/restart buttons.
// Reads scan_phase_state + scan_jobs. Realtime-updated.
export function ScanControl({ targetId, targetDomain }: { targetId: string; targetDomain?: string }) {
  const qc = useQueryClient();

  const phases = useQuery({
    queryKey: ["phase-state", targetId],
    queryFn: async () => {
      const { data } = await supabase
        .from("scan_phase_state" as any)
        .select("phase,status,last_heartbeat,checks_attempted,findings_count")
        .eq("target_id", targetId);
      return (data || []) as any[];
    },
    refetchInterval: 5000,
  });

  const jobs = useQuery({
    queryKey: ["job-counts", targetId],
    queryFn: async () => {
      const [r, q, d, f] = await Promise.all([
        supabase.from("scan_jobs" as any).select("id", { count: "exact", head: true }).eq("target_id", targetId).eq("status", "running"),
        supabase.from("scan_jobs" as any).select("id", { count: "exact", head: true }).eq("target_id", targetId).eq("status", "queued"),
        supabase.from("scan_jobs" as any).select("id", { count: "exact", head: true }).eq("target_id", targetId).eq("status", "done"),
        supabase.from("scan_jobs" as any).select("id", { count: "exact", head: true }).eq("target_id", targetId).eq("status", "failed"),
      ]);
      return { running: r.count || 0, queued: q.count || 0, done: d.count || 0, failed: f.count || 0 };
    },
    refetchInterval: 5000,
  });

  useEffect(() => {
    const ch = supabase
      .channel(`scan-ctl-${targetId}`)
      .on("postgres_changes", { event: "*", schema: "public", table: "scan_phase_state", filter: `target_id=eq.${targetId}` }, () => phases.refetch())
      .on("postgres_changes", { event: "*", schema: "public", table: "scan_jobs", filter: `target_id=eq.${targetId}` }, () => jobs.refetch())
      .subscribe();
    return () => { supabase.removeChannel(ch); };
  }, [targetId, phases, jobs]);

  const phaseMap = new Map((phases.data || []).map((p: any) => [p.phase, p]));
  const completed = PHASES.filter((p) => (phaseMap.get(p) as any)?.status === "complete").length;
  const pct = Math.round((completed / PHASES.length) * 100);
  const activePhase = PHASES.find((p) => (phaseMap.get(p) as any)?.status === "running");

  const startScan = useMutation({
    mutationFn: async () => {
      const { error } = await supabase.functions.invoke("recon-engine", { body: { targetId } });
      if (error) throw error;
    },
    onSuccess: () => { toast.success("Scan started — pipeline will auto-chain"); qc.invalidateQueries({ queryKey: ["phase-state", targetId] }); },
    onError: (e: any) => {
      const m = (e?.message || "").toLowerCase();
      if (m.includes("timeout") || m.includes("failed to fetch")) toast.info("Recon running in background");
      else toast.error(`Start failed: ${e.message}`);
    },
  });

  const abortScan = useMutation({
    mutationFn: async () => {
      const { data, error } = await supabase.rpc("abort_target_scan" as any, { _target_id: targetId });
      if (error) throw error;
      return data;
    },
    onSuccess: (r: any) => {
      toast.success(`Aborted: ${r?.jobs_cancelled ?? 0} jobs cancelled, ${r?.phases_reset ?? 0} phases reset`);
      qc.invalidateQueries({ queryKey: ["phase-state", targetId] });
      qc.invalidateQueries({ queryKey: ["job-counts", targetId] });
    },
    onError: (e: any) => toast.error(`Abort failed: ${e.message}`),
  });

  const restartScan = useMutation({
    mutationFn: async () => {
      await supabase.rpc("abort_target_scan" as any, { _target_id: targetId });
      const { error } = await supabase.functions.invoke("recon-engine", { body: { targetId } });
      if (error && !/timeout|failed to fetch/i.test(error.message)) throw error;
    },
    onSuccess: () => toast.success("Scan restarted from recon"),
    onError: (e: any) => toast.error(`Restart failed: ${e.message}`),
  });

  const resumeMissing = useMutation({
    mutationFn: async () => {
      const { data, error } = await supabase.functions.invoke("phase-arbiter", { body: { action: "resume", targetId } });
      if (error) throw error;
      return data;
    },
    onSuccess: (r: any) => {
      const n = Object.values(r?.resumed || {}).reduce((a: number, b: any) => a + (b || 0), 0);
      toast.success(`Resumed ${n} missing modules`);
    },
    onError: (e: any) => toast.error(`Resume failed: ${e.message}`),
  });

  const j = jobs.data || { running: 0, queued: 0, done: 0, failed: 0 };
  const busy = startScan.isPending || abortScan.isPending || restartScan.isPending || resumeMissing.isPending;

  return (
    <div className="rounded border border-border bg-card p-3 space-y-2">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="min-w-0">
          <p className="text-[10px] font-mono text-muted-foreground uppercase">Scan Control</p>
          <p className="text-xs font-mono text-foreground truncate">{targetDomain || targetId.slice(0, 8)}</p>
        </div>
        <div className="flex items-center gap-1">
          <Button size="sm" variant="outline" className="h-7 text-[10px] gap-1" onClick={() => startScan.mutate()} disabled={busy || !!activePhase}>
            {startScan.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Play className="h-3 w-3" />} Start
          </Button>
          <Button size="sm" variant="outline" className="h-7 text-[10px] gap-1" onClick={() => resumeMissing.mutate()} disabled={busy}>
            <RefreshCw className={`h-3 w-3 ${resumeMissing.isPending ? "animate-spin" : ""}`} /> Resume
          </Button>
          <Button size="sm" variant="outline" className="h-7 text-[10px] gap-1" onClick={() => restartScan.mutate()} disabled={busy}>
            <RefreshCw className="h-3 w-3" /> Restart
          </Button>
          <Button
            size="sm" variant="outline"
            className="h-7 text-[10px] gap-1 border-destructive/30 text-destructive hover:bg-destructive/10"
            onClick={() => { if (confirm("Abort all running/queued jobs for this target?")) abortScan.mutate(); }}
            disabled={busy}
          >
            <Square className="h-3 w-3" /> Abort
          </Button>
        </div>
      </div>

      <div>
        <div className="flex items-center justify-between text-[10px] font-mono text-muted-foreground mb-1">
          <span>{completed}/{PHASES.length} phases {activePhase && <span className="text-cyber-cyan">· {activePhase} running</span>}</span>
          <span>{pct}%</span>
        </div>
        <Progress value={pct} className="h-1.5" />
      </div>

      <div className="flex flex-wrap gap-1">
        {PHASES.map((p) => {
          const state = (phaseMap.get(p) as any)?.status || "pending";
          const attempts = (phaseMap.get(p) as any)?.checks_attempted || 0;
          const findings = (phaseMap.get(p) as any)?.findings_count || 0;
          return (
            <span
              key={p}
              className={`text-[9px] font-mono px-1.5 py-0.5 rounded border ${phaseColor[state]}`}
              title={`${p}: ${state} · ${attempts} attempts · ${findings} findings`}
            >
              {p}
            </span>
          );
        })}
      </div>

      <div className="flex flex-wrap gap-1 text-[10px] font-mono">
        <Badge variant="outline" className="text-cyber-green border-cyber-green/40">▶ {j.running}</Badge>
        <Badge variant="outline" className="text-cyber-amber border-cyber-amber/40">⏳ {j.queued}</Badge>
        <Badge variant="outline" className="text-muted-foreground">✓ {j.done}</Badge>
        {j.failed > 0 && <Badge variant="outline" className="text-destructive border-destructive/40">✗ {j.failed}</Badge>}
      </div>
    </div>
  );
}
