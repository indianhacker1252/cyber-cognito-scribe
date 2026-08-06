import { useEffect, useRef, useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Pause, Play, Terminal, Trash2, Globe, Link, Bug, Shield, ChevronDown, ChevronRight, Target } from "lucide-react";
import { toast } from "sonner";
import { BrainPanel } from "@/components/BrainPanel";
import { MythosPanel } from "@/components/MythosPanel";

const logColors: Record<string, string> = {
  thought: "text-cyber-cyan",
  action: "text-cyber-green",
  result: "text-cyber-amber",
  error: "text-destructive",
  info: "text-muted-foreground",
};

const logPrefix: Record<string, string> = {
  thought: "[THOUGHT]",
  action: "[ACTION]",
  result: "[RESULT]",
  error: "[ERROR]",
  info: "[INFO]",
};

interface ScanLog {
  id: string;
  log_type: string;
  message: string;
  created_at: string;
  metadata: Record<string, unknown>;
  target_id: string | null;
}

const severityColor: Record<string, string> = {
  critical: "bg-destructive text-destructive-foreground",
  high: "bg-destructive/80 text-destructive-foreground",
  medium: "bg-cyber-amber/20 text-cyber-amber",
  low: "bg-muted text-muted-foreground",
  info: "bg-muted text-muted-foreground",
};

export default function NeuralLog() {
  const queryClient = useQueryClient();
  const [logs, setLogs] = useState<ScanLog[]>([]);
  const [paused, setPaused] = useState(false);
  const [showPanel, setShowPanel] = useState(true);
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    finding: true, endpoint: true, param: false,
  });
  const [selectedTarget, setSelectedTarget] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);

  // ─── Real DB queries for live data ───
  const { data: targets } = useQuery({
    queryKey: ["targets-list"],
    queryFn: async () => {
      const { data } = await supabase.from("target_workspaces").select("id, name, domain, status").order("created_at", { ascending: false });
      return data || [];
    },
  });

  // Auto-select the scanning target
  useEffect(() => {
    if (!selectedTarget && targets) {
      const scanning = targets.find(t => t.status === "scanning");
      if (scanning) setSelectedTarget(scanning.id);
      else if (targets.length > 0) setSelectedTarget(targets[0].id);
    }
  }, [targets, selectedTarget]);

  const { data: endpoints } = useQuery({
    queryKey: ["live-endpoints", selectedTarget],
    queryFn: async () => {
      if (!selectedTarget) return [];
      const { data } = await supabase.from("discovered_endpoints").select("id, url, method, parameters, status_code")
        .eq("target_id", selectedTarget).order("created_at", { ascending: false }).limit(100);
      return data || [];
    },
    enabled: !!selectedTarget,
    refetchInterval: 5000,
  });

  const { data: findings } = useQuery({
    queryKey: ["live-findings", selectedTarget],
    queryFn: async () => {
      if (!selectedTarget) return [];
      const { data } = await supabase.from("vulnerability_findings").select("id, title, severity, confidence_score, payload, validation_status")
        .eq("target_id", selectedTarget).order("created_at", { ascending: false }).limit(50);
      return data || [];
    },
    enabled: !!selectedTarget,
    refetchInterval: 5000,
  });

  const { data: approvals } = useQuery({
    queryKey: ["live-approvals", selectedTarget],
    queryFn: async () => {
      if (!selectedTarget) return [];
      const { data } = await supabase.from("pending_approvals").select("id, title, severity, finding_type, confidence_level, payload_used")
        .eq("target_id", selectedTarget).eq("status", "pending").order("created_at", { ascending: false }).limit(50);
      return data || [];
    },
    enabled: !!selectedTarget,
    refetchInterval: 5000,
  });

  // Extract unique params from endpoints
  const paramList = useMemo(() => {
    const params: Array<{ name: string; url: string; value: string }> = [];
    const seen = new Set<string>();
    for (const ep of (endpoints || [])) {
      const p = (ep.parameters as Record<string, string>) || {};
      for (const [k, v] of Object.entries(p)) {
        const key = `${k}@${ep.url}`;
        if (!seen.has(key)) {
          seen.add(key);
          params.push({ name: k, url: ep.url, value: String(v) });
        }
      }
    }
    return params;
  }, [endpoints]);

  // All findings merged (confirmed + pending)
  const allFindings = useMemo(() => {
    const merged: Array<{ id: string; title: string; severity: string; confidence: number; source: string }> = [];
    for (const f of (findings || [])) {
      merged.push({ id: f.id, title: f.title, severity: f.severity, confidence: f.confidence_score || 0, source: "confirmed" });
    }
    for (const a of (approvals || [])) {
      merged.push({ id: a.id, title: a.title, severity: a.severity, confidence: 0, source: "pending" });
    }
    return merged;
  }, [findings, approvals]);

  // ─── Logs ───
  const { data: initialLogs } = useQuery({
    queryKey: ["scan-logs"],
    queryFn: async () => {
      const { data } = await supabase.from("scan_logs").select("*").order("created_at", { ascending: true }).limit(500);
      return (data || []) as ScanLog[];
    },
  });

  useEffect(() => {
    if (initialLogs) setLogs(initialLogs);
  }, [initialLogs]);

  useEffect(() => {
    let channel: ReturnType<typeof supabase.channel> | null = null;
    let reconnectTimer: number | null = null;

    const subscribe = () => {
      // Build the channel and register listeners BEFORE calling subscribe()
      const ch = supabase.channel(`scan-logs-realtime-${Date.now()}`);
      ch.on("postgres_changes", { event: "INSERT", schema: "public", table: "scan_logs" }, (payload) => {
        if (!paused) setLogs(prev => [...prev, payload.new as ScanLog].slice(-1000));
      });
      ch.subscribe((status) => {
        if (status === "CHANNEL_ERROR" || status === "TIMED_OUT" || status === "CLOSED") {
          if (reconnectTimer) clearTimeout(reconnectTimer);
          reconnectTimer = setTimeout(() => {
            if (channel) supabase.removeChannel(channel);
            subscribe();
          }, 2000) as unknown as number;
        }
      });
      channel = ch;
    };

    // Re-subscribe when tab becomes visible again (long-poll resilience)
    const onVisible = () => {
      if (document.visibilityState === "visible" && channel) {
        supabase.removeChannel(channel);
        subscribe();
      }
    };
    document.addEventListener("visibilitychange", onVisible);

    subscribe();
    return () => {
      document.removeEventListener("visibilitychange", onVisible);
      if (reconnectTimer) clearTimeout(reconnectTimer);
      if (channel) supabase.removeChannel(channel);
    };
  }, [paused]);

  // Also listen for new findings/endpoints in realtime
  useEffect(() => {
    const ch1 = supabase.channel("live-findings-rt")
      .on("postgres_changes", { event: "INSERT", schema: "public", table: "vulnerability_findings" }, () => {
        queryClient.invalidateQueries({ queryKey: ["live-findings", selectedTarget] });
      })
      .subscribe();

    const ch2 = supabase.channel("live-endpoints-rt")
      .on("postgres_changes", { event: "INSERT", schema: "public", table: "discovered_endpoints" }, () => {
        queryClient.invalidateQueries({ queryKey: ["live-endpoints", selectedTarget] });
      })
      .subscribe();

    const ch3 = supabase.channel("live-approvals-rt")
      .on("postgres_changes", { event: "INSERT", schema: "public", table: "pending_approvals" }, () => {
        queryClient.invalidateQueries({ queryKey: ["live-approvals", selectedTarget] });
      })
      .subscribe();

    return () => {
      supabase.removeChannel(ch1);
      supabase.removeChannel(ch2);
      supabase.removeChannel(ch3);
    };
  }, [selectedTarget, queryClient]);

  useEffect(() => {
    if (!paused && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs, paused]);

  const clearDbLogs = useMutation({
    mutationFn: async () => {
      const { error } = await supabase.from("scan_logs").delete().neq("id", "00000000-0000-0000-0000-000000000000");
      if (error) throw error;
    },
    onSuccess: () => {
      setLogs([]);
      queryClient.invalidateQueries({ queryKey: ["scan-logs"] });
      toast.success("All logs cleared");
    },
    onError: (e) => toast.error(e.message),
  });

  const formatTime = (ts: string) => {
    const d = new Date(ts);
    return d.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
  };

  const toggleSection = (key: string) =>
    setExpandedSections(prev => ({ ...prev, [key]: !prev[key] }));

  return (
    <div className="space-y-4 h-full flex flex-col">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div>
          <h1 className="text-xl font-bold font-mono text-primary text-glow-green">Live Neural Log</h1>
          <p className="text-xs font-mono text-muted-foreground">Real-time AI agent activity stream</p>
        </div>
        <div className="flex gap-2 flex-wrap">
          {/* Target selector */}
          <select
            className="bg-background border border-border rounded px-2 py-1 font-mono text-xs text-card-foreground"
            value={selectedTarget || ""}
            onChange={e => setSelectedTarget(e.target.value || null)}
          >
            <option value="">All Targets</option>
            {(targets || []).map(t => (
              <option key={t.id} value={t.id}>
                {t.name} {t.status === "scanning" ? "⚡" : ""}
              </option>
            ))}
          </select>
          <Button variant="outline" size="sm" className="font-mono text-xs gap-1" onClick={() => setShowPanel(!showPanel)}>
            {showPanel ? "Hide" : "Show"} Discoveries
          </Button>
          <Button variant="outline" size="sm" className="font-mono text-xs gap-1" onClick={() => setPaused(!paused)}>
            {paused ? <Play className="h-3 w-3" /> : <Pause className="h-3 w-3" />}
            {paused ? "Resume" : "Pause"}
          </Button>
          <Button variant="outline" size="sm" className="font-mono text-xs gap-1" onClick={() => setLogs([])}>
            <Trash2 className="h-3 w-3" /> Clear
          </Button>
          <Button
            variant="outline" size="sm"
            className="font-mono text-xs gap-1 text-destructive border-destructive/30 hover:bg-destructive/10"
            onClick={() => { if (confirm("Delete all logs from database?")) clearDbLogs.mutate(); }}
          >
            <Trash2 className="h-3 w-3" /> Delete All
          </Button>
        </div>
      </div>

      <div className="flex-1 flex gap-3 min-h-0">
        {/* Main log stream */}
        <div
          ref={scrollRef}
          className={`${showPanel ? "flex-[2]" : "flex-1"} min-h-[400px] max-h-[calc(100vh-220px)] overflow-auto rounded-lg border border-border bg-background p-4 font-mono text-xs scanline`}
        >
          {logs.length > 0 ? (
            logs.map((log) => (
              <div key={log.id} className="flex gap-2 py-0.5 hover:bg-muted/30">
                <span className="text-muted-foreground shrink-0">{formatTime(log.created_at)}</span>
                <span className={`shrink-0 font-bold ${logColors[log.log_type] || "text-muted-foreground"}`}>
                  {logPrefix[log.log_type] || "[LOG]"}
                </span>
                <span className="text-card-foreground">{log.message}</span>
              </div>
            ))
          ) : (
            <div className="flex flex-col items-center justify-center h-full text-muted-foreground">
              <Terminal className="h-8 w-8 mb-2 opacity-30" />
              <p>Awaiting neural activity...</p>
              <p className="text-[10px] mt-1">Start a scan to see AI agent logs here</p>
            </div>
          )}
        </div>

        {/* Live Discoveries Panel — Real DB Data */}
        {showPanel && (
          <div className="flex-1 min-w-[280px] max-w-[400px] max-h-[calc(100vh-220px)] overflow-auto rounded-lg border border-border bg-background p-3 font-mono text-xs space-y-2">
            <div className="flex items-center justify-between mb-1">
              <span className="text-sm font-bold text-primary flex items-center gap-1">
                <Target className="h-3.5 w-3.5" /> Live Discoveries
              </span>
              <Badge variant="outline" className="text-[10px]">
                {allFindings.length + (endpoints?.length || 0) + paramList.length}
              </Badge>
            </div>

            {selectedTarget && (
              <div className="text-[10px] text-muted-foreground border-b border-border/50 pb-1 mb-1">
                Target: {targets?.find(t => t.id === selectedTarget)?.domain || targets?.find(t => t.id === selectedTarget)?.name}
              </div>
            )}

            {/* AI brain: NOW / NEXT / HYPOTHESES */}
            <BrainPanel targetId={selectedTarget} />



            {/* Findings & Vulns */}
            <DiscoverySection
              title="Findings & Vulns"
              icon={<Bug className="h-3 w-3 text-destructive" />}
              count={allFindings.length}
              isOpen={expandedSections.finding}
              onToggle={() => toggleSection("finding")}
            >
              {allFindings.map((f) => (
                <div key={f.id} className="px-2 py-1 hover:bg-muted/20 flex items-start gap-1.5">
                  <span className={`text-[8px] px-1 py-0.5 rounded uppercase font-bold mt-0.5 shrink-0 ${severityColor[f.severity] || ""}`}>
                    {f.severity}
                  </span>
                  <div className="min-w-0 flex-1">
                    <p className="text-[10px] text-card-foreground truncate">{f.title}</p>
                    <p className="text-[9px] text-muted-foreground">
                      {f.source === "pending" ? "⏳ Pending approval" : `✅ ${f.confidence}% confidence`}
                    </p>
                  </div>
                </div>
              ))}
            </DiscoverySection>

            {/* Endpoints */}
            <DiscoverySection
              title="Endpoints"
              icon={<Link className="h-3 w-3 text-primary" />}
              count={endpoints?.length || 0}
              isOpen={expandedSections.endpoint}
              onToggle={() => toggleSection("endpoint")}
            >
              {(endpoints || []).slice(0, 30).map((ep) => (
                <div key={ep.id} className="px-2 py-1 hover:bg-muted/20">
                  <div className="flex items-center gap-1">
                    <Badge variant="outline" className="text-[8px] px-1 py-0 shrink-0">{ep.method}</Badge>
                    <span className={`text-[8px] px-1 rounded ${ep.status_code && ep.status_code < 400 ? "text-cyber-green" : "text-muted-foreground"}`}>
                      {ep.status_code || "?"}
                    </span>
                  </div>
                  <p className="text-[9px] text-card-foreground truncate mt-0.5">
                    {(() => { try { return new URL(ep.url).pathname; } catch { return ep.url; } })()}
                  </p>
                  {ep.parameters && Object.keys(ep.parameters as Record<string, string>).length > 0 && (
                    <p className="text-[8px] text-muted-foreground truncate">
                      params: {Object.keys(ep.parameters as Record<string, string>).join(", ")}
                    </p>
                  )}
                </div>
              ))}
              {(endpoints?.length || 0) > 30 && (
                <p className="px-2 py-1 text-[9px] text-muted-foreground italic">+{(endpoints?.length || 0) - 30} more</p>
              )}
            </DiscoverySection>

            {/* Parameters */}
            <DiscoverySection
              title="Parameters Found"
              icon={<Shield className="h-3 w-3 text-cyber-cyan" />}
              count={paramList.length}
              isOpen={expandedSections.param}
              onToggle={() => toggleSection("param")}
            >
              {paramList.slice(0, 40).map((p, i) => (
                <div key={i} className="px-2 py-0.5 hover:bg-muted/20 flex items-center gap-1">
                  <span className="text-[10px] font-semibold text-cyber-cyan">{p.name}</span>
                  <span className="text-[8px] text-muted-foreground">=</span>
                  <span className="text-[9px] text-muted-foreground truncate">{p.value.slice(0, 20)}</span>
                </div>
              ))}
              {paramList.length > 40 && (
                <p className="px-2 py-1 text-[9px] text-muted-foreground italic">+{paramList.length - 40} more</p>
              )}
            </DiscoverySection>
          </div>
        )}
      </div>

      <div className="flex items-center gap-2 text-[10px] font-mono text-muted-foreground">
        <div className={`h-2 w-2 rounded-full ${paused ? "bg-cyber-amber" : "bg-cyber-green animate-pulse-glow"}`} />
        <span>{paused ? "Stream paused" : "Streaming live"}</span>
        <span className="ml-2 flex gap-1">
          {allFindings.length > 0 && <Badge variant="destructive" className="text-[8px]">{allFindings.length} vulns</Badge>}
          {(endpoints?.length || 0) > 0 && <Badge variant="outline" className="text-[8px]">{endpoints?.length} endpoints</Badge>}
          {paramList.length > 0 && <Badge variant="outline" className="text-[8px]">{paramList.length} params</Badge>}
        </span>
        <span className="ml-auto">{logs.length} log entries</span>
      </div>
    </div>
  );
}

// Reusable collapsible section
function DiscoverySection({
  title, icon, count, isOpen, onToggle, children,
}: {
  title: string; icon: React.ReactNode; count: number;
  isOpen: boolean; onToggle: () => void; children: React.ReactNode;
}) {
  return (
    <div className="border border-border/50 rounded-md overflow-hidden">
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-2 px-2 py-1.5 bg-muted/30 hover:bg-muted/50 transition-colors"
      >
        {isOpen ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
        {icon}
        <span className="text-[11px] font-semibold">{title}</span>
        <Badge variant="outline" className="ml-auto text-[9px] px-1">{count}</Badge>
      </button>
      {isOpen && count > 0 && (
        <div className="divide-y divide-border/30 max-h-[220px] overflow-auto">
          {children}
        </div>
      )}
      {isOpen && count === 0 && (
        <p className="px-2 py-2 text-[10px] text-muted-foreground italic">None discovered yet</p>
      )}
    </div>
  );
}
