import { useEffect, useRef, useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Pause, Play, Terminal, Trash2, Globe, Link, Bug, Shield, ChevronDown, ChevronRight } from "lucide-react";
import { toast } from "sonner";

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

interface LiveDiscovery {
  type: "subdomain" | "endpoint" | "param" | "finding";
  value: string;
  detail?: string;
  severity?: string;
  timestamp: string;
}

function extractDiscoveries(logs: ScanLog[]): LiveDiscovery[] {
  const discoveries: LiveDiscovery[] = [];
  const seen = new Set<string>();

  for (const log of logs) {
    const msg = log.message;
    const ts = log.created_at;

    // Subdomains
    const subMatch = msg.match(/(?:subdomain|sub-domain|probed|discovered)\S*\s+(\S+\.\S+\.\S+)/i);
    if (subMatch && !seen.has(`sub:${subMatch[1]}`)) {
      seen.add(`sub:${subMatch[1]}`);
      discoveries.push({ type: "subdomain", value: subMatch[1], timestamp: ts });
    }

    // Endpoints
    const epMatch = msg.match(/(?:endpoint|url|path|crawled|spider)\S*\s+(https?:\/\/\S+)/i);
    if (epMatch && !seen.has(`ep:${epMatch[1]}`)) {
      seen.add(`ep:${epMatch[1]}`);
      discoveries.push({ type: "endpoint", value: epMatch[1], timestamp: ts });
    }
    // "Loaded N endpoints" pattern
    const loadedEp = msg.match(/Loaded (\d+) endpoints/i);
    if (loadedEp && !seen.has("ep_count")) {
      seen.add("ep_count");
      discoveries.push({ type: "endpoint", value: `${loadedEp[1]} endpoints loaded`, timestamp: ts });
    }

    // Parameters
    const paramMatch = msg.match(/(?:Testing|param|parameter)\s+(\w+)\s+for\s+(\w[\w-]*)/i);
    if (paramMatch && !seen.has(`param:${paramMatch[1]}:${paramMatch[2]}`)) {
      seen.add(`param:${paramMatch[1]}:${paramMatch[2]}`);
      discoveries.push({ type: "param", value: paramMatch[1], detail: paramMatch[2], timestamp: ts });
    }

    // Findings / vulnerabilities
    const findMatch = msg.match(/(?:POTENTIAL|CONFIRMED|HIT|Chain Attack|Logic Flaw)\s*(.*)/i);
    if (findMatch) {
      const sev = /critical/i.test(msg) ? "critical" : /high/i.test(msg) ? "high" : /medium/i.test(msg) ? "medium" : "low";
      const key = `find:${findMatch[1].slice(0, 40)}`;
      if (!seen.has(key)) {
        seen.add(key);
        discoveries.push({ type: "finding", value: findMatch[1].slice(0, 120), severity: sev, timestamp: ts });
      }
    }

    // Google dork results
    const dorkMatch = msg.match(/(?:dork|google.*discover)\S*.*?(\d+)\s+(?:result|finding|hit)/i);
    if (dorkMatch) {
      const key = `dork:${msg.slice(0, 40)}`;
      if (!seen.has(key)) {
        seen.add(key);
        discoveries.push({ type: "subdomain", value: `Dork: ${dorkMatch[1]} results`, detail: msg.slice(0, 80), timestamp: ts });
      }
    }
  }

  return discoveries;
}

const severityColor: Record<string, string> = {
  critical: "bg-destructive text-destructive-foreground",
  high: "bg-destructive/80 text-destructive-foreground",
  medium: "bg-cyber-amber/20 text-cyber-amber",
  low: "bg-muted text-muted-foreground",
};

const typeIcon: Record<string, typeof Globe> = {
  subdomain: Globe,
  endpoint: Link,
  param: Shield,
  finding: Bug,
};

export default function NeuralLog() {
  const queryClient = useQueryClient();
  const [logs, setLogs] = useState<ScanLog[]>([]);
  const [paused, setPaused] = useState(false);
  const [showPanel, setShowPanel] = useState(true);
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    subdomain: true, endpoint: true, param: true, finding: true,
  });
  const scrollRef = useRef<HTMLDivElement>(null);

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
    const channel = supabase
      .channel("scan-logs-realtime")
      .on("postgres_changes", { event: "INSERT", schema: "public", table: "scan_logs" }, (payload) => {
        if (!paused) {
          setLogs((prev) => [...prev, payload.new as ScanLog]);
        }
      })
      .subscribe();

    return () => { supabase.removeChannel(channel); };
  }, [paused]);

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
      toast.success("All logs cleared from database");
    },
    onError: (e) => toast.error(e.message),
  });

  const discoveries = useMemo(() => extractDiscoveries(logs), [logs]);

  const grouped = useMemo(() => {
    const g: Record<string, LiveDiscovery[]> = { subdomain: [], endpoint: [], param: [], finding: [] };
    for (const d of discoveries) g[d.type]?.push(d);
    return g;
  }, [discoveries]);

  const formatTime = (ts: string) => {
    const d = new Date(ts);
    return d.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
  };

  const toggleSection = (key: string) =>
    setExpandedSections(prev => ({ ...prev, [key]: !prev[key] }));

  const sectionLabels: Record<string, string> = {
    subdomain: "Subdomains & Dorks",
    endpoint: "Endpoints",
    param: "Parameters",
    finding: "Findings & Vulns",
  };

  return (
    <div className="space-y-4 h-full flex flex-col">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold font-mono text-primary text-glow-green">Live Neural Log</h1>
          <p className="text-xs font-mono text-muted-foreground">Real-time AI agent activity stream</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" className="font-mono text-xs gap-1" onClick={() => setShowPanel(!showPanel)}>
            {showPanel ? "Hide" : "Show"} Discoveries
          </Button>
          <Button variant="outline" size="sm" className="font-mono text-xs gap-1" onClick={() => setPaused(!paused)}>
            {paused ? <Play className="h-3 w-3" /> : <Pause className="h-3 w-3" />}
            {paused ? "Resume" : "Pause"}
          </Button>
          <Button variant="outline" size="sm" className="font-mono text-xs gap-1" onClick={() => setLogs([])}>
            <Trash2 className="h-3 w-3" /> Clear View
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

        {/* Live Discoveries Panel */}
        {showPanel && (
          <div className="flex-1 min-w-[280px] max-w-[380px] max-h-[calc(100vh-220px)] overflow-auto rounded-lg border border-border bg-background p-3 font-mono text-xs space-y-2">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm font-bold text-primary">Live Discoveries</span>
              <Badge variant="outline" className="text-[10px]">{discoveries.length}</Badge>
            </div>

            {(["finding", "subdomain", "endpoint", "param"] as const).map(section => {
              const items = grouped[section];
              const Icon = typeIcon[section];
              const isOpen = expandedSections[section];
              return (
                <div key={section} className="border border-border/50 rounded-md overflow-hidden">
                  <button
                    onClick={() => toggleSection(section)}
                    className="w-full flex items-center gap-2 px-2 py-1.5 bg-muted/30 hover:bg-muted/50 transition-colors"
                  >
                    {isOpen ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                    <Icon className="h-3 w-3 text-primary" />
                    <span className="text-[11px] font-semibold">{sectionLabels[section]}</span>
                    <Badge variant="outline" className="ml-auto text-[9px] px-1">{items.length}</Badge>
                  </button>
                  {isOpen && items.length > 0 && (
                    <div className="divide-y divide-border/30 max-h-[200px] overflow-auto">
                      {items.map((d, i) => (
                        <div key={i} className="px-2 py-1 hover:bg-muted/20 flex items-start gap-1.5">
                          {d.severity && (
                            <span className={`text-[8px] px-1 py-0.5 rounded uppercase font-bold mt-0.5 ${severityColor[d.severity] || ""}`}>
                              {d.severity}
                            </span>
                          )}
                          <div className="min-w-0 flex-1">
                            <p className="text-[10px] text-card-foreground truncate">{d.value}</p>
                            {d.detail && <p className="text-[9px] text-muted-foreground truncate">{d.detail}</p>}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                  {isOpen && items.length === 0 && (
                    <p className="px-2 py-2 text-[10px] text-muted-foreground italic">None discovered yet</p>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      <div className="flex items-center gap-2 text-[10px] font-mono text-muted-foreground">
        <div className={`h-2 w-2 rounded-full ${paused ? "bg-cyber-amber" : "bg-cyber-green animate-pulse-glow"}`} />
        <span>{paused ? "Stream paused" : "Streaming live"}</span>
        <span className="ml-2">
          {grouped.finding.length > 0 && <Badge variant="destructive" className="text-[8px] mr-1">{grouped.finding.length} vulns</Badge>}
          {grouped.endpoint.length > 0 && <Badge variant="outline" className="text-[8px] mr-1">{grouped.endpoint.length} endpoints</Badge>}
          {grouped.subdomain.length > 0 && <Badge variant="outline" className="text-[8px] mr-1">{grouped.subdomain.length} subs</Badge>}
        </span>
        <span className="ml-auto">{logs.length} entries</span>
      </div>
    </div>
  );
}
