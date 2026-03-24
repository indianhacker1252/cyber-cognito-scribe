import { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Pause, Play, Terminal, Trash2 } from "lucide-react";

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
}

export default function NeuralLog() {
  const [logs, setLogs] = useState<ScanLog[]>([]);
  const [paused, setPaused] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  // Initial load
  const { data: initialLogs } = useQuery({
    queryKey: ["scan-logs"],
    queryFn: async () => {
      const { data } = await supabase.from("scan_logs").select("*").order("created_at", { ascending: true }).limit(200);
      return (data || []) as ScanLog[];
    },
  });

  useEffect(() => {
    if (initialLogs) setLogs(initialLogs);
  }, [initialLogs]);

  // Realtime subscription
  useEffect(() => {
    const channel = supabase
      .channel("scan-logs-realtime")
      .on("postgres_changes", { event: "INSERT", schema: "public", table: "scan_logs" }, (payload) => {
        if (!paused) {
          setLogs((prev) => [...prev, payload.new as ScanLog]);
        }
      })
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, [paused]);

  // Auto-scroll
  useEffect(() => {
    if (!paused && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs, paused]);

  const formatTime = (ts: string) => {
    const d = new Date(ts);
    return d.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
  };

  return (
    <div className="space-y-4 h-full flex flex-col">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold font-mono text-primary text-glow-green">Live Neural Log</h1>
          <p className="text-xs font-mono text-muted-foreground">Real-time AI agent activity stream</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" className="font-mono text-xs gap-1" onClick={() => setPaused(!paused)}>
            {paused ? <Play className="h-3 w-3" /> : <Pause className="h-3 w-3" />}
            {paused ? "Resume" : "Pause"}
          </Button>
          <Button variant="outline" size="sm" className="font-mono text-xs gap-1" onClick={() => setLogs([])}>
            <Trash2 className="h-3 w-3" /> Clear
          </Button>
        </div>
      </div>

      <div
        ref={scrollRef}
        className="flex-1 min-h-[400px] max-h-[calc(100vh-220px)] overflow-auto rounded-lg border border-border bg-background p-4 font-mono text-xs scanline"
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

      <div className="flex items-center gap-2 text-[10px] font-mono text-muted-foreground">
        <div className={`h-2 w-2 rounded-full ${paused ? "bg-cyber-amber" : "bg-cyber-green animate-pulse-glow"}`} />
        <span>{paused ? "Stream paused" : "Streaming live"}</span>
        <span className="ml-auto">{logs.length} entries</span>
      </div>
    </div>
  );
}
