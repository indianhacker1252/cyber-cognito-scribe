import { useState, useRef, useEffect } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { ShieldAlert, Zap, Loader2, AlertTriangle, CheckCircle2, ServerCog, Activity } from "lucide-react";
import { toast } from "sonner";

interface MutationStep {
  iteration: number;
  payload: string;
  httpStatus: number;
  httpStatusText: string;
  engineAction: string;
  technique: string;
  timestamp: string;
}

interface DriftReport {
  endpoint: string;
  previousServer: string;
  currentServer: string;
  previousWaf: string;
  currentWaf: string;
  driftDetected: boolean;
  driftType: string;
  detectedAt: string;
}

const initialEndpoint = "https://target.example.com/api/search";

export function WafDriftMonitor() {
  const [endpoint, setEndpoint] = useState(initialEndpoint);
  const [running, setRunning] = useState(false);
  const [drift, setDrift] = useState<DriftReport | null>(null);
  const [steps, setSteps] = useState<MutationStep[]>([]);
  const [logLines, setLogLines] = useState<string[]>([
    "[init] mutation engine idle — awaiting target endpoint",
  ]);
  const consoleRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (consoleRef.current) {
      consoleRef.current.scrollTop = consoleRef.current.scrollHeight;
    }
  }, [logLines]);

  const appendLog = (line: string) => {
    const ts = new Date().toISOString().split("T")[1].slice(0, 12);
    setLogLines((prev) => [...prev, `[${ts}] ${line}`]);
  };

  const runSimulation = async () => {
    if (!endpoint.trim()) {
      toast.error("Provide a target endpoint");
      return;
    }
    setRunning(true);
    setSteps([]);
    setDrift(null);
    setLogLines([`[boot] adaptive routing initiated → ${endpoint}`]);
    appendLog("calling cyberscope-adaptive-drift edge function...");

    try {
      const { data, error } = await supabase.functions.invoke("cyberscope-adaptive-drift", {
        body: { endpoint, payload: "<script>alert(1)</script>" },
      });
      if (error) throw error;
      if (!data?.ok) throw new Error(data?.error || "engine failure");

      setDrift(data.drift);
      appendLog(`drift report received → ${data.drift.driftType}`);
      appendLog(`baseline: ${data.drift.previousServer} / ${data.drift.previousWaf}`);
      appendLog(`current : ${data.drift.currentServer} / ${data.drift.currentWaf}`);

      // Animate steps in sequence
      const chain: MutationStep[] = data.mutationChain;
      for (const step of chain) {
        await new Promise((r) => setTimeout(r, 900));
        setSteps((prev) => [...prev, step]);
        appendLog(`iter#${step.iteration} [${step.technique}] → ${step.httpStatus} ${step.httpStatusText}`);
        appendLog(`  ↳ ${step.engineAction}`);
      }
      appendLog("mutation chain complete.");
      toast.success("Adaptive routing simulation finished");
    } catch (e: any) {
      appendLog(`ERROR: ${e.message}`);
      toast.error(`Drift simulation failed: ${e.message}`);
    } finally {
      setRunning(false);
    }
  };

  const statusColor = (s: number) => {
    if (s >= 200 && s < 300) return "bg-primary/20 text-primary border-primary/40";
    if (s === 403 || s === 401) return "bg-cyber-red/20 text-cyber-red border-cyber-red/40";
    if (s === 406 || s === 429) return "bg-cyber-amber/20 text-cyber-amber border-cyber-amber/40";
    return "bg-muted text-muted-foreground border-border";
  };

  return (
    <Card className="border-cyber-amber/30 bg-card">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-mono text-cyber-amber flex items-center gap-2">
          <ShieldAlert className="h-4 w-4" />
          WAF & Baseline Drift Monitor
          <Badge variant="outline" className="ml-2 text-[9px] font-mono border-cyber-amber/30 text-cyber-amber">
            Adaptive Defense Telemetry
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Controls */}
        <div className="flex flex-col sm:flex-row gap-2">
          <Input
            value={endpoint}
            onChange={(e) => setEndpoint(e.target.value)}
            placeholder="Target Endpoint (e.g. https://api.example.com/search)"
            className="font-mono text-xs bg-muted border-border flex-1"
          />
          <Button
            size="sm"
            onClick={runSimulation}
            disabled={running}
            className="font-mono text-xs gap-1 bg-cyber-amber/20 text-cyber-amber border border-cyber-amber/40 hover:bg-cyber-amber/30"
          >
            {running ? <Loader2 className="h-3 w-3 animate-spin" /> : <Zap className="h-3 w-3" />}
            {running ? "Routing..." : "Simulate Adaptive Routing"}
          </Button>
        </div>

        {/* Dual panel */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          {/* Baseline diff */}
          <Card className="border-border bg-muted/30">
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-mono text-cyber-cyan flex items-center gap-2">
                <ServerCog className="h-3 w-3" /> Baseline Diffing
                {drift?.driftDetected && (
                  <Badge className="bg-cyber-amber/20 text-cyber-amber border border-cyber-amber/40 font-mono text-[9px] gap-1 ml-auto">
                    <AlertTriangle className="h-2.5 w-2.5" /> Drift Detected
                  </Badge>
                )}
                {!drift && (
                  <Badge variant="outline" className="ml-auto text-[9px] font-mono border-border text-muted-foreground">
                    awaiting scan
                  </Badge>
                )}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <div className="grid grid-cols-2 gap-2">
                <div className="rounded border border-border bg-background/50 p-2">
                  <p className="text-[9px] font-mono text-muted-foreground uppercase mb-1">Last Scan</p>
                  <p className="text-xs font-mono text-foreground">{drift?.previousServer || "—"}</p>
                  <p className="text-[10px] font-mono text-muted-foreground">{drift?.previousWaf || "—"}</p>
                </div>
                <div className="rounded border border-cyber-amber/30 bg-cyber-amber/5 p-2">
                  <p className="text-[9px] font-mono text-cyber-amber uppercase mb-1">Current Scan</p>
                  <p className="text-xs font-mono text-foreground">{drift?.currentServer || "—"}</p>
                  <p className="text-[10px] font-mono text-cyber-amber">{drift?.currentWaf || "—"}</p>
                </div>
              </div>
              {drift && (
                <div className="rounded border border-border bg-background/30 p-2">
                  <p className="text-[9px] font-mono text-muted-foreground uppercase mb-1">Drift Type</p>
                  <p className="text-[11px] font-mono text-cyber-amber">{drift.driftType}</p>
                  <p className="text-[9px] font-mono text-muted-foreground mt-1">
                    detected {new Date(drift.detectedAt).toLocaleTimeString()}
                  </p>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Mutation engine console */}
          <Card className="border-primary/30 bg-black">
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-mono text-primary flex items-center gap-2">
                <Activity className="h-3 w-3" /> Mutation Engine Logs
                <span className="ml-auto h-1.5 w-1.5 rounded-full bg-primary animate-pulse" />
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div
                ref={consoleRef}
                className="h-[180px] overflow-y-auto rounded border border-primary/20 bg-black p-2 font-mono text-[10px] leading-relaxed"
                style={{ scrollbarWidth: "thin" }}
              >
                {logLines.map((line, i) => {
                  const isError = line.includes("ERROR");
                  const isOk = line.includes("complete") || line.includes("Successful");
                  const isWarn = line.includes("Blocked") || line.includes("drift");
                  const color = isError
                    ? "text-cyber-red"
                    : isOk
                    ? "text-primary"
                    : isWarn
                    ? "text-cyber-amber"
                    : "text-primary/70";
                  return (
                    <div key={i} className={color}>
                      {line}
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Mutation chain table */}
        <Card className="border-border bg-card">
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-mono text-primary flex items-center gap-2">
              <Zap className="h-3 w-3" /> Payload Mutation History
              <Badge variant="outline" className="ml-auto text-[9px] font-mono border-border text-muted-foreground">
                {steps.length} iterations
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow className="border-border hover:bg-transparent">
                  <TableHead className="font-mono text-[10px] text-muted-foreground w-20">Iteration</TableHead>
                  <TableHead className="font-mono text-[10px] text-muted-foreground">Payload Signature</TableHead>
                  <TableHead className="font-mono text-[10px] text-muted-foreground w-32">HTTP Response</TableHead>
                  <TableHead className="font-mono text-[10px] text-muted-foreground">Engine Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {steps.length === 0 ? (
                  <TableRow className="border-border/50">
                    <TableCell colSpan={4} className="text-center font-mono text-[11px] text-muted-foreground py-6">
                      No mutation chain — click "Simulate Adaptive Routing" to begin
                    </TableCell>
                  </TableRow>
                ) : (
                  steps.map((s) => (
                    <TableRow key={s.iteration} className="border-border/50">
                      <TableCell className="font-mono text-[11px] text-cyber-cyan">Attempt {s.iteration}</TableCell>
                      <TableCell className="font-mono text-[11px] text-foreground max-w-[300px] truncate" title={s.payload}>
                        {s.payload}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className={`font-mono text-[9px] gap-1 ${statusColor(s.httpStatus)}`}>
                          {s.httpStatus === 200 ? <CheckCircle2 className="h-2.5 w-2.5" /> : <AlertTriangle className="h-2.5 w-2.5" />}
                          {s.httpStatus} {s.httpStatusText}
                        </Badge>
                      </TableCell>
                      <TableCell className="font-mono text-[11px] text-muted-foreground">{s.engineAction}</TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </CardContent>
    </Card>
  );
}
