import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { supabase } from "@/integrations/supabase/client";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Brain, Shield, Swords, Target as TargetIcon, ExternalLink, RefreshCw, Activity, AlertTriangle, Zap } from "lucide-react";

type Target = { id: string; name: string; domain: string | null };
type Run = {
  id: string;
  target_id: string;
  status: string;
  current_phase: string | null;
  iteration: number;
  max_iterations: number;
  findings_count: number | null;
  chains_count: number | null;
  variants_count: number | null;
  started_at: string | null;
  completed_at: string | null;
  thought_log: any;
};
type Finding = {
  id: string;
  title: string;
  severity: string;
  confidence_score: number | null;
  confidence_level: string | null;
  validation_status: string | null;
  payload: string | null;
  triage_reasoning: string | null;
  cvss_score: number | null;
  created_at: string;
  target_id: string;
};
type Chain = {
  id: string;
  chain_name: string;
  chain_narrative: string | null;
  combined_severity: string | null;
  combined_cvss: number | null;
  steps: any;
  execution_status: string | null;
  run_id: string | null;
  created_at: string;
};
type Variant = {
  id: string;
  vuln_class: string;
  parent_cve: string | null;
  variant_payload: string;
  is_zero_day_candidate: boolean | null;
  test_status: string | null;
  test_endpoint: string | null;
  created_at: string;
};
type Debate = {
  id: string;
  endpoint_url: string | null;
  param_name: string | null;
  vuln_class: string | null;
  fp_verdict: string | null;
  confidence_score: number | null;
  agreed_payload: string | null;
  created_at: string;
};

const sevColor: Record<string, string> = {
  critical: "bg-destructive text-destructive-foreground",
  high: "bg-destructive/80 text-destructive-foreground",
  medium: "bg-yellow-600/80 text-white",
  low: "bg-blue-600/70 text-white",
  info: "bg-muted text-muted-foreground",
};

function ConfidenceBar({ score }: { score: number | null }) {
  const v = Math.max(0, Math.min(100, score ?? 0));
  const tone = v >= 75 ? "bg-primary" : v >= 50 ? "bg-yellow-500" : "bg-muted-foreground";
  return (
    <div className="flex items-center gap-2 w-32">
      <div className="flex-1 h-1.5 rounded bg-muted overflow-hidden">
        <div className={`h-full ${tone}`} style={{ width: `${v}%` }} />
      </div>
      <span className="font-mono text-[10px] text-muted-foreground w-8 text-right">{v}%</span>
    </div>
  );
}

export default function MythosResults() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [targets, setTargets] = useState<Target[]>([]);
  const [targetId, setTargetId] = useState<string>(searchParams.get("targetId") || "");
  const [runs, setRuns] = useState<Run[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [chains, setChains] = useState<Chain[]>([]);
  const [variants, setVariants] = useState<Variant[]>([]);
  const [debates, setDebates] = useState<Debate[]>([]);
  const [loading, setLoading] = useState(false);
  const [running, setRunning] = useState(false);

  // Load targets
  useEffect(() => {
    supabase.from("target_workspaces").select("id,name,domain").order("created_at", { ascending: false })
      .then(({ data }) => {
        const list = (data as Target[]) || [];
        setTargets(list);
        if (!targetId && list.length) {
          setTargetId(list[0].id);
          setSearchParams({ targetId: list[0].id });
        }
      });
  }, []);

  const reload = async (tid: string) => {
    if (!tid) return;
    setLoading(true);
    const [r, f, c, v, d] = await Promise.all([
      supabase.from("mythos_runs").select("*").eq("target_id", tid).order("created_at", { ascending: false }).limit(20),
      supabase.from("vulnerability_findings").select("*").eq("target_id", tid).order("created_at", { ascending: false }).limit(100),
      supabase.from("mythos_chains").select("*").eq("target_id", tid).order("created_at", { ascending: false }).limit(50),
      supabase.from("mythos_variants").select("*").eq("target_id", tid).order("created_at", { ascending: false }).limit(100),
      supabase.from("mythos_debates").select("*").eq("target_id", tid).order("created_at", { ascending: false }).limit(50),
    ]);
    setRuns((r.data as Run[]) || []);
    setFindings((f.data as Finding[]) || []);
    setChains((c.data as Chain[]) || []);
    setVariants((v.data as Variant[]) || []);
    setDebates((d.data as Debate[]) || []);
    setLoading(false);
  };

  useEffect(() => {
    if (targetId) {
      reload(targetId);
      const ch = supabase
        .channel(`mythos-${targetId}`)
        .on("postgres_changes", { event: "*", schema: "public", table: "mythos_runs", filter: `target_id=eq.${targetId}` }, () => reload(targetId))
        .on("postgres_changes", { event: "*", schema: "public", table: "vulnerability_findings", filter: `target_id=eq.${targetId}` }, () => reload(targetId))
        .on("postgres_changes", { event: "*", schema: "public", table: "mythos_chains", filter: `target_id=eq.${targetId}` }, () => reload(targetId))
        .on("postgres_changes", { event: "*", schema: "public", table: "mythos_variants", filter: `target_id=eq.${targetId}` }, () => reload(targetId))
        .on("postgres_changes", { event: "*", schema: "public", table: "mythos_debates", filter: `target_id=eq.${targetId}` }, () => reload(targetId))
        .subscribe();
      return () => { supabase.removeChannel(ch); };
    }
  }, [targetId]);

  const onTargetChange = (id: string) => {
    setTargetId(id);
    setSearchParams({ targetId: id });
  };

  const triggerMythos = async () => {
    if (!targetId) return;
    setRunning(true);
    try {
      const { error } = await supabase.functions.invoke("mythos-orchestrator", {
        body: { targetId, triggerType: "manual", maxIterations: 4 },
      });
      if (error) console.error("mythos-orchestrator error", error);
      setTimeout(() => reload(targetId), 2000);
    } finally {
      setRunning(false);
    }
  };

  const triggerScan = async () => {
    if (!targetId) return;
    setRunning(true);
    try {
      await supabase.functions.invoke("mythos-orchestrator", { body: { targetId, triggerType: "manual", maxIterations: 4 } });
      setTimeout(() => reload(targetId), 2000);
    } finally {
      setRunning(false);
    }
  };

  const stats = useMemo(() => {
    const xss = findings.filter(f => /xss|cross.site/i.test(f.title) || /xss/i.test(f.triage_reasoning || "")).length;
    const sqli = findings.filter(f => /sqli|sql.inject/i.test(f.title)).length;
    const high = findings.filter(f => f.severity === "critical" || f.severity === "high").length;
    const zerodays = variants.filter(v => v.is_zero_day_candidate).length;
    return { xss, sqli, high, zerodays };
  }, [findings, variants]);

  const activeRun = runs.find(r => r.status === "running") || runs[0];
  const targetDomain = targets.find(t => t.id === targetId)?.domain;

  // Trace link: deep-link to NeuralLog filtered by target + (optional) run/debate context
  const traceLink = (extra?: Record<string, string>) => {
    const p = new URLSearchParams({ targetId, ...extra });
    return `/logs?${p.toString()}`;
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold font-mono text-primary text-glow-green flex items-center gap-2">
            <Brain className="h-6 w-6" /> MYTHOS RESULTS
          </h1>
          <p className="text-xs text-muted-foreground font-mono mt-1">
            Long-horizon agent loop · findings · confidence · sources · live trace
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <Select value={targetId} onValueChange={onTargetChange}>
            <SelectTrigger className="w-72 font-mono text-xs"><SelectValue placeholder="Select target" /></SelectTrigger>
            <SelectContent>
              {targets.map(t => (
                <SelectItem key={t.id} value={t.id} className="font-mono text-xs">
                  {t.name} {t.domain ? `· ${t.domain}` : ""}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button size="sm" variant="outline" onClick={() => reload(targetId)} disabled={loading}>
            <RefreshCw className={`h-3 w-3 mr-1 ${loading ? "animate-spin" : ""}`} /> Refresh
          </Button>
          <Button size="sm" variant="secondary" onClick={triggerScan} disabled={running || !targetId}>
            <Zap className="h-3 w-3 mr-1" /> Run Scan
          </Button>
          <Button size="sm" onClick={triggerMythos} disabled={running || !targetId}>
            <Brain className="h-3 w-3 mr-1" /> Run Mythos
          </Button>
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <Card>
          <CardContent className="p-4">
            <div className="text-[10px] font-mono text-muted-foreground uppercase">Findings</div>
            <div className="text-2xl font-mono font-bold text-primary">{findings.length}</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="text-[10px] font-mono text-muted-foreground uppercase">High/Crit</div>
            <div className="text-2xl font-mono font-bold text-destructive">{stats.high}</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="text-[10px] font-mono text-muted-foreground uppercase">XSS</div>
            <div className="text-2xl font-mono font-bold text-destructive/80">{stats.xss}</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="text-[10px] font-mono text-muted-foreground uppercase">Chains</div>
            <div className="text-2xl font-mono font-bold text-primary">{chains.length}</div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4">
            <div className="text-[10px] font-mono text-muted-foreground uppercase">0-Day Candidates</div>
            <div className="text-2xl font-mono font-bold text-destructive">{stats.zerodays}</div>
          </CardContent>
        </Card>
      </div>

      {/* Active run */}
      {activeRun && (
        <Card className="border-primary/40">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-mono flex items-center gap-2">
              <Activity className={`h-4 w-4 ${activeRun.status === "running" ? "text-primary animate-pulse" : "text-muted-foreground"}`} />
              Latest Run · <span className={activeRun.status === "running" ? "text-primary" : "text-muted-foreground"}>{activeRun.status.toUpperCase()}</span>
              {activeRun.current_phase && <Badge variant="outline" className="font-mono text-[10px]">{activeRun.current_phase}</Badge>}
              <span className="ml-auto">
                <Link to={traceLink({ runId: activeRun.id })} className="text-xs text-primary hover:underline flex items-center gap-1">
                  <ExternalLink className="h-3 w-3" /> View live trace
                </Link>
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-4 gap-4 text-xs font-mono">
              <div><div className="text-muted-foreground">Iteration</div><div className="text-primary">{activeRun.iteration} / {activeRun.max_iterations}</div></div>
              <div><div className="text-muted-foreground">Findings</div><div className="text-primary">{activeRun.findings_count ?? 0}</div></div>
              <div><div className="text-muted-foreground">Chains</div><div className="text-primary">{activeRun.chains_count ?? 0}</div></div>
              <div><div className="text-muted-foreground">Variants</div><div className="text-primary">{activeRun.variants_count ?? 0}</div></div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Tabs */}
      <Tabs defaultValue="findings" className="w-full">
        <TabsList className="font-mono text-xs">
          <TabsTrigger value="findings"><Shield className="h-3 w-3 mr-1" /> Findings ({findings.length})</TabsTrigger>
          <TabsTrigger value="chains"><Swords className="h-3 w-3 mr-1" /> Kill Chains ({chains.length})</TabsTrigger>
          <TabsTrigger value="variants"><Zap className="h-3 w-3 mr-1" /> Variants ({variants.length})</TabsTrigger>
          <TabsTrigger value="debates"><Brain className="h-3 w-3 mr-1" /> Debates ({debates.length})</TabsTrigger>
          <TabsTrigger value="runs"><Activity className="h-3 w-3 mr-1" /> Runs ({runs.length})</TabsTrigger>
        </TabsList>

        <TabsContent value="findings">
          <Card>
            <CardContent className="p-0">
              <ScrollArea className="h-[520px]">
                {findings.length === 0 ? (
                  <div className="p-6 text-center text-muted-foreground font-mono text-xs">No findings yet. Trigger Run Scan + Run Mythos.</div>
                ) : findings.map(f => (
                  <div key={f.id} className="border-b border-border p-3 hover:bg-muted/30">
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <Badge className={`${sevColor[f.severity] || sevColor.info} text-[10px] font-mono uppercase`}>{f.severity}</Badge>
                          <span className="font-mono text-sm text-foreground truncate">{f.title}</span>
                          {f.validation_status && (
                            <Badge variant="outline" className="font-mono text-[10px]">{f.validation_status}</Badge>
                          )}
                        </div>
                        {f.payload && (
                          <div className="mt-1 font-mono text-[10px] text-muted-foreground truncate">payload: <span className="text-primary">{f.payload}</span></div>
                        )}
                        {f.triage_reasoning && (
                          <div className="mt-1 font-mono text-[10px] text-muted-foreground line-clamp-2">{f.triage_reasoning}</div>
                        )}
                      </div>
                      <div className="flex flex-col items-end gap-1 shrink-0">
                        <ConfidenceBar score={f.confidence_score} />
                        {f.cvss_score != null && <span className="font-mono text-[10px] text-muted-foreground">CVSS {f.cvss_score}</span>}
                        <Link to={traceLink({ findingId: f.id })} className="text-[10px] text-primary hover:underline flex items-center gap-1">
                          <ExternalLink className="h-3 w-3" /> trace
                        </Link>
                      </div>
                    </div>
                  </div>
                ))}
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="chains">
          <Card>
            <CardContent className="p-0">
              <ScrollArea className="h-[520px]">
                {chains.length === 0 ? (
                  <div className="p-6 text-center text-muted-foreground font-mono text-xs">No kill-chains proposed yet.</div>
                ) : chains.map(c => (
                  <div key={c.id} className="border-b border-border p-3 hover:bg-muted/30">
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <Badge className={`${sevColor[c.combined_severity || "medium"]} text-[10px] font-mono uppercase`}>{c.combined_severity || "medium"}</Badge>
                        <span className="font-mono text-sm text-foreground">{c.chain_name}</span>
                        <Badge variant="outline" className="font-mono text-[10px]">{c.execution_status || "proposed"}</Badge>
                      </div>
                      {c.run_id && (
                        <Link to={traceLink({ runId: c.run_id })} className="text-[10px] text-primary hover:underline flex items-center gap-1">
                          <ExternalLink className="h-3 w-3" /> trace
                        </Link>
                      )}
                    </div>
                    {c.chain_narrative && <div className="mt-1 font-mono text-[10px] text-muted-foreground">{c.chain_narrative}</div>}
                    {Array.isArray(c.steps) && c.steps.length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-1">
                        {c.steps.map((s: any, i: number) => (
                          <Badge key={i} variant="outline" className="font-mono text-[10px]">
                            {i + 1}. {typeof s === "string" ? s : (s.title || s.name || s.action || JSON.stringify(s).slice(0, 40))}
                          </Badge>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="variants">
          <Card>
            <CardContent className="p-0">
              <ScrollArea className="h-[520px]">
                {variants.length === 0 ? (
                  <div className="p-6 text-center text-muted-foreground font-mono text-xs">No variants generated yet.</div>
                ) : variants.map(v => (
                  <div key={v.id} className="border-b border-border p-3 hover:bg-muted/30">
                    <div className="flex items-center gap-2 flex-wrap">
                      <Badge className={`${v.is_zero_day_candidate ? "bg-destructive text-destructive-foreground" : "bg-muted text-muted-foreground"} text-[10px] font-mono uppercase`}>
                        {v.is_zero_day_candidate ? "0-DAY" : "variant"}
                      </Badge>
                      <span className="font-mono text-sm text-foreground">{v.vuln_class}</span>
                      {v.parent_cve && <Badge variant="outline" className="font-mono text-[10px]">{v.parent_cve}</Badge>}
                      <Badge variant="outline" className="font-mono text-[10px]">{v.test_status || "pending"}</Badge>
                    </div>
                    <div className="mt-1 font-mono text-[10px] text-muted-foreground truncate">payload: <span className="text-primary">{v.variant_payload}</span></div>
                    {v.test_endpoint && <div className="mt-0.5 font-mono text-[10px] text-muted-foreground truncate">→ {v.test_endpoint}</div>}
                  </div>
                ))}
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="debates">
          <Card>
            <CardContent className="p-0">
              <ScrollArea className="h-[520px]">
                {debates.length === 0 ? (
                  <div className="p-6 text-center text-muted-foreground font-mono text-xs">No agent debates recorded yet.</div>
                ) : debates.map(d => (
                  <div key={d.id} className="border-b border-border p-3 hover:bg-muted/30">
                    <div className="flex items-center gap-2 flex-wrap">
                      <Badge className={`${d.fp_verdict === "true_positive" ? "bg-destructive text-destructive-foreground" : d.fp_verdict === "false_positive" ? "bg-muted text-muted-foreground" : "bg-yellow-600/70 text-white"} text-[10px] font-mono uppercase`}>
                        {d.fp_verdict || "unknown"}
                      </Badge>
                      <span className="font-mono text-sm text-foreground">{d.vuln_class || "auto"} · {d.param_name}</span>
                      <ConfidenceBar score={d.confidence_score} />
                    </div>
                    {d.endpoint_url && <div className="mt-1 font-mono text-[10px] text-muted-foreground truncate">{d.endpoint_url}</div>}
                    {d.agreed_payload && <div className="mt-0.5 font-mono text-[10px]">payload: <span className="text-primary">{d.agreed_payload}</span></div>}
                  </div>
                ))}
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="runs">
          <Card>
            <CardContent className="p-0">
              <ScrollArea className="h-[520px]">
                {runs.map(r => (
                  <div key={r.id} className="border-b border-border p-3 hover:bg-muted/30">
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <Badge className={`${r.status === "complete" ? "bg-primary text-primary-foreground" : r.status === "running" ? "bg-yellow-600/80 text-white" : r.status === "failed" ? "bg-destructive/80 text-destructive-foreground" : "bg-muted text-muted-foreground"} text-[10px] font-mono uppercase`}>{r.status}</Badge>
                        <span className="font-mono text-xs text-muted-foreground">{new Date(r.started_at || r.completed_at || Date.now()).toLocaleString()}</span>
                        {r.current_phase && <Badge variant="outline" className="font-mono text-[10px]">{r.current_phase}</Badge>}
                      </div>
                      <div className="flex items-center gap-2">
                        {(r.status === "running" || r.status === "failed") && r.current_phase && r.current_phase !== "done" && (
                          <Button
                            size="sm"
                            variant="outline"
                            className="h-6 text-[10px] font-mono"
                            onClick={async () => {
                              const { error } = await supabase.functions.invoke("mythos-orchestrator", {
                                body: { runId: r.id, nextPhase: r.current_phase },
                              });
                              if (error) console.error(error);
                              reload(targetId);
                            }}
                          >
                            <RefreshCw className="h-3 w-3 mr-1" /> Resume
                          </Button>
                        )}
                        <Link to={traceLink({ runId: r.id })} className="text-[10px] text-primary hover:underline flex items-center gap-1">
                          <ExternalLink className="h-3 w-3" /> trace
                        </Link>
                      </div>
                    </div>
                    <div className="mt-1 grid grid-cols-4 gap-2 font-mono text-[10px] text-muted-foreground">
                      <div>iter <span className="text-primary">{r.iteration}/{r.max_iterations}</span></div>
                      <div>findings <span className="text-primary">{r.findings_count ?? 0}</span></div>
                      <div>chains <span className="text-primary">{r.chains_count ?? 0}</span></div>
                      <div>variants <span className="text-primary">{r.variants_count ?? 0}</span></div>
                    </div>
                  </div>
                ))}
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {targetDomain && (
        <div className="text-[10px] font-mono text-muted-foreground flex items-center gap-1">
          <TargetIcon className="h-3 w-3" /> Target: <span className="text-primary">{targetDomain}</span>
          <AlertTriangle className="h-3 w-3 ml-2 text-destructive/80" /> All testing must be authorized.
        </div>
      )}
    </div>
  );
}
