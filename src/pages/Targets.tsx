import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Plus, Crosshair, Trash2, Radar, Loader2, ShieldAlert,
  Copy, CheckCircle2, XCircle, AlertTriangle, Activity, Bug, GitCompare, Scan,
} from "lucide-react";
import { toast } from "sonner";
import { WafDriftMonitor } from "@/components/WafDriftMonitor";
import { AdvancedScannerPanel } from "@/components/AdvancedScannerPanel";
import { ScopeGateDialog } from "@/components/ScopeGateDialog";


const statusColors: Record<string, string> = {
  queued: "bg-cyber-amber/20 text-cyber-amber border-cyber-amber/30",
  scanning: "bg-cyber-cyan/20 text-cyber-cyan border-cyber-cyan/30",
  completed: "bg-cyber-green/20 text-cyber-green border-cyber-green/30",
  error: "bg-destructive/20 text-destructive border-destructive/30",
};

interface OwaspFinding {
  id: string;
  parameter: string;
  testSignature: string;
  controlResponse: { status: number; bytes: number; label: string };
  anomalyResponse: { status: number; bytes: number; label: string };
  verificationStatus: string;
  severity: string;
  pocCurl: string;
}
interface CveFinding {
  id: string;
  dependency: string;
  cveId: string;
  severity: string;
  description: string;
  fixVersion: string;
  status: string;
}
interface DiffResult {
  id: string;
  testCase: string;
  twinAResponse: string;
  twinBResponse: string;
  byteDelta: string;
  verdict: string;
  confidence: number;
}
interface DeepAuditResults {
  target: string;
  scanId: string;
  timestamp: string;
  owaspFindings: OwaspFinding[];
  cveFindings: CveFinding[];
  differentialResults: DiffResult[];
}

function StatBox({ label, value, icon }: { label: string; value: string; icon: React.ReactNode }) {
  return (
    <Card className="border-border bg-card">
      <CardContent className="p-3 flex items-center gap-3">
        <div className="text-primary">{icon}</div>
        <div>
          <p className="text-[10px] font-mono text-muted-foreground uppercase">{label}</p>
          <p className="text-sm font-mono font-bold text-foreground">{value}</p>
        </div>
      </CardContent>
    </Card>
  );
}

const severityColor = (s: string) => {
  switch (s) {
    case "critical": return "bg-cyber-red/20 text-cyber-red border-cyber-red/40";
    case "high": return "bg-cyber-amber/20 text-cyber-amber border-cyber-amber/40";
    case "medium": return "bg-yellow-500/20 text-yellow-400 border-yellow-500/40";
    default: return "bg-muted text-muted-foreground border-border";
  }
};

export default function Targets() {
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [domain, setDomain] = useState("");
  const [ipRange, setIpRange] = useState("");
  const [apiSchema, setApiSchema] = useState("");
  const [scanningTargets, setScanningTargets] = useState<Set<string>>(new Set());
  const [vulnScanTargets, setVulnScanTargets] = useState<Set<string>>(new Set());
  const [deepAuditTargets, setDeepAuditTargets] = useState<Set<string>>(new Set());
  const [deepAuditResults, setDeepAuditResults] = useState<Record<string, DeepAuditResults>>({});
  const [expandedAudit, setExpandedAudit] = useState<string | null>(null);

  const { data: targets, isLoading } = useQuery({
    queryKey: ["targets"],
    queryFn: async () => {
      const { data } = await supabase.from("target_workspaces").select("*").order("created_at", { ascending: false });
      return data || [];
    },
  });

  const addTarget = useMutation({
    mutationFn: async () => {
      const { data, error } = await supabase.from("target_workspaces").insert({
        name,
        domain: domain || null,
        ip_range: ipRange || null,
        api_schema_url: apiSchema || null,
      }).select().single();
      if (error) throw error;
      if (!data) throw new Error("Insert blocked — admin role required to add targets");
      // If an OpenAPI/Swagger URL was provided, kick off the importer
      // (full auto-attack mode) right away.
      if (apiSchema && data.id) {
        supabase.functions.invoke("openapi-importer", {
          body: { targetId: data.id, schemaUrl: apiSchema, autoAttack: true },
        }).catch(() => { /* surfaces in Neural Log */ });
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["targets"] });
      toast.success(apiSchema ? "Target added — OpenAPI auto-attack queued" : "Target added");
      setOpen(false);
      setName("");
      setDomain("");
      setIpRange("");
      setApiSchema("");
    },
    onError: (e) => toast.error(e.message),
  });

  const deleteTarget = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await supabase.from("target_workspaces").delete().eq("id", id);
      if (error) throw error;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["targets"] });
      toast.success("Target removed");
    },
  });

  // Long-running scans: tolerate client-side timeouts (Supabase JS aborts at ~150s).
  // The edge function continues running server-side; we surface progress via Neural Log + DB polling.
  const isTimeoutOrNetworkError = (err: any): boolean => {
    const m = (err?.message || String(err) || "").toLowerCase();
    return m.includes("timeout") || m.includes("aborted") || m.includes("failed to fetch") ||
           m.includes("network") || m.includes("load failed") || m.includes("context canceled");
  };

  const consumeCredit = async (targetId: string, scanType: string): Promise<boolean> => {
    const { data, error } = await supabase.rpc("consume_scan_credit" as any, { _target_id: targetId, _scan_type: scanType });
    if (error) { toast.error(`Credit error: ${error.message}`); return false; }
    const r = data as any;
    if (!r?.ok) {
      if (r?.error === "no_credits") toast.error("Out of scan credits — ask an admin to grant more");
      else toast.error(`Cannot scan: ${r?.error || "unknown"}`);
      return false;
    }
    if (!r.admin) toast.info(`Scan credit used (${r.remaining} left)`);
    return true;
  };

  const startRecon = async (targetId: string) => {
    if (!(await consumeCredit(targetId, "recon"))) return;
    setScanningTargets((prev) => new Set(prev).add(targetId));
    toast.info("Recon pipeline started — Pro-Fuzz + Drift Reval will auto-chain after recon");
    let reconOk = false;
    try {
      const { data, error } = await supabase.functions.invoke("recon-engine", { body: { targetId } });
      if (error) {
        if (isTimeoutOrNetworkError(error)) {
          toast.info("Recon running in background — watch Neural Log for live progress");
          reconOk = true; // server still executing
        } else {
          toast.error(`Recon failed: ${error.message}`); return;
        }
      } else if (data?.error) { toast.error(`Recon failed: ${data.error}`); return; }
      else {
        reconOk = true;
        toast.success(`Recon: ${data.subdomains} subdomains, ${data.endpointsIngested} endpoints — chaining Pro-Fuzz + Drift Reval...`);
      }

      queryClient.invalidateQueries({ queryKey: ["targets"] });
      queryClient.invalidateQueries({ queryKey: ["endpoints-count"] });
      queryClient.invalidateQueries({ queryKey: ["findings"] });
      queryClient.invalidateQueries({ queryKey: ["recent-logs"] });

      if (!reconOk) return;

      // ── Auto-chain: fire-and-forget; results stream to Neural Log ──
      supabase.functions.invoke("cyberscope-adaptive-drift", { body: { targetId } })
        .catch((e) => console.warn("drift baseline:", e?.message));

      supabase.functions.invoke("advanced-fuzzer", { body: { targetId } })
        .then(({ data: fz }: any) => {
          if (fz?.ok) toast.success(`🔥 Pro-Fuzz: ${fz.totalProbes} probes, ${fz.anomalies} anomalies, ${fz.cveReport?.confirmed || 0}/${fz.cveReport?.tested || 0} CVE matched`);
        })
        .catch((e) => {
          if (!isTimeoutOrNetworkError(e)) toast.error(`Pro-Fuzz error: ${e.message}`);
        });

      supabase.functions.invoke("drift-revalidator", { body: { targetId } })
        .then(({ data: rv }: any) => {
          if (rv?.ok && rv.processed > 0) {
            const confirmed = rv.results?.filter((r: { status: string }) => r.status === "confirmed").length || 0;
            const regressed = rv.results?.filter((r: { status: string }) => r.status === "regressed").length || 0;
            toast.success(`🔬 Drift Reval: ${confirmed} confirmed, ${regressed} regressed`);
          }
        })
        .catch((e) => console.warn("drift reval:", e?.message));

      // ── Mythos auto-trigger ──
      try {
        const { data: tgt } = await supabase.from("target_workspaces").select("auto_mythos").eq("id", targetId).maybeSingle();
        if ((tgt as any)?.auto_mythos) {
          toast.info("🧠 Auto-Mythos enabled — queueing long-horizon run");
          supabase.functions.invoke("mythos-orchestrator", { body: { targetId, triggerType: "auto", maxIterations: 3 } })
            .then(({ data: mr }: any) => {
              if (mr?.runId) toast.success(`Mythos run ${mr.runId.slice(0, 8)} queued`);
            })
            .catch((e) => console.warn("mythos auto:", e?.message));
        }
      } catch (e) { console.warn("auto-mythos check:", e); }

      queryClient.invalidateQueries({ queryKey: ["findings"] });
      queryClient.invalidateQueries({ queryKey: ["recent-logs"] });
      queryClient.invalidateQueries({ queryKey: ["targets-for-drift"] });
    } catch (e: any) {
      if (isTimeoutOrNetworkError(e)) {
        toast.info("Recon running in background — watch Neural Log");
      } else {
        toast.error(`Recon error: ${e.message}`);
      }
    } finally {
      setScanningTargets((prev) => { const n = new Set(prev); n.delete(targetId); return n; });
    }
  };

  const startVulnScan = async (targetId: string) => {
    if (!(await consumeCredit(targetId, "vuln-scan"))) return;
    setVulnScanTargets((prev) => new Set(prev).add(targetId));
    toast.info("Mythos scan queued — findings will stream into Neural Log");
    try {
      const { data, error } = await supabase.functions.invoke("mythos-orchestrator", { body: { targetId, triggerType: "manual", maxIterations: 4 } });
      if (error) {
        if (isTimeoutOrNetworkError(error)) {
          toast.info("Mythos scan running in background — check Neural Log");
        } else {
          toast.error(`Mythos scan failed: ${error.message}`);
        }
      } else if (data?.error) toast.error(`Mythos scan failed: ${data.error}`);
      else {
        toast.success(`Mythos run ${data?.runId?.slice?.(0, 8) || ""} queued`);
      }
      queryClient.invalidateQueries({ queryKey: ["targets"] });
      queryClient.invalidateQueries({ queryKey: ["approvals"] });
      queryClient.invalidateQueries({ queryKey: ["recent-logs"] });
    } catch (e: any) {
      if (isTimeoutOrNetworkError(e)) {
        toast.info("Mythos scan running in background — check Neural Log");
      } else {
        toast.error(`Mythos scan error: ${e.message}`);
      }
    } finally {
      setVulnScanTargets((prev) => { const n = new Set(prev); n.delete(targetId); return n; });
    }
  };

  const startDeepAudit = async (targetId: string, targetDomain: string) => {
    if (!(await consumeCredit(targetId, "deep-audit"))) return;
    setDeepAuditTargets((prev) => new Set(prev).add(targetId));
    toast.info("Deep Audit initiated — Twin-Test differential analysis running");
    try {
      const { data, error } = await supabase.functions.invoke("cyberscope-deep-audit", {
        body: { targetUrl: targetDomain.startsWith("http") ? targetDomain : `https://${targetDomain}`, targetId },
      });
      if (error) {
        if (isTimeoutOrNetworkError(error)) {
          toast.info("Deep Audit running in background — refresh shortly to see results");
          return;
        }
        throw error;
      }
      setDeepAuditResults((prev) => ({ ...prev, [targetId]: data as DeepAuditResults }));
      setExpandedAudit(targetId);
      toast.success("Deep Audit complete — review results below");
    } catch (e: any) {
      if (isTimeoutOrNetworkError(e)) {
        toast.info("Deep Audit running in background — refresh shortly");
      } else {
        toast.error(`Deep Audit error: ${e.message}`);
      }
    } finally {
      setDeepAuditTargets((prev) => { const n = new Set(prev); n.delete(targetId); return n; });
    }
  };


  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success("Copied to clipboard");
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold font-mono text-primary text-glow-green">Target Management</h1>
          <p className="text-xs font-mono text-muted-foreground">Configure, scan, and deep-audit targets</p>
        </div>
        <Dialog open={open} onOpenChange={setOpen}>
          <DialogTrigger asChild>
            <Button size="sm" className="font-mono text-xs gap-1">
              <Plus className="h-3 w-3" /> Add Target
            </Button>
          </DialogTrigger>
          <DialogContent className="bg-card border-border">
            <DialogHeader>
              <DialogTitle className="font-mono text-primary">New Target</DialogTitle>
            </DialogHeader>
            <div className="space-y-3">
              <Input placeholder="Target name" value={name} onChange={(e) => setName(e.target.value)} className="font-mono text-xs bg-muted border-border" />
              <Input placeholder="Domain (e.g. example.com)" value={domain} onChange={(e) => setDomain(e.target.value)} className="font-mono text-xs bg-muted border-border" />
              <Input placeholder="IP Range (e.g. 192.168.1.0/24)" value={ipRange} onChange={(e) => setIpRange(e.target.value)} className="font-mono text-xs bg-muted border-border" />
              <Input placeholder="API Schema URL" value={apiSchema} onChange={(e) => setApiSchema(e.target.value)} className="font-mono text-xs bg-muted border-border" />
              <Button onClick={() => addTarget.mutate()} disabled={!name || addTarget.isPending} className="w-full font-mono text-xs">
                {addTarget.isPending ? "Adding..." : "Add Target"}
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      <WafDriftMonitor />

      <div className="space-y-4">
        {isLoading ? (
          <p className="text-xs font-mono text-muted-foreground">Loading targets...</p>
        ) : targets && targets.length > 0 ? (
          targets.map((target) => {
            const isScanning = scanningTargets.has(target.id) || target.status === "scanning";
            const isVulnScanning = vulnScanTargets.has(target.id);
            const isDeepAuditing = deepAuditTargets.has(target.id);
            const auditData = deepAuditResults[target.id];
            const isExpanded = expandedAudit === target.id;

            return (
              <div key={target.id} className="space-y-0">
                {/* Target row */}
                <div className={`rounded-lg border bg-card p-4 flex items-center justify-between hover:border-primary/30 transition-colors ${isExpanded && auditData ? "border-primary/40 rounded-b-none border-b-0" : "border-border"}`}>
                  <div className="flex items-center gap-3">
                    <Crosshair className="h-4 w-4 text-primary" />
                    <div>
                      <p className="text-sm font-mono font-semibold text-card-foreground">{target.name}</p>
                      <p className="text-[10px] font-mono text-muted-foreground">
                        {target.domain || target.ip_range || target.api_schema_url || "No target specified"}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 flex-wrap justify-end">
                    <Badge variant="outline" className={`text-[9px] font-mono ${statusColors[target.status]}`}>
                      {target.status}
                    </Badge>
                    {target.domain && (
                      <Button variant="outline" size="sm" className="font-mono text-[10px] gap-1 border-cyber-cyan/30 text-cyber-cyan hover:bg-cyber-cyan/10" onClick={() => startRecon(target.id)} disabled={isScanning}>
                        {isScanning ? <Loader2 className="h-3 w-3 animate-spin" /> : <Radar className="h-3 w-3" />}
                        {isScanning ? "Scanning..." : "Recon"}
                      </Button>
                    )}
                    {target.domain && target.status === "completed" && (
                      <Button variant="outline" size="sm" className="font-mono text-[10px] gap-1 border-cyber-red/30 text-cyber-red hover:bg-cyber-red/10" onClick={() => startVulnScan(target.id)} disabled={isVulnScanning}>
                        {isVulnScanning ? <Loader2 className="h-3 w-3 animate-spin" /> : <ShieldAlert className="h-3 w-3" />}
                        {isVulnScanning ? "Scanning..." : "OWASP Scan"}
                      </Button>
                    )}
                    {target.domain && (
                      <Button variant="outline" size="sm" className="font-mono text-[10px] gap-1 border-primary/30 text-primary hover:bg-primary/10 glow-green" onClick={() => auditData && isExpanded ? setExpandedAudit(null) : startDeepAudit(target.id, target.domain!)} disabled={isDeepAuditing}>
                        {isDeepAuditing ? <Loader2 className="h-3 w-3 animate-spin" /> : <Scan className="h-3 w-3" />}
                        {isDeepAuditing ? "Auditing..." : auditData && isExpanded ? "Hide Audit" : "Deep Audit"}
                      </Button>
                    )}
                    {/* Pro-Fuzz and Drift Reval auto-chain after Recon — buttons removed by design */}
                    <ScopeGateDialog targetId={target.id} targetName={target.name} />
                    <Button variant="ghost" size="icon" className="h-7 w-7 text-muted-foreground hover:text-destructive" onClick={() => deleteTarget.mutate(target.id)}>
                      <Trash2 className="h-3 w-3" />
                    </Button>

                  </div>
                </div>

                {/* Deep Audit loading skeleton */}
                {isDeepAuditing && (
                  <div className="border border-t-0 border-border rounded-b-lg bg-card p-4 space-y-3">
                    {[1, 2, 3].map((i) => <Skeleton key={i} className="h-14 w-full bg-muted/50" />)}
                  </div>
                )}

                {/* Deep Audit results inline */}
                {auditData && isExpanded && !isDeepAuditing && (
                  <div className="border border-t-0 border-primary/40 rounded-b-lg bg-card/80 p-4 space-y-4">
                    {/* Stats */}
                    <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                      <StatBox label="Verified Findings" value={String((auditData as any).verifiedFindingsCount ?? auditData.owaspFindings.length)} icon={<Bug className="h-4 w-4" />} />
                      <StatBox label="CVEs Found" value={String(auditData.cveFindings.length)} icon={<AlertTriangle className="h-4 w-4" />} />
                      <StatBox label="FPs Eliminated" value={String((auditData as any).falsePositivesEliminated ?? 0)} icon={<XCircle className="h-4 w-4" />} />
                      <StatBox label="Intel Tested" value={String((auditData as any).intelTemplatesTested ?? 0)} icon={<Radar className="h-4 w-4" />} />
                      <StatBox label="Intel Confirmed" value={String((auditData as any).intelConfirmed ?? 0)} icon={<CheckCircle2 className="h-4 w-4" />} />
                    </div>

                    <Tabs defaultValue="owasp" className="space-y-3">
                      <TabsList className="bg-muted/50 border border-border font-mono">
                        <TabsTrigger value="owasp" className="data-[state=active]:bg-primary/20 data-[state=active]:text-primary font-mono text-xs">OWASP Logic & DOM</TabsTrigger>
                        <TabsTrigger value="cve" className="data-[state=active]:bg-primary/20 data-[state=active]:text-primary font-mono text-xs">CVE & Dependencies</TabsTrigger>
                        <TabsTrigger value="diff" className="data-[state=active]:bg-primary/20 data-[state=active]:text-primary font-mono text-xs">Differential (FP)</TabsTrigger>
                      </TabsList>

                      <TabsContent value="owasp">
                        <Card className="border-border bg-card">
                          <CardHeader className="pb-2"><CardTitle className="text-xs font-mono text-primary flex items-center gap-2"><Bug className="h-3 w-3" /> OWASP Logic & DOM Analysis</CardTitle></CardHeader>
                          <CardContent className="p-0">
                            <Table>
                              <TableHeader>
                                <TableRow className="border-border hover:bg-transparent">
                                  <TableHead className="font-mono text-[10px] text-muted-foreground">Parameter/Input</TableHead>
                                  <TableHead className="font-mono text-[10px] text-muted-foreground">Test Signature</TableHead>
                                  <TableHead className="font-mono text-[10px] text-muted-foreground">Control (Safe)</TableHead>
                                  <TableHead className="font-mono text-[10px] text-muted-foreground">Anomaly (Payload)</TableHead>
                                  <TableHead className="font-mono text-[10px] text-muted-foreground">Status</TableHead>
                                  <TableHead className="font-mono text-[10px] text-muted-foreground">PoC</TableHead>
                                </TableRow>
                              </TableHeader>
                              <TableBody>
                                {auditData.owaspFindings.map((f) => (
                                  <TableRow key={f.id} className="border-border/50">
                                    <TableCell className="font-mono text-[11px] text-foreground">{f.parameter}</TableCell>
                                    <TableCell className="font-mono text-[11px] text-cyber-cyan">{f.testSignature}</TableCell>
                                    <TableCell className="font-mono text-[11px] text-muted-foreground">{f.controlResponse.label}</TableCell>
                                    <TableCell className="font-mono text-[11px]">
                                      <span className={f.verificationStatus === "verified_critical" ? "text-cyber-red" : "text-muted-foreground"}>{f.anomalyResponse.label}</span>
                                    </TableCell>
                                    <TableCell>
                                      {f.verificationStatus === "verified_critical" ? (
                                        <Badge className="bg-primary/20 text-primary border border-primary/40 font-mono text-[9px] gap-1 glow-green"><CheckCircle2 className="h-2.5 w-2.5" /> Verified</Badge>
                                      ) : f.verificationStatus === "likely_vuln" ? (
                                        <Badge className="bg-cyber-amber/20 text-cyber-amber border border-cyber-amber/40 font-mono text-[9px] gap-1"><AlertTriangle className="h-2.5 w-2.5" /> Likely</Badge>
                                      ) : f.verificationStatus === "needs_review" ? (
                                        <Badge className="bg-cyber-cyan/20 text-cyber-cyan border border-cyber-cyan/40 font-mono text-[9px] gap-1"><Activity className="h-2.5 w-2.5" /> Review</Badge>
                                      ) : (
                                        <Badge variant="secondary" className="font-mono text-[9px] gap-1 bg-muted text-muted-foreground border border-border"><XCircle className="h-2.5 w-2.5" /> FP/WAF</Badge>
                                      )}
                                    </TableCell>
                                    <TableCell>
                                      <button onClick={() => copyToClipboard(f.pocCurl)} className="flex items-center gap-1 text-[9px] font-mono text-cyber-cyan hover:text-primary transition-colors bg-muted/50 border border-border rounded px-1.5 py-0.5">
                                        <Copy className="h-2.5 w-2.5" /> curl
                                      </button>
                                    </TableCell>
                                  </TableRow>
                                ))}
                              </TableBody>
                            </Table>
                          </CardContent>
                        </Card>
                      </TabsContent>

                      <TabsContent value="cve">
                        <Card className="border-border bg-card">
                          <CardHeader className="pb-2"><CardTitle className="text-xs font-mono text-primary flex items-center gap-2"><AlertTriangle className="h-3 w-3" /> CVE & Dependency Health</CardTitle></CardHeader>
                          <CardContent className="p-0">
                            <Table>
                              <TableHeader>
                                <TableRow className="border-border hover:bg-transparent">
                                  <TableHead className="font-mono text-[10px] text-muted-foreground">Dependency</TableHead>
                                  <TableHead className="font-mono text-[10px] text-muted-foreground">CVE ID</TableHead>
                                  <TableHead className="font-mono text-[10px] text-muted-foreground">Severity</TableHead>
                                  <TableHead className="font-mono text-[10px] text-muted-foreground">Description</TableHead>
                                  <TableHead className="font-mono text-[10px] text-muted-foreground">Fix</TableHead>
                                  <TableHead className="font-mono text-[10px] text-muted-foreground">Status</TableHead>
                                </TableRow>
                              </TableHeader>
                              <TableBody>
                                {auditData.cveFindings.map((c) => (
                                  <TableRow key={c.id} className="border-border/50">
                                    <TableCell className="font-mono text-[11px] text-foreground font-semibold">{c.dependency}</TableCell>
                                    <TableCell className="font-mono text-[11px] text-cyber-cyan">{c.cveId}</TableCell>
                                    <TableCell><Badge className={`font-mono text-[9px] border ${severityColor(c.severity)}`}>{c.severity.toUpperCase()}</Badge></TableCell>
                                    <TableCell className="font-mono text-[11px] text-muted-foreground max-w-[200px]">{c.description}</TableCell>
                                    <TableCell className="font-mono text-[11px] text-primary">{c.fixVersion}</TableCell>
                                    <TableCell><Badge className="bg-cyber-red/20 text-cyber-red border border-cyber-red/40 font-mono text-[9px]">{c.status.toUpperCase()}</Badge></TableCell>
                                  </TableRow>
                                ))}
                              </TableBody>
                            </Table>
                          </CardContent>
                        </Card>
                      </TabsContent>

                      <TabsContent value="diff">
                        <Card className="border-border bg-card">
                          <CardHeader className="pb-2"><CardTitle className="text-xs font-mono text-primary flex items-center gap-2"><GitCompare className="h-3 w-3" /> Differential Engine — FP Elimination</CardTitle></CardHeader>
                          <CardContent className="p-0">
                            <Table>
                              <TableHeader>
                                <TableRow className="border-border hover:bg-transparent">
                                  <TableHead className="font-mono text-[10px] text-muted-foreground">Test Case</TableHead>
                                  <TableHead className="font-mono text-[10px] text-muted-foreground">Twin-A (Payload)</TableHead>
                                  <TableHead className="font-mono text-[10px] text-muted-foreground">Twin-B (Control)</TableHead>
                                  <TableHead className="font-mono text-[10px] text-muted-foreground">Byte Delta</TableHead>
                                  <TableHead className="font-mono text-[10px] text-muted-foreground">Verdict</TableHead>
                                  <TableHead className="font-mono text-[10px] text-muted-foreground">Confidence</TableHead>
                                </TableRow>
                              </TableHeader>
                              <TableBody>
                                {auditData.differentialResults.map((d) => (
                                  <TableRow key={d.id} className="border-border/50">
                                    <TableCell className="font-mono text-[11px] text-foreground">{d.testCase}</TableCell>
                                    <TableCell className="font-mono text-[11px] text-cyber-red max-w-[160px]">{d.twinAResponse}</TableCell>
                                    <TableCell className="font-mono text-[11px] text-muted-foreground max-w-[160px]">{d.twinBResponse}</TableCell>
                                    <TableCell className="font-mono text-[11px] text-cyber-amber">{d.byteDelta}</TableCell>
                                    <TableCell>
                                      {d.verdict === "confirmed" ? (
                                        <Badge className="bg-primary/20 text-primary border border-primary/40 font-mono text-[9px] gap-1 glow-green"><CheckCircle2 className="h-2.5 w-2.5" /> CONFIRMED</Badge>
                                      ) : (
                                        <Badge variant="secondary" className="font-mono text-[9px] gap-1 bg-muted text-muted-foreground border border-border"><XCircle className="h-2.5 w-2.5" /> WAF BLOCKED</Badge>
                                      )}
                                    </TableCell>
                                    <TableCell>
                                      <div className="flex items-center gap-1.5">
                                        <div className="w-12 h-1.5 rounded-full bg-muted overflow-hidden">
                                          <div className={`h-full rounded-full ${d.confidence > 0.7 ? "bg-primary" : "bg-muted-foreground"}`} style={{ width: `${d.confidence * 100}%` }} />
                                        </div>
                                        <span className="font-mono text-[9px] text-muted-foreground">{(d.confidence * 100).toFixed(0)}%</span>
                                      </div>
                                    </TableCell>
                                  </TableRow>
                                ))}
                              </TableBody>
                            </Table>
                          </CardContent>
                        </Card>
                      </TabsContent>
                    </Tabs>

                    <div className="mt-4">
                      <AdvancedScannerPanel targetId={target.id} baseUrl={target.domain ? `https://${target.domain}` : (target.api_schema_url || "")} />
                    </div>
                  </div>
                )}
              </div>
            );
          })
        ) : (
          <div className="text-center py-12 border border-dashed border-border rounded-lg">
            <Crosshair className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
            <p className="text-xs font-mono text-muted-foreground">No targets configured. Add a target to begin.</p>
          </div>
        )}
      </div>
    </div>
  );
}
