import { useState, useMemo, useCallback } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ShieldAlert, Shield, Trash2, BrainCircuit, Gauge, Ban, Filter, X, FileDown, Send, Box, Crosshair, EyeOff, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import ValidationModal from "@/components/ValidationModal";
import AdaptiveValidationModal from "@/components/AdaptiveValidationModal";
import FindingDetailsDialog from "@/components/FindingDetailsDialog";
import SubmitBountyDialog from "@/components/SubmitBountyDialog";
import SandboxRunDialog from "@/components/SandboxRunDialog";
import { FileText } from "lucide-react";
import { markAsFalsePositive } from "@/services/LearningService";
import { triageFinding } from "@/services/TriageBrain";
import { generateFindingPdf, generateBulkPdf } from "@/services/PdfReport";

const severityBadge: Record<string, string> = {
  critical: "bg-cyber-red/20 text-cyber-red border-cyber-red/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-cyber-amber/20 text-cyber-amber border-cyber-amber/30",
  low: "bg-cyber-green/20 text-cyber-green border-cyber-green/30",
  info: "bg-cyber-cyan/20 text-cyber-cyan border-cyber-cyan/30",
};

const confidenceBadge: Record<string, string> = {
  high: "bg-cyber-green/20 text-cyber-green border-cyber-green/30",
  medium: "bg-cyber-amber/20 text-cyber-amber border-cyber-amber/30",
  low: "bg-cyber-red/20 text-cyber-red border-cyber-red/30",
};

export default function Findings() {
  const queryClient = useQueryClient();
  const [selectedFinding, setSelectedFinding] = useState<any>(null);
  const [adaptiveFinding, setAdaptiveFinding] = useState<any>(null);
  const [detailsFinding, setDetailsFinding] = useState<any>(null);
  const [bountyFinding, setBountyFinding] = useState<any>(null);
  const [sandboxFinding, setSandboxFinding] = useState<any>(null);
  const [triaging, setTriaging] = useState<string | null>(null);
  const [activeTargetFilter, setActiveTargetFilter] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<"all" | "confirmed" | "needs_review" | "inconclusive">("all");
  const [sourceFilter, setSourceFilter] = useState<"all" | "dast" | "code" | "package">("all");
  const [verifying, setVerifying] = useState<string | null>(null);

  const { data: findings, isLoading } = useQuery({
    queryKey: ["findings-unified"],
    queryFn: async () => {
      const [dast, code, pkg] = await Promise.all([
        supabase.from("vulnerability_findings").select("*, target_workspaces(name)").order("created_at", { ascending: false }),
        supabase.from("code_findings").select("*").order("created_at", { ascending: false }).limit(500),
        supabase.from("app_package_findings").select("*, app_packages(name)").order("created_at", { ascending: false }).limit(500),
      ]);
      const dastRows = (dast.data || []).map((f: any) => ({ ...f, source_type: "dast" as const }));
      const codeRows = (code.data || []).map((f: any) => ({
        ...f,
        source_type: "code" as const,
        title: `[SAST] ${f.vuln_class || "code finding"} @ ${f.file_path || "unknown"}`,
        description: f.ai_reasoning || f.source_snippet || "",
        payload: f.file_path ? `${f.file_path}:${f.line_start ?? "?"}` : null,
        source: "sast",
        proof_tier: f.reachability_confirmed ? "reflected" : "signal",
        validation_status: f.reachability_confirmed ? "confirmed" : "needs_review",
        confidence_score: f.reachability_confirmed ? 85 : 55,
        confidence_level: f.reachability_confirmed ? "high" : "medium",
        cvss_score: null,
      }));
      const pkgRows = (pkg.data || []).map((f: any) => ({
        ...f,
        source_type: "package" as const,
        target_id: null,
        target_workspaces: f.app_packages ? { name: f.app_packages.name } : null,
        title: `[Package] ${f.title || f.vuln_class}`,
        description: f.description || f.ai_reasoning || "",
        payload: f.file_path ? `${f.file_path}:${f.line_start ?? "?"}` : null,
        source: "package-scan",
        proof_tier: "signal",
        validation_status: "needs_review",
        confidence_score: 60,
        confidence_level: "medium",
      }));
      return [...dastRows, ...codeRows, ...pkgRows].sort(
        (a: any, b: any) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
      );
    },
  });

  // Derive unique targets for filter
  const targetNames = useMemo(() => {
    if (!findings) return [];
    const names = new Map<string, string>();
    for (const f of findings) {
      const name = (f as any).target_workspaces?.name;
      if (name && f.target_id) names.set(f.target_id, name);
    }
    return Array.from(names.entries()); // [target_id, name][]
  }, [findings]);

  const normalizeValidationStatus = (status?: string | null): "confirmed" | "needs_review" | "inconclusive" => {
    const s = (status || "").toLowerCase();
    if (["confirmed", "validated", "verified", "debate_confirmed", "ai_confirmed", "ai_confirmed_reflection", "auto-accepted"].includes(s)) return "confirmed";
    if (["needs_review", "pending_exploit", "fuzzer_anomaly", "pending", "review"].includes(s)) return "needs_review";
    return "inconclusive";
  };

  const filteredFindings = useMemo(() => {
    if (!findings) return [];
    let out = findings as any[];
    if (activeTargetFilter) out = out.filter((f: any) => f.target_id === activeTargetFilter);
    if (statusFilter !== "all") {
      out = out.filter((f: any) => {
        return normalizeValidationStatus(f.validation_status) === statusFilter;
      });
    }
    return out;
  }, [findings, activeTargetFilter, statusFilter]);

  const statusCounts = useMemo(() => {
    const base = { confirmed: 0, needs_review: 0, inconclusive: 0 };
    if (!findings) return base;
    for (const f of findings as any[]) {
      const s = normalizeValidationStatus(f.validation_status);
      if (s === "confirmed") base.confirmed++;
      else if (s === "needs_review") base.needs_review++;
      else base.inconclusive++;
    }
    return base;
  }, [findings]);

  const deleteFinding = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await supabase.from("vulnerability_findings").delete().eq("id", id);
      if (error) throw error;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["findings-unified"] });
      toast.success("Finding deleted");
    },
  });

  const clearAllFindings = useMutation({
    mutationFn: async () => {
      const { error } = await supabase.from("vulnerability_findings").delete().neq("id", "00000000-0000-0000-0000-000000000000");
      if (error) throw error;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["findings-unified"] });
      toast.success("All findings cleared");
    },
  });

  const handleFalsePositive = async (f: any) => {
    const success = await markAsFalsePositive(f.title, null, {}, {}, "Marked as false positive from findings page", f.target_id);
    if (success) {
      deleteFinding.mutate(f.id);
      toast.success("False positive recorded & finding removed");
    }
  };

  const handleAiTriage = async (f: any) => {
    setTriaging(f.id);
    try {
      const result = await triageFinding({ title: f.title, vulnClass: f.title, severity: f.severity, payload: f.payload || "" });
      await supabase.from("vulnerability_findings").update({
        confidence_score: result.confidenceScore,
        confidence_level: result.confidenceScore >= 80 ? "high" : result.confidenceScore >= 50 ? "medium" : "low",
        ai_verified: result.classification === "deep_finding" || result.classification === "confirmed",
        triage_reasoning: result.reasoning,
      }).eq("id", f.id);
      queryClient.invalidateQueries({ queryKey: ["findings-unified"] });
      toast.success(`AI Triage: ${result.classification} (${result.confidenceScore}%)`);
    } catch {
      toast.error("AI triage failed");
    } finally {
      setTriaging(null);
    }
  };

  const handleProve = async (f: any) => {
    toast.info(`Proof Engine running on "${f.title.slice(0,40)}"...`);
    try {
      const { data, error } = await supabase.functions.invoke("proof-engine", { body: { findingId: f.id } });
      if (error) throw error;
      if (!data?.ok) throw new Error(data?.error || "proof failed");
      queryClient.invalidateQueries({ queryKey: ["findings-unified"] });
      toast.success(`Proof tier: ${data.proof_tier}${data.sensitive ? " (sensitive — admin only)" : ""}`);
    } catch (e: any) { toast.error(`Proof engine: ${e.message}`); }
  };

  const proofTierBadge = (t?: string) =>
    t === "exploited" ? "bg-cyber-red/20 text-cyber-red border-cyber-red/40"
    : t === "reflected" ? "bg-cyber-amber/20 text-cyber-amber border-cyber-amber/40"
    : "bg-muted/30 text-muted-foreground border-muted/40";

  const getConfidenceColor = (score: number | null | undefined) => {
    if (!score) return "text-muted-foreground";
    if (score >= 90) return "text-cyber-green";
    if (score >= 85) return "text-cyber-cyan";
    if (score >= 50) return "text-cyber-amber";
    return "text-cyber-red";
  };

  const handleTripleVerify = async (f: any) => {
    setVerifying(f.id);
    try {
      const { data, error } = await supabase.functions.invoke("triple-verify", { body: { findingId: f.id } });
      if (error) throw error;
      if (!data?.ok) throw new Error(data?.error || "verify failed");
      queryClient.invalidateQueries({ queryKey: ["findings-unified"] });
      const tier = data.tier as string;
      const conf = data.confidence as number;
      if (tier === "confirmed") {
        toast.success(`✅ CONFIRMED — ${conf}% confidence`);
        if (data.exploit?.ran) {
          toast.info("⚡ Exploit verification: running...");
          // exploit-engine already finished server-side, but invalidate again to pick up proof_tier
          setTimeout(() => queryClient.invalidateQueries({ queryKey: ["findings-unified"] }), 500);
          if (data.exploit.proven) {
            toast.success(`💀 EXPLOITED ✓ — ready for submission`);
          } else if (data.exploit.error) {
            toast.warning(`Exploit chain error: ${data.exploit.error}`);
          } else {
            toast.info(`Reproduced only — exploit ran but no proven evidence`);
          }
        }
      } else if (tier === "needs_review") toast.info(`⚠️ Needs Review — ${conf}% confidence`);
      else toast.warning(`Inconclusive — ${conf}% confidence`);
    } catch (e: any) {
      toast.error(`Triple-verify: ${e.message}`);
    } finally {
      setVerifying(null);
    }
  };

  const statusBadgeClass = (s?: string) => {
    const normalized = normalizeValidationStatus(s);
    if (normalized === "confirmed") return "bg-cyber-green/20 text-cyber-green border-cyber-green/40";
    if (normalized === "needs_review") return "bg-cyber-amber/20 text-cyber-amber border-cyber-amber/40";
    if (normalized === "inconclusive") return "bg-muted/30 text-muted-foreground border-muted/40";
    return "text-muted-foreground border-muted/40";
  };

  const exportPdfReport = useCallback(async () => {
    if (!filteredFindings || filteredFindings.length === 0) {
      toast.error("No findings to export");
      return;
    }
    toast.info("Generating professional VAPT PDF...");
    try {
      const targetName = activeTargetFilter
        ? targetNames.find(([id]) => id === activeTargetFilter)?.[1] || "All Targets"
        : "All Targets";
      await generateBulkPdf(filteredFindings as any, targetName);
      toast.success("PDF report downloaded");
    } catch (e: any) {
      toast.error(`Export failed: ${e.message}`);
    }
  }, [filteredFindings, activeTargetFilter, targetNames]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold font-mono text-primary text-glow-green">Vulnerability Findings</h1>
          <p className="text-xs font-mono text-muted-foreground">Verified vulnerabilities with confidence scores — AI triaged</p>
        </div>
        <div className="flex gap-2">
          {findings && findings.length > 0 && (
            <>
              <Button
                variant="outline" size="sm"
                className="font-mono text-[10px] gap-1 border-primary/30 text-primary hover:bg-primary/10"
                onClick={exportPdfReport}
              >
                <FileDown className="h-3 w-3" /> Export Report
              </Button>
              <Button
                variant="outline" size="sm"
                className="font-mono text-[10px] gap-1 text-destructive border-destructive/30 hover:bg-destructive/10"
                onClick={() => { if (confirm("Clear all findings?")) clearAllFindings.mutate(); }}
              >
                <Trash2 className="h-3 w-3" /> Clear All
              </Button>
            </>
          )}
        </div>
      </div>

      {/* Target Filter Bar */}
      {targetNames.length > 0 && (
        <div className="flex items-center gap-2 flex-wrap">
          <Filter className="h-3.5 w-3.5 text-muted-foreground" />
          <span className="text-[10px] font-mono text-muted-foreground">Filter by target:</span>
          <button
            onClick={() => setActiveTargetFilter(null)}
            className={`px-2 py-1 rounded text-[10px] font-mono border transition-all ${
              !activeTargetFilter
                ? "bg-primary/20 border-primary text-primary"
                : "border-border text-muted-foreground hover:text-foreground hover:border-primary/30"
            }`}
          >
            All ({findings?.length || 0})
          </button>
          {targetNames.map(([id, name]) => {
            const count = findings?.filter((f: any) => f.target_id === id).length || 0;
            return (
              <button
                key={id}
                onClick={() => setActiveTargetFilter(activeTargetFilter === id ? null : id)}
                className={`px-2 py-1 rounded text-[10px] font-mono border transition-all ${
                  activeTargetFilter === id
                    ? "bg-primary/20 border-primary text-primary"
                    : "border-border text-muted-foreground hover:text-foreground hover:border-primary/30"
                }`}
              >
                {name} ({count})
              </button>
            );
          })}
          {activeTargetFilter && (
            <button onClick={() => setActiveTargetFilter(null)} className="text-muted-foreground hover:text-foreground">
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      )}

      {/* Verification Status Filter (triple-verify) */}
      {findings && findings.length > 0 && (
        <div className="flex items-center gap-2 flex-wrap">
          <ShieldCheck className="h-3.5 w-3.5 text-muted-foreground" />
          <span className="text-[10px] font-mono text-muted-foreground">Verification:</span>
          {([
            ["all", `All (${findings.length})`],
            ["confirmed", `✓ Confirmed (${statusCounts.confirmed})`],
            ["needs_review", `⚠ Needs Review (${statusCounts.needs_review})`],
            ["inconclusive", `Inconclusive (${statusCounts.inconclusive})`],
          ] as const).map(([key, label]) => (
            <button
              key={key}
              onClick={() => setStatusFilter(key as any)}
              className={`px-2 py-1 rounded text-[10px] font-mono border transition-all ${
                statusFilter === key
                  ? "bg-primary/20 border-primary text-primary"
                  : key === "confirmed" ? "border-cyber-green/30 text-cyber-green hover:border-cyber-green"
                  : key === "needs_review" ? "border-cyber-amber/30 text-cyber-amber hover:border-cyber-amber"
                  : "border-border text-muted-foreground hover:text-foreground"
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      )}

      {isLoading ? (
        <p className="text-xs font-mono text-muted-foreground">Loading findings...</p>
      ) : filteredFindings.length > 0 ? (
        <div className="rounded-lg border border-border overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow className="border-border hover:bg-transparent">
                <TableHead className="font-mono text-[10px] uppercase text-muted-foreground">Severity</TableHead>
                <TableHead className="font-mono text-[10px] uppercase text-muted-foreground">Title</TableHead>
                <TableHead className="font-mono text-[10px] uppercase text-muted-foreground">CVSS</TableHead>
                <TableHead className="font-mono text-[10px] uppercase text-muted-foreground">Score</TableHead>
                <TableHead className="font-mono text-[10px] uppercase text-muted-foreground">Confidence</TableHead>
                <TableHead className="font-mono text-[10px] uppercase text-muted-foreground">Target</TableHead>
                <TableHead className="font-mono text-[10px] uppercase text-muted-foreground">Status</TableHead>
                <TableHead className="font-mono text-[10px] uppercase text-muted-foreground">Proof</TableHead>
                <TableHead className="font-mono text-[10px] uppercase text-muted-foreground">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredFindings.map((f: any) => (
                <TableRow key={f.id} className="border-border hover:bg-muted/30">
                  <TableCell>
                    <Badge variant="outline" className={`text-[9px] font-mono ${severityBadge[f.severity]}`}>
                      {f.severity}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-mono text-xs text-card-foreground max-w-xs truncate">
                    {f.title}
                    {f.triage_reasoning && (
                      <p className="text-[9px] text-muted-foreground mt-0.5 truncate" title={f.triage_reasoning}>
                        💡 {f.triage_reasoning.slice(0, 60)}...
                      </p>
                    )}
                  </TableCell>
                  <TableCell className="font-mono text-xs text-cyber-amber">{f.cvss_score || "—"}</TableCell>
                  <TableCell>
                    <span className={`font-mono text-xs font-bold ${getConfidenceColor(f.confidence_score)}`}>
                      {f.confidence_score ? `${f.confidence_score}%` : "—"}
                    </span>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1">
                      {f.confidence_level && (
                        <Badge variant="outline" className={`text-[9px] font-mono ${confidenceBadge[f.confidence_level] || ""}`}>
                          {f.confidence_level}
                        </Badge>
                      )}
                      {f.ai_verified && <BrainCircuit className="h-3 w-3 text-cyber-green" />}
                    </div>
                  </TableCell>
                  <TableCell>
                    <button
                      className="font-mono text-[10px] text-muted-foreground hover:text-primary hover:underline transition-colors cursor-pointer"
                      onClick={() => setActiveTargetFilter(f.target_id)}
                    >
                      {f.target_workspaces?.name || "—"}
                    </button>
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant="outline"
                      className={`text-[9px] font-mono ${statusBadgeClass(f.validation_status)}`}
                      title={f.triage_reasoning || "Run Re-Verify to validate"}
                    >
                      {f.validation_status === "confirmed" ? "✓ confirmed"
                        : f.validation_status === "needs_review" ? "⚠ needs review"
                        : f.validation_status === "inconclusive" ? "inconclusive"
                        : f.validation_status || "unverified"}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1 flex-wrap">
                      <Badge variant="outline" className={`text-[9px] font-mono ${proofTierBadge(f.proof_tier)}`}>
                        {f.proof_tier === "exploited" ? "💀 Exploited ✓"
                          : f.validation_status === "confirmed" && f.proof_tier !== "exploited" ? "Reproduced only"
                          : (f.proof_tier || "signal")}
                      </Badge>
                      {f.proof_tier === "exploited" && (
                        <Badge variant="outline" className="text-[9px] font-mono bg-orange-500/20 text-orange-400 border-orange-500/40">
                          Ready for submission
                        </Badge>
                      )}
                      {f.sensitive && <EyeOff className="h-3 w-3 text-cyber-red" aria-label="sensitive — admin only" />}
                    </div>
                  </TableCell>
                  <TableCell>
                    <div className="flex gap-1">
                      <Button variant="outline" size="sm" className="font-mono text-[10px] gap-1 border-cyber-green/30 text-cyber-green hover:bg-cyber-green/10" onClick={() => setDetailsFinding(f)}>
                        <FileText className="h-3 w-3" /> Details
                      </Button>
                      <Button variant="outline" size="sm" className="font-mono text-[10px] gap-1 border-primary/30 text-primary hover:bg-primary/10" onClick={() => setSelectedFinding(f)}>
                        <Shield className="h-3 w-3" /> Validate
                      </Button>
                      <Button variant="outline" size="sm" className="font-mono text-[10px] gap-1 border-cyber-amber/30 text-cyber-amber hover:bg-cyber-amber/10" onClick={() => setAdaptiveFinding(f)}>
                        <Shield className="h-3 w-3" /> Adaptive
                      </Button>
                      <Button variant="outline" size="sm" className="font-mono text-[10px] gap-1 border-cyber-cyan/30 text-cyber-cyan hover:bg-cyber-cyan/10" onClick={() => handleAiTriage(f)} disabled={triaging === f.id}>
                        <Gauge className="h-3 w-3" /> {triaging === f.id ? "..." : "Triage"}
                      </Button>
                      <Button variant="outline" size="sm" className="font-mono text-[10px] gap-1 border-cyber-red/30 text-cyber-red hover:bg-cyber-red/10" onClick={() => handleFalsePositive(f)}>
                        <Ban className="h-3 w-3" /> FP
                      </Button>
                      <Button variant="outline" size="sm" className="font-mono text-[10px] gap-1 border-cyber-cyan/30 text-cyber-cyan hover:bg-cyber-cyan/10" onClick={() => generateFindingPdf(f).catch(e => toast.error(e.message))}>
                        <FileDown className="h-3 w-3" /> PDF
                      </Button>
                      <Button variant="outline" size="sm" className="font-mono text-[10px] gap-1 border-cyber-green/30 text-cyber-green hover:bg-cyber-green/10" onClick={() => setSandboxFinding(f)}>
                        <Box className="h-3 w-3" /> Sandbox
                      </Button>
                      <Button
                        variant="outline" size="sm"
                        className="font-mono text-[10px] gap-1 border-cyber-green/40 text-cyber-green hover:bg-cyber-green/10 disabled:opacity-50"
                        onClick={() => handleTripleVerify(f)}
                        disabled={verifying === f.id}
                        title="Run triple-verification (baseline → mutated → rebaseline → replay)"
                      >
                        <ShieldCheck className="h-3 w-3" /> {verifying === f.id ? "..." : "Re-Verify"}
                      </Button>
                      <Button variant="outline" size="sm" className="font-mono text-[10px] gap-1 border-fuchsia-500/30 text-fuchsia-400 hover:bg-fuchsia-500/10" onClick={() => handleProve(f)}>
                        <Crosshair className="h-3 w-3" /> Prove
                      </Button>
                      <Button
                        variant="outline" size="sm"
                        className="font-mono text-[10px] gap-1 border-orange-500/30 text-orange-400 hover:bg-orange-500/10 disabled:opacity-50"
                        title={f.proof_tier !== "exploited" ? "Run Prove first — only exploited findings can be submitted" : ""}
                        disabled={f.proof_tier !== "exploited"}
                        onClick={() => setBountyFinding(f)}>
                        <Send className="h-3 w-3" /> Submit
                      </Button>
                      <Button variant="ghost" size="icon" className="h-7 w-7 text-muted-foreground hover:text-destructive" onClick={() => deleteFinding.mutate(f.id)}>
                        <Trash2 className="h-3 w-3" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      ) : (
        <div className="text-center py-12 border border-dashed border-border rounded-lg">
          <ShieldAlert className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
          <p className="text-xs font-mono text-muted-foreground">
            {activeTargetFilter ? "No findings for this target." : "No vulnerabilities found yet. Run scans to discover findings."}
          </p>
          {activeTargetFilter && (
            <Button variant="ghost" size="sm" className="mt-2 font-mono text-[10px]" onClick={() => setActiveTargetFilter(null)}>
              Clear Filter
            </Button>
          )}
        </div>
      )}

      {selectedFinding && (
        <ValidationModal
          open={!!selectedFinding}
          onOpenChange={(open) => { if (!open) setSelectedFinding(null); }}
          finding={{ id: selectedFinding.id, title: selectedFinding.title, severity: selectedFinding.severity, description: selectedFinding.description, payload_used: selectedFinding.payload, cvss_score: selectedFinding.cvss_score, target_id: selectedFinding.target_id }}
          source="finding"
        />
      )}
      {adaptiveFinding && (
        <AdaptiveValidationModal
          open={!!adaptiveFinding}
          onOpenChange={(open) => { if (!open) setAdaptiveFinding(null); }}
          finding={{ id: adaptiveFinding.id, title: adaptiveFinding.title, severity: adaptiveFinding.severity, description: adaptiveFinding.description, payload_used: adaptiveFinding.payload, cvss_score: adaptiveFinding.cvss_score, target_id: adaptiveFinding.target_id }}
          source="finding"
        />
      )}
      <FindingDetailsDialog
        open={!!detailsFinding}
        onOpenChange={(open) => { if (!open) setDetailsFinding(null); }}
        finding={detailsFinding}
      />
      {bountyFinding && (
        <SubmitBountyDialog open={!!bountyFinding} onOpenChange={(o) => { if (!o) setBountyFinding(null); }} finding={bountyFinding} />
      )}
      {sandboxFinding && (
        <SandboxRunDialog open={!!sandboxFinding} onOpenChange={(o) => { if (!o) setSandboxFinding(null); }} finding={sandboxFinding} />
      )}
    </div>
  );
}
