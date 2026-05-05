import { useState, useMemo, useCallback } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ShieldAlert, Shield, Trash2, BrainCircuit, Gauge, Ban, Filter, X, FileDown, Send, Box } from "lucide-react";
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

  const { data: findings, isLoading } = useQuery({
    queryKey: ["findings"],
    queryFn: async () => {
      const { data } = await supabase
        .from("vulnerability_findings")
        .select("*, target_workspaces(name)")
        .order("created_at", { ascending: false });
      return data || [];
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

  const filteredFindings = useMemo(() => {
    if (!findings) return [];
    if (!activeTargetFilter) return findings;
    return findings.filter((f: any) => f.target_id === activeTargetFilter);
  }, [findings, activeTargetFilter]);

  const deleteFinding = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await supabase.from("vulnerability_findings").delete().eq("id", id);
      if (error) throw error;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["findings"] });
      toast.success("Finding deleted");
    },
  });

  const clearAllFindings = useMutation({
    mutationFn: async () => {
      const { error } = await supabase.from("vulnerability_findings").delete().neq("id", "00000000-0000-0000-0000-000000000000");
      if (error) throw error;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["findings"] });
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
      queryClient.invalidateQueries({ queryKey: ["findings"] });
      toast.success(`AI Triage: ${result.classification} (${result.confidenceScore}%)`);
    } catch {
      toast.error("AI triage failed");
    } finally {
      setTriaging(null);
    }
  };

  const getConfidenceColor = (score: number | null | undefined) => {
    if (!score) return "text-muted-foreground";
    if (score >= 90) return "text-cyber-green";
    if (score >= 85) return "text-cyber-cyan";
    if (score >= 50) return "text-cyber-amber";
    return "text-cyber-red";
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
                    <Badge variant="outline" className={`text-[9px] font-mono ${f.validation_status === "verified" ? "text-cyber-green border-cyber-green/30" : "text-muted-foreground"}`}>
                      {f.validation_status || "unverified"}
                    </Badge>
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
    </div>
  );
}
