import { useEffect, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { CheckCircle, XCircle, AlertTriangle, Eye, ShieldCheck, Shield, Trash2, BrainCircuit, Ban, Gauge } from "lucide-react";
import { toast } from "sonner";
import ValidationModal from "@/components/ValidationModal";
import AdaptiveValidationModal from "@/components/AdaptiveValidationModal";
import { markAsFalsePositive } from "@/services/LearningService";
import { triageFinding } from "@/services/TriageBrain";
import { deepTriageFinding } from "@/services/DeepSignalTriage";

const severityBadge: Record<string, string> = {
  critical: "bg-cyber-red/20 text-cyber-red border-cyber-red/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-cyber-amber/20 text-cyber-amber border-cyber-amber/30",
  low: "bg-cyber-green/20 text-cyber-green border-cyber-green/30",
  info: "bg-cyber-cyan/20 text-cyber-cyan border-cyber-cyan/30",
};

const statusBadge: Record<string, string> = {
  pending: "bg-cyber-amber/20 text-cyber-amber border-cyber-amber/30",
  approved: "bg-cyber-green/20 text-cyber-green border-cyber-green/30",
  rejected: "bg-muted text-muted-foreground border-border",
  escalated: "bg-cyber-purple/20 text-cyber-purple border-cyber-purple/30",
};

const confidenceBadge: Record<string, string> = {
  high: "bg-cyber-green/20 text-cyber-green border-cyber-green/30",
  medium: "bg-cyber-amber/20 text-cyber-amber border-cyber-amber/30",
  low: "bg-cyber-red/20 text-cyber-red border-cyber-red/30",
};

interface Approval {
  id: string;
  target_id: string;
  endpoint_id: string | null;
  finding_type: string;
  severity: string;
  title: string;
  description: string | null;
  evidence: Record<string, unknown>;
  parameter: string | null;
  payload_used: string | null;
  baseline_response: Record<string, unknown> | null;
  mutated_response: Record<string, unknown> | null;
  cve_ids: string[] | null;
  cvss_score: number | null;
  status: string;
  reviewer_notes: string | null;
  created_at: string;
  reviewed_at: string | null;
  confidence_level?: string | null;
  confidence_score?: number | null;
  ai_verified?: boolean | null;
  ai_verification_notes?: string | null;
  request_data?: Record<string, unknown> | null;
  response_data?: Record<string, unknown> | null;
  reachability_status?: string | null;
  triage_reasoning?: string | null;
  target_workspaces?: { name: string } | null;
}

export default function Approvals() {
  const queryClient = useQueryClient();
  const [selected, setSelected] = useState<Approval | null>(null);
  const [notes, setNotes] = useState("");
  const [validationTarget, setValidationTarget] = useState<Approval | null>(null);
  const [adaptiveTarget, setAdaptiveTarget] = useState<Approval | null>(null);
  const [triaging, setTriaging] = useState<string | null>(null);
  const [deepTriaging, setDeepTriaging] = useState<string | null>(null);

  const { data: approvals, isLoading } = useQuery({
    queryKey: ["approvals"],
    queryFn: async () => {
      const { data } = await supabase
        .from("pending_approvals")
        .select("*, target_workspaces(name)")
        .order("created_at", { ascending: false });
      return (data || []) as Approval[];
    },
  });

  useEffect(() => {
    const channel = supabase
      .channel("approvals-realtime")
      .on("postgres_changes", { event: "INSERT", schema: "public", table: "pending_approvals" }, () => {
        queryClient.invalidateQueries({ queryKey: ["approvals"] });
        toast.info("New finding requires review");
      })
      .subscribe();
    return () => { supabase.removeChannel(channel); };
  }, [queryClient]);

  const updateApproval = useMutation({
    mutationFn: async ({ id, status }: { id: string; status: string }) => {
      const update: Record<string, unknown> = {
        status,
        reviewed_at: new Date().toISOString(),
        reviewer_notes: notes || null,
      };

      const { error } = await supabase.from("pending_approvals").update(update).eq("id", id);
      if (error) throw error;

      if (status === "approved" && selected) {
        await supabase.from("vulnerability_findings").insert([{
          target_id: selected.target_id,
          endpoint_id: selected.endpoint_id,
          title: selected.title,
          severity: selected.severity as any,
          cvss_score: selected.cvss_score,
          description: selected.description,
          poc: selected.payload_used ? `Payload: ${selected.payload_used}` : null,
          payload: selected.payload_used,
          remediation: (selected.evidence as any)?.remediation || null,
          confidence_level: selected.confidence_level || "medium",
          confidence_score: selected.confidence_score || 0,
          ai_verified: selected.ai_verified || false,
          triage_reasoning: selected.triage_reasoning,
          reachability_status: selected.reachability_status,
        }]);
      }
    },
    onSuccess: (_, { status }) => {
      queryClient.invalidateQueries({ queryKey: ["approvals"] });
      queryClient.invalidateQueries({ queryKey: ["findings"] });
      toast.success(`Finding ${status}`);
      setSelected(null);
      setNotes("");
    },
    onError: (e) => toast.error(e.message),
  });

  const handleFalsePositive = async (approval: Approval) => {
    const success = await markAsFalsePositive(
      approval.finding_type,
      (approval.evidence as any)?.vulnClass || null,
      approval.request_data || {},
      approval.response_data || {},
      notes || "Marked as false positive by human reviewer",
      approval.target_id
    );
    if (success) {
      updateApproval.mutate({ id: approval.id, status: "rejected" });
      toast.success("False positive recorded — pattern added to suppression database");
    } else {
      toast.error("Failed to record suppression vector");
    }
  };

  const handleAiTriage = async (approval: Approval) => {
    setTriaging(approval.id);
    try {
      const result = await triageFinding({
        title: approval.title,
        vulnClass: (approval.evidence as any)?.vulnClass || approval.finding_type,
        severity: approval.severity,
        payload: approval.payload_used || "",
        requestData: approval.request_data || {},
        responseData: approval.response_data || {},
        baselineResponse: approval.baseline_response || {},
        mutatedResponse: approval.mutated_response || {},
        reachabilityStatus: approval.reachability_status || "unknown",
      });

      await supabase.from("pending_approvals").update({
        confidence_score: result.confidenceScore,
        triage_reasoning: result.reasoning,
        ai_verified: result.classification === "deep_finding" || result.classification === "confirmed",
        confidence_level: result.confidenceScore >= 80 ? "high" : result.confidenceScore >= 50 ? "medium" : "low",
      }).eq("id", approval.id);

      queryClient.invalidateQueries({ queryKey: ["approvals"] });
      toast.success(`AI Triage: ${result.classification} (${result.confidenceScore}%)`);
    } catch {
      toast.error("AI triage failed");
    } finally {
      setTriaging(null);
    }
  };

  const handleDeepTriage = async (approval: Approval) => {
    setDeepTriaging(approval.id);
    try {
      const result = await deepTriageFinding({
        findingTitle: approval.title,
        vulnClass: (approval.evidence as any)?.vulnClass || approval.finding_type,
        severity: approval.severity,
        payload: approval.payload_used || "",
        baselineResponse: approval.baseline_response || {},
        mutatedResponse: approval.mutated_response || {},
        intruderResults: (approval.evidence as any)?.intruderResults || [],
        techStack: {},
        confidenceScore: approval.confidence_score || 0,
      });

      const newScore = result.confidenceScore;
      await supabase.from("pending_approvals").update({
        confidence_score: newScore,
        triage_reasoning: `[Deep Signal Judge] ${result.reasoning}\n\nVerdict: ${result.verdict} | Math consistency: ${result.mathematicalConsistency}% | Evidence chain: ${result.evidenceChainValid ? "Valid" : "Invalid"}\n\nRecommendations: ${result.recommendations.join("; ")}`,
        ai_verified: result.verdict === "promote",
        confidence_level: newScore >= 80 ? "high" : newScore >= 50 ? "medium" : "low",
      }).eq("id", approval.id);

      queryClient.invalidateQueries({ queryKey: ["approvals"] });
      toast.success(`Deep Triage: ${result.verdict} (${newScore}%, math: ${result.mathematicalConsistency}%)`);
    } catch {
      toast.error("Deep signal triage failed");
    } finally {
      setDeepTriaging(null);
    }
  };

  const deleteApproval = useMutation({
    mutationFn: async (id: string) => {
      const { error } = await supabase.from("pending_approvals").delete().eq("id", id);
      if (error) throw error;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["approvals"] });
      toast.success("Approval deleted");
    },
  });

  const clearAllApprovals = useMutation({
    mutationFn: async () => {
      const { error } = await supabase.from("pending_approvals").delete().neq("id", "00000000-0000-0000-0000-000000000000");
      if (error) throw error;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["approvals"] });
      toast.success("All approvals cleared");
    },
  });

  const pendingCount = approvals?.filter((a) => a.status === "pending").length || 0;

  const getConfidenceColor = (score: number | null | undefined) => {
    if (!score) return "text-muted-foreground";
    if (score >= 90) return "text-cyber-green";
    if (score >= 85) return "text-cyber-cyan";
    if (score >= 50) return "text-cyber-amber";
    return "text-cyber-red";
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold font-mono text-primary text-glow-green">HITL Approval Queue</h1>
          <p className="text-xs font-mono text-muted-foreground">
            {pendingCount} findings awaiting human review
          </p>
        </div>
        <div className="flex gap-2">
          <Badge variant="outline" className={`font-mono text-xs ${pendingCount > 0 ? "bg-cyber-amber/20 text-cyber-amber border-cyber-amber/30 animate-pulse-glow" : "text-muted-foreground"}`}>
            {pendingCount} Pending
          </Badge>
          {approvals && approvals.length > 0 && (
            <Button
              variant="outline" size="sm"
              className="font-mono text-[10px] gap-1 text-destructive border-destructive/30 hover:bg-destructive/10"
              onClick={() => { if (confirm("Clear all approvals?")) clearAllApprovals.mutate(); }}
            >
              <Trash2 className="h-3 w-3" /> Clear All
            </Button>
          )}
        </div>
      </div>

      {isLoading ? (
        <p className="text-xs font-mono text-muted-foreground">Loading approvals...</p>
      ) : approvals && approvals.length > 0 ? (
        <div className="space-y-2">
          {approvals.map((approval) => (
            <div
              key={approval.id}
              className="rounded-lg border border-border bg-card p-4 flex items-center justify-between hover:border-primary/30 transition-colors cursor-pointer"
              onClick={() => { setSelected(approval); setNotes(approval.reviewer_notes || ""); }}
            >
              <div className="flex items-center gap-3 flex-1 min-w-0">
                <AlertTriangle className={`h-4 w-4 shrink-0 ${approval.severity === "critical" ? "text-cyber-red" : approval.severity === "high" ? "text-orange-400" : "text-cyber-amber"}`} />
                <div className="min-w-0">
                  <p className="text-sm font-mono font-semibold text-card-foreground truncate">{approval.title}</p>
                  <p className="text-[10px] font-mono text-muted-foreground">
                    {approval.finding_type} • {approval.target_workspaces?.name || "Unknown target"}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                {approval.confidence_score != null && approval.confidence_score > 0 && (
                  <Badge variant="outline" className={`text-[9px] font-mono ${getConfidenceColor(approval.confidence_score)} border-current/30 gap-0.5`}>
                    <Gauge className="h-2.5 w-2.5" /> {approval.confidence_score}%
                  </Badge>
                )}
                {(approval.evidence as any)?.gauntletProof?.proven && (
                  <Badge variant="outline" className="text-[9px] font-mono bg-cyber-green/20 text-cyber-green border-cyber-green/30 gap-0.5">
                    🛡️ Proven
                  </Badge>
                )}
                {(approval.evidence as any)?.peerReview?.verdict === "upheld" && (
                  <Badge variant="outline" className="text-[9px] font-mono bg-cyber-cyan/20 text-cyber-cyan border-cyber-cyan/30 gap-0.5">
                    🤔 Upheld
                  </Badge>
                )}
                {(approval.evidence as any)?.peerReview?.verdict === "disputed" && (
                  <Badge variant="outline" className="text-[9px] font-mono bg-cyber-red/20 text-cyber-red border-cyber-red/30 gap-0.5">
                    🤔 Disputed
                  </Badge>
                )}
                {approval.ai_verified && (
                  <Badge variant="outline" className="text-[9px] font-mono bg-cyber-green/20 text-cyber-green border-cyber-green/30 gap-0.5">
                    <BrainCircuit className="h-2.5 w-2.5" /> AI ✓
                  </Badge>
                )}
                {approval.confidence_level && (
                  <Badge variant="outline" className={`text-[9px] font-mono ${confidenceBadge[approval.confidence_level] || ""}`}>
                    {approval.confidence_level}
                  </Badge>
                )}
                <Badge variant="outline" className={`text-[9px] font-mono ${severityBadge[approval.severity]}`}>
                  {approval.severity}
                </Badge>
                <Badge variant="outline" className={`text-[9px] font-mono ${statusBadge[approval.status]}`}>
                  {approval.status}
                </Badge>
                <Button
                  variant="ghost" size="icon" className="h-6 w-6 text-muted-foreground hover:text-destructive"
                  onClick={(e) => { e.stopPropagation(); deleteApproval.mutate(approval.id); }}
                >
                  <Trash2 className="h-3 w-3" />
                </Button>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="text-center py-12 border border-dashed border-border rounded-lg">
          <ShieldCheck className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
          <p className="text-xs font-mono text-muted-foreground">No findings in queue. Run a vulnerability scan to generate findings.</p>
        </div>
      )}

      {/* Detail Dialog */}
      <Dialog open={!!selected} onOpenChange={(open) => { if (!open) setSelected(null); }}>
        <DialogContent className="bg-card border-border max-w-2xl max-h-[80vh] overflow-auto">
          {selected && (
            <>
              <DialogHeader>
                <DialogTitle className="font-mono text-primary text-sm">{selected.title}</DialogTitle>
              </DialogHeader>
              <div className="space-y-4">
                <div className="flex gap-2 flex-wrap">
                  <Badge variant="outline" className={`text-[9px] font-mono ${severityBadge[selected.severity]}`}>
                    {selected.severity}
                  </Badge>
                  <Badge variant="outline" className="text-[9px] font-mono text-muted-foreground">
                    {selected.finding_type}
                  </Badge>
                  {selected.cvss_score && (
                    <Badge variant="outline" className="text-[9px] font-mono text-cyber-amber border-cyber-amber/30">
                      CVSS {selected.cvss_score}
                    </Badge>
                  )}
                  {selected.confidence_score != null && selected.confidence_score > 0 && (
                    <Badge variant="outline" className={`text-[9px] font-mono ${getConfidenceColor(selected.confidence_score)} border-current/30 gap-0.5`}>
                      <Gauge className="h-2.5 w-2.5" /> {selected.confidence_score}%
                    </Badge>
                  )}
                  {selected.confidence_level && (
                    <Badge variant="outline" className={`text-[9px] font-mono ${confidenceBadge[selected.confidence_level] || ""}`}>
                      Confidence: {selected.confidence_level}
                    </Badge>
                  )}
                  {selected.ai_verified && (
                    <Badge variant="outline" className="text-[9px] font-mono bg-cyber-green/20 text-cyber-green border-cyber-green/30 gap-0.5">
                      <BrainCircuit className="h-2.5 w-2.5" /> AI Verified
                    </Badge>
                  )}
                  {selected.reachability_status && selected.reachability_status !== "unknown" && (
                    <Badge variant="outline" className={`text-[9px] font-mono ${selected.reachability_status === "reachable" ? "text-cyber-red border-cyber-red/30" : "text-cyber-green border-cyber-green/30"}`}>
                      {selected.reachability_status === "reachable" ? "🌐 Public" : "🛡️ Protected"}
                    </Badge>
                  )}
                </div>

                {/* Phase 9: Gauntlet Proof & Peer Review */}
                {(selected.evidence as any)?.gauntletProof && (
                  <div className={`border rounded-lg p-3 ${(selected.evidence as any).gauntletProof.proven ? "border-cyber-green/30 bg-cyber-green/5" : "border-cyber-amber/30 bg-cyber-amber/5"}`}>
                    <p className="text-[10px] font-mono uppercase mb-1 flex items-center gap-1">
                      🛡️ <span className={(selected.evidence as any).gauntletProof.proven ? "text-cyber-green" : "text-cyber-amber"}>
                        Gauntlet Proof: {(selected.evidence as any).gauntletProof.proven ? "PROVEN" : "UNPROVEN"}
                      </span>
                    </p>
                    <p className="text-xs font-mono text-card-foreground">{(selected.evidence as any).gauntletProof.mathematicalBasis}</p>
                    <p className="text-[10px] font-mono text-muted-foreground mt-1">Type: {(selected.evidence as any).gauntletProof.proofType}</p>
                  </div>
                )}

                {(selected.evidence as any)?.peerReview && (
                  <div className={`border rounded-lg p-3 ${(selected.evidence as any).peerReview.verdict === "upheld" ? "border-cyber-green/30 bg-cyber-green/5" : (selected.evidence as any).peerReview.verdict === "disputed" ? "border-cyber-red/30 bg-cyber-red/5" : "border-cyber-amber/30 bg-cyber-amber/5"}`}>
                    <p className="text-[10px] font-mono uppercase mb-1 flex items-center gap-1">
                      🤔 <span className={(selected.evidence as any).peerReview.verdict === "upheld" ? "text-cyber-green" : "text-cyber-red"}>
                        Peer Review: {(selected.evidence as any).peerReview.verdict.toUpperCase()}
                      </span>
                      <span className="text-muted-foreground ml-2">Skeptic Score: {(selected.evidence as any).peerReview.skepticScore}</span>
                    </p>
                    <p className="text-xs font-mono text-card-foreground">{(selected.evidence as any).peerReview.reasoning}</p>
                    <p className="text-[10px] font-mono text-muted-foreground mt-1">Final Confidence: {Math.round((selected.evidence as any).peerReview.finalConfidence)}%</p>
                  </div>
                )}

                {/* AI Triage Reasoning */}
                {selected.triage_reasoning && (
                  <div className="border border-primary/20 rounded-lg p-3 bg-primary/5">
                    <p className="text-[10px] font-mono uppercase text-primary mb-1 flex items-center gap-1">
                      <BrainCircuit className="h-3 w-3" /> AI Triage Reasoning
                    </p>
                    <p className="text-xs font-mono text-card-foreground whitespace-pre-wrap">{selected.triage_reasoning}</p>
                  </div>
                )}

                {selected.ai_verification_notes && (
                  <div>
                    <p className="text-[10px] font-mono uppercase text-muted-foreground mb-1">AI Verification Notes</p>
                    <p className="text-xs font-mono text-card-foreground bg-muted/50 p-2 rounded border border-border">{selected.ai_verification_notes}</p>
                  </div>
                )}

                {selected.description && (
                  <div>
                    <p className="text-[10px] font-mono uppercase text-muted-foreground mb-1">Description</p>
                    <p className="text-xs font-mono text-card-foreground whitespace-pre-wrap">{selected.description}</p>
                  </div>
                )}

                {selected.parameter && (
                  <div>
                    <p className="text-[10px] font-mono uppercase text-muted-foreground mb-1">Parameter</p>
                    <code className="text-xs font-mono text-cyber-cyan bg-muted px-2 py-1 rounded">{selected.parameter}</code>
                  </div>
                )}

                {selected.payload_used && (
                  <div>
                    <p className="text-[10px] font-mono uppercase text-muted-foreground mb-1">Payload Used</p>
                    <code className="text-xs font-mono text-cyber-amber bg-muted px-2 py-1 rounded block">{selected.payload_used}</code>
                  </div>
                )}

                {selected.request_data && Object.keys(selected.request_data).length > 0 && (
                  <div>
                    <p className="text-[10px] font-mono uppercase text-muted-foreground mb-1">📡 Request (Repeater)</p>
                    <pre className="text-[10px] font-mono text-card-foreground bg-muted p-2 rounded overflow-auto max-h-32 border border-border">
                      {JSON.stringify(selected.request_data, null, 2)}
                    </pre>
                  </div>
                )}

                {selected.response_data && Object.keys(selected.response_data).length > 0 && (
                  <div>
                    <p className="text-[10px] font-mono uppercase text-muted-foreground mb-1">📥 Response</p>
                    <pre className="text-[10px] font-mono text-card-foreground bg-muted p-2 rounded overflow-auto max-h-32 border border-border">
                      {JSON.stringify(selected.response_data, null, 2)}
                    </pre>
                  </div>
                )}

                {selected.baseline_response && (
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <p className="text-[10px] font-mono uppercase text-muted-foreground mb-1">Baseline Response</p>
                      <pre className="text-[10px] font-mono text-card-foreground bg-muted p-2 rounded overflow-auto max-h-24">
                        {JSON.stringify(selected.baseline_response, null, 2)}
                      </pre>
                    </div>
                    <div>
                      <p className="text-[10px] font-mono uppercase text-muted-foreground mb-1">Mutated Response</p>
                      <pre className="text-[10px] font-mono text-card-foreground bg-muted p-2 rounded overflow-auto max-h-24">
                        {JSON.stringify(selected.mutated_response, null, 2)}
                      </pre>
                    </div>
                  </div>
                )}

                {(selected.evidence as any)?.intruderResults && (
                  <div>
                    <p className="text-[10px] font-mono uppercase text-muted-foreground mb-1">🎯 Intruder Results</p>
                    <div className="space-y-1">
                      {((selected.evidence as any).intruderResults as Array<{ payload: string; status: number; length: number; timingMs: number }>).map((ir, idx) => (
                        <div key={idx} className="flex items-center gap-2 text-[10px] font-mono bg-muted p-1.5 rounded">
                          <Badge variant="outline" className={`text-[8px] ${ir.status === 200 ? "text-cyber-green border-cyber-green/30" : "text-cyber-red border-cyber-red/30"}`}>
                            {ir.status}
                          </Badge>
                          <span className="text-card-foreground truncate flex-1">{ir.payload}</span>
                          <span className="text-muted-foreground">{ir.length}B</span>
                          <span className="text-muted-foreground">{ir.timingMs}ms</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {selected.cve_ids && selected.cve_ids.length > 0 && (
                  <div>
                    <p className="text-[10px] font-mono uppercase text-muted-foreground mb-1">CVE References</p>
                    <div className="flex flex-wrap gap-1">
                      {selected.cve_ids.map((cve) => (
                        <Badge key={cve} variant="outline" className="text-[9px] font-mono text-cyber-red border-cyber-red/30">
                          {cve}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                <div>
                  <p className="text-[10px] font-mono uppercase text-muted-foreground mb-1">Evidence</p>
                  <pre className="text-[10px] font-mono text-card-foreground bg-muted p-2 rounded overflow-auto max-h-32">
                    {JSON.stringify(selected.evidence, null, 2)}
                  </pre>
                </div>

                <div>
                  <p className="text-[10px] font-mono uppercase text-muted-foreground mb-1">Reviewer Notes</p>
                  <textarea
                    value={notes}
                    onChange={(e) => setNotes(e.target.value)}
                    placeholder="Add notes about this finding..."
                    className="w-full bg-muted border border-border rounded p-2 text-xs font-mono text-card-foreground resize-none h-16 focus:outline-none focus:ring-1 focus:ring-primary"
                  />
                </div>

                {selected.status === "pending" && (
                  <div className="space-y-2">
                    {/* AI Triage Button */}
                    <Button
                      size="sm" className="w-full font-mono text-xs gap-1 bg-primary/20 text-primary hover:bg-primary/30 border border-primary/30"
                      onClick={() => handleAiTriage(selected)}
                      disabled={triaging === selected.id}
                    >
                      <BrainCircuit className="h-3 w-3" />
                      {triaging === selected.id ? "AI Triaging..." : "🧠 Run AI Triage"}
                    </Button>

                    <Button
                      size="sm" className="w-full font-mono text-xs gap-1 bg-cyber-purple/20 text-cyber-purple hover:bg-cyber-purple/30 border border-cyber-purple/30"
                      onClick={() => handleDeepTriage(selected)}
                      disabled={deepTriaging === selected.id}
                    >
                      <Gauge className="h-3 w-3" />
                      {deepTriaging === selected.id ? "Deep Judging..." : "🔬 Deep Signal Triage"}
                    </Button>

                    <div className="flex gap-2 flex-wrap">
                      <Button
                        size="sm"
                        className="flex-1 font-mono text-xs gap-1 bg-cyber-green/20 text-cyber-green hover:bg-cyber-green/30 border border-cyber-green/30"
                        onClick={() => updateApproval.mutate({ id: selected.id, status: "approved" })}
                        disabled={updateApproval.isPending}
                      >
                        <CheckCircle className="h-3 w-3" /> Confirm & Log
                      </Button>
                      <Button
                        size="sm" variant="outline"
                        className="flex-1 font-mono text-xs gap-1 text-cyber-red border-cyber-red/30 hover:bg-cyber-red/10"
                        onClick={() => handleFalsePositive(selected)}
                        disabled={updateApproval.isPending}
                      >
                        <Ban className="h-3 w-3" /> False Positive + Learn
                      </Button>
                      <Button
                        size="sm" variant="outline"
                        className="font-mono text-xs gap-1 border-cyber-purple/30 text-cyber-purple hover:bg-cyber-purple/10"
                        onClick={() => updateApproval.mutate({ id: selected.id, status: "escalated" })}
                        disabled={updateApproval.isPending}
                      >
                        <Eye className="h-3 w-3" /> Escalate
                      </Button>
                    </div>
                    <div className="flex gap-2">
                      <Button
                        size="sm" variant="outline"
                        className="flex-1 font-mono text-xs gap-1 border-primary/30 text-primary hover:bg-primary/10"
                        onClick={() => { setValidationTarget(selected); setSelected(null); }}
                      >
                        <Shield className="h-3 w-3" /> Validate
                      </Button>
                      <Button
                        size="sm" variant="outline"
                        className="flex-1 font-mono text-xs gap-1 border-cyber-amber/30 text-cyber-amber hover:bg-cyber-amber/10"
                        onClick={() => { setAdaptiveTarget(selected); setSelected(null); }}
                      >
                        <Shield className="h-3 w-3" /> Adaptive
                      </Button>
                    </div>
                  </div>
                )}
              </div>
            </>
          )}
        </DialogContent>
      </Dialog>

      {validationTarget && (
        <ValidationModal
          open={!!validationTarget}
          onOpenChange={(open) => { if (!open) setValidationTarget(null); }}
          finding={{
            id: validationTarget.id, title: validationTarget.title,
            severity: validationTarget.severity, description: validationTarget.description,
            parameter: validationTarget.parameter, payload_used: validationTarget.payload_used,
            cvss_score: validationTarget.cvss_score, finding_type: validationTarget.finding_type,
            target_id: validationTarget.target_id,
          }}
          source="approval"
        />
      )}
      {adaptiveTarget && (
        <AdaptiveValidationModal
          open={!!adaptiveTarget}
          onOpenChange={(open) => { if (!open) setAdaptiveTarget(null); }}
          finding={{
            id: adaptiveTarget.id, title: adaptiveTarget.title,
            severity: adaptiveTarget.severity, description: adaptiveTarget.description,
            parameter: adaptiveTarget.parameter, payload_used: adaptiveTarget.payload_used,
            cvss_score: adaptiveTarget.cvss_score, finding_type: adaptiveTarget.finding_type,
            target_id: adaptiveTarget.target_id,
          }}
          source="approval"
        />
      )}
    </div>
  );
}
