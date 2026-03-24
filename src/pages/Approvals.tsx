import { useEffect, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { CheckCircle, XCircle, AlertTriangle, Eye, ShieldCheck, Shield } from "lucide-react";
import { toast } from "sonner";
import ValidationModal from "@/components/ValidationModal";
import AdaptiveValidationModal from "@/components/AdaptiveValidationModal";

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
  target_workspaces?: { name: string } | null;
}

export default function Approvals() {
  const queryClient = useQueryClient();
  const [selected, setSelected] = useState<Approval | null>(null);
  const [notes, setNotes] = useState("");
  const [validationTarget, setValidationTarget] = useState<Approval | null>(null);
  const [adaptiveTarget, setAdaptiveTarget] = useState<Approval | null>(null);

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

  // Realtime subscription for new approvals
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

      // If approved, create a vulnerability finding
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

  const pendingCount = approvals?.filter((a) => a.status === "pending").length || 0;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold font-mono text-primary text-glow-green">HITL Approval Queue</h1>
          <p className="text-xs font-mono text-muted-foreground">
            {pendingCount} findings awaiting human review
          </p>
        </div>
        <Badge variant="outline" className={`font-mono text-xs ${pendingCount > 0 ? "bg-cyber-amber/20 text-cyber-amber border-cyber-amber/30 animate-pulse-glow" : "text-muted-foreground"}`}>
          {pendingCount} Pending
        </Badge>
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
                <Badge variant="outline" className={`text-[9px] font-mono ${severityBadge[approval.severity]}`}>
                  {approval.severity}
                </Badge>
                <Badge variant="outline" className={`text-[9px] font-mono ${statusBadge[approval.status]}`}>
                  {approval.status}
                </Badge>
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
                <div className="flex gap-2">
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
                </div>

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

                {/* Reviewer Notes */}
                <div>
                  <p className="text-[10px] font-mono uppercase text-muted-foreground mb-1">Reviewer Notes</p>
                  <textarea
                    value={notes}
                    onChange={(e) => setNotes(e.target.value)}
                    placeholder="Add notes about this finding..."
                    className="w-full bg-muted border border-border rounded p-2 text-xs font-mono text-card-foreground resize-none h-16 focus:outline-none focus:ring-1 focus:ring-primary"
                  />
                </div>

                {/* Action Buttons */}
                {selected.status === "pending" && (
                  <div className="flex gap-2">
                    <Button
                      size="sm"
                      className="flex-1 font-mono text-xs gap-1 bg-cyber-green/20 text-cyber-green hover:bg-cyber-green/30 border border-cyber-green/30"
                      onClick={() => updateApproval.mutate({ id: selected.id, status: "approved" })}
                      disabled={updateApproval.isPending}
                    >
                      <CheckCircle className="h-3 w-3" /> Confirm & Log
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      className="flex-1 font-mono text-xs gap-1"
                      onClick={() => updateApproval.mutate({ id: selected.id, status: "rejected" })}
                      disabled={updateApproval.isPending}
                    >
                      <XCircle className="h-3 w-3" /> False Positive
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      className="font-mono text-xs gap-1 border-cyber-purple/30 text-cyber-purple hover:bg-cyber-purple/10"
                      onClick={() => updateApproval.mutate({ id: selected.id, status: "escalated" })}
                      disabled={updateApproval.isPending}
                    >
                      <Eye className="h-3 w-3" /> Escalate
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      className="font-mono text-xs gap-1 border-primary/30 text-primary hover:bg-primary/10"
                      onClick={() => { setValidationTarget(selected); setSelected(null); }}
                    >
                      <Shield className="h-3 w-3" /> Validate
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      className="font-mono text-xs gap-1 border-cyber-amber/30 text-cyber-amber hover:bg-cyber-amber/10"
                      onClick={() => { setAdaptiveTarget(selected); setSelected(null); }}
                    >
                      <Shield className="h-3 w-3" /> Adaptive
                    </Button>
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
            id: validationTarget.id,
            title: validationTarget.title,
            severity: validationTarget.severity,
            description: validationTarget.description,
            parameter: validationTarget.parameter,
            payload_used: validationTarget.payload_used,
            cvss_score: validationTarget.cvss_score,
            finding_type: validationTarget.finding_type,
            target_id: validationTarget.target_id,
          }}
          source="approval"
        />
      )}
    </div>
  );
}
