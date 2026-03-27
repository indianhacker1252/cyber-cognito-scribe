import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ShieldAlert, Shield, Trash2, BrainCircuit } from "lucide-react";
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

const confidenceBadge: Record<string, string> = {
  high: "bg-cyber-green/20 text-cyber-green border-cyber-green/30",
  medium: "bg-cyber-amber/20 text-cyber-amber border-cyber-amber/30",
  low: "bg-cyber-red/20 text-cyber-red border-cyber-red/30",
};

export default function Findings() {
  const queryClient = useQueryClient();
  const [selectedFinding, setSelectedFinding] = useState<any>(null);
  const [adaptiveFinding, setAdaptiveFinding] = useState<any>(null);

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

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold font-mono text-primary text-glow-green">Vulnerability Findings</h1>
          <p className="text-xs font-mono text-muted-foreground">Discovered vulnerabilities with CVSS scores — click to validate</p>
        </div>
        {findings && findings.length > 0 && (
          <Button
            variant="outline" size="sm"
            className="font-mono text-[10px] gap-1 text-destructive border-destructive/30 hover:bg-destructive/10"
            onClick={() => { if (confirm("Clear all findings?")) clearAllFindings.mutate(); }}
          >
            <Trash2 className="h-3 w-3" /> Clear All
          </Button>
        )}
      </div>

      {isLoading ? (
        <p className="text-xs font-mono text-muted-foreground">Loading findings...</p>
      ) : findings && findings.length > 0 ? (
        <div className="rounded-lg border border-border overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow className="border-border hover:bg-transparent">
                <TableHead className="font-mono text-[10px] uppercase text-muted-foreground">Severity</TableHead>
                <TableHead className="font-mono text-[10px] uppercase text-muted-foreground">Title</TableHead>
                <TableHead className="font-mono text-[10px] uppercase text-muted-foreground">CVSS</TableHead>
                <TableHead className="font-mono text-[10px] uppercase text-muted-foreground">Confidence</TableHead>
                <TableHead className="font-mono text-[10px] uppercase text-muted-foreground">Target</TableHead>
                <TableHead className="font-mono text-[10px] uppercase text-muted-foreground">Status</TableHead>
                <TableHead className="font-mono text-[10px] uppercase text-muted-foreground">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {findings.map((f: any) => (
                <TableRow key={f.id} className="border-border hover:bg-muted/30">
                  <TableCell>
                    <Badge variant="outline" className={`text-[9px] font-mono ${severityBadge[f.severity]}`}>
                      {f.severity}
                    </Badge>
                  </TableCell>
                  <TableCell className="font-mono text-xs text-card-foreground max-w-xs truncate">{f.title}</TableCell>
                  <TableCell className="font-mono text-xs text-cyber-amber">{f.cvss_score || "—"}</TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1">
                      {f.confidence_level && (
                        <Badge variant="outline" className={`text-[9px] font-mono ${confidenceBadge[f.confidence_level] || ""}`}>
                          {f.confidence_level}
                        </Badge>
                      )}
                      {f.ai_verified && (
                        <BrainCircuit className="h-3 w-3 text-cyber-green" />
                      )}
                    </div>
                  </TableCell>
                  <TableCell className="font-mono text-[10px] text-muted-foreground">
                    {f.target_workspaces?.name || "—"}
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className={`text-[9px] font-mono ${f.validation_status === "verified" ? "text-cyber-green border-cyber-green/30" : "text-muted-foreground"}`}>
                      {f.validation_status || "unverified"}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex gap-1">
                      <Button
                        variant="outline" size="sm"
                        className="font-mono text-[10px] gap-1 border-primary/30 text-primary hover:bg-primary/10"
                        onClick={() => setSelectedFinding(f)}
                      >
                        <Shield className="h-3 w-3" /> Validate
                      </Button>
                      <Button
                        variant="outline" size="sm"
                        className="font-mono text-[10px] gap-1 border-cyber-amber/30 text-cyber-amber hover:bg-cyber-amber/10"
                        onClick={() => setAdaptiveFinding(f)}
                      >
                        <Shield className="h-3 w-3" /> Adaptive
                      </Button>
                      <Button
                        variant="ghost" size="icon" className="h-7 w-7 text-muted-foreground hover:text-destructive"
                        onClick={() => deleteFinding.mutate(f.id)}
                      >
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
          <p className="text-xs font-mono text-muted-foreground">No vulnerabilities found yet. Run scans to discover findings.</p>
        </div>
      )}

      {selectedFinding && (
        <ValidationModal
          open={!!selectedFinding}
          onOpenChange={(open) => { if (!open) setSelectedFinding(null); }}
          finding={{
            id: selectedFinding.id, title: selectedFinding.title,
            severity: selectedFinding.severity, description: selectedFinding.description,
            payload_used: selectedFinding.payload, cvss_score: selectedFinding.cvss_score,
            target_id: selectedFinding.target_id,
          }}
          source="finding"
        />
      )}
      {adaptiveFinding && (
        <AdaptiveValidationModal
          open={!!adaptiveFinding}
          onOpenChange={(open) => { if (!open) setAdaptiveFinding(null); }}
          finding={{
            id: adaptiveFinding.id, title: adaptiveFinding.title,
            severity: adaptiveFinding.severity, description: adaptiveFinding.description,
            payload_used: adaptiveFinding.payload, cvss_score: adaptiveFinding.cvss_score,
            target_id: adaptiveFinding.target_id,
          }}
          source="finding"
        />
      )}
    </div>
  );
}
