import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ShieldAlert, Shield } from "lucide-react";
import ValidationModal from "@/components/ValidationModal";
import AdaptiveValidationModal from "@/components/AdaptiveValidationModal";

const severityBadge: Record<string, string> = {
  critical: "bg-cyber-red/20 text-cyber-red border-cyber-red/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-cyber-amber/20 text-cyber-amber border-cyber-amber/30",
  low: "bg-cyber-green/20 text-cyber-green border-cyber-green/30",
  info: "bg-cyber-cyan/20 text-cyber-cyan border-cyber-cyan/30",
};

export default function Findings() {
  const [selectedFinding, setSelectedFinding] = useState<any>(null);

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

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold font-mono text-primary text-glow-green">Vulnerability Findings</h1>
        <p className="text-xs font-mono text-muted-foreground">Discovered vulnerabilities with CVSS scores — click to validate</p>
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
                <TableHead className="font-mono text-[10px] uppercase text-muted-foreground">Target</TableHead>
                <TableHead className="font-mono text-[10px] uppercase text-muted-foreground">Description</TableHead>
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
                  <TableCell className="font-mono text-xs text-card-foreground">{f.title}</TableCell>
                  <TableCell className="font-mono text-xs text-cyber-amber">{f.cvss_score || "—"}</TableCell>
                  <TableCell className="font-mono text-[10px] text-muted-foreground">
                    {f.target_workspaces?.name || "—"}
                  </TableCell>
                  <TableCell className="font-mono text-[10px] text-muted-foreground max-w-xs truncate">
                    {f.description || "—"}
                  </TableCell>
                  <TableCell>
                    <Button
                      variant="outline"
                      size="sm"
                      className="font-mono text-[10px] gap-1 border-primary/30 text-primary hover:bg-primary/10"
                      onClick={() => setSelectedFinding(f)}
                    >
                      <Shield className="h-3 w-3" /> Validate
                    </Button>
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
            id: selectedFinding.id,
            title: selectedFinding.title,
            severity: selectedFinding.severity,
            description: selectedFinding.description,
            payload_used: selectedFinding.payload,
            cvss_score: selectedFinding.cvss_score,
            target_id: selectedFinding.target_id,
          }}
          source="finding"
        />
      )}
    </div>
  );
}
