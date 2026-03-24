import { useState } from "react";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { supabase } from "@/integrations/supabase/client";
import { toast } from "sonner";
import { Loader2, Play, FileText, Shield, AlertTriangle, CheckCircle, Copy } from "lucide-react";
import Editor from "@monaco-editor/react";

interface ValidationModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  finding: {
    id: string;
    title: string;
    severity: string;
    description?: string | null;
    parameter?: string | null;
    payload_used?: string | null;
    cvss_score?: number | null;
    finding_type?: string;
    target_id: string;
  };
  source: "finding" | "approval";
}

const severityBadge: Record<string, string> = {
  critical: "bg-cyber-red/20 text-cyber-red border-cyber-red/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-cyber-amber/20 text-cyber-amber border-cyber-amber/30",
  low: "bg-cyber-green/20 text-cyber-green border-cyber-green/30",
  info: "bg-cyber-cyan/20 text-cyber-cyan border-cyber-cyan/30",
};

export default function ValidationModal({ open, onOpenChange, finding, source }: ValidationModalProps) {
  const [activeTab, setActiveTab] = useState("editor");
  const [script, setScript] = useState("");
  const [terminalOutput, setTerminalOutput] = useState("");
  const [report, setReport] = useState("");
  const [isGenerating, setIsGenerating] = useState(false);
  const [isValidating, setIsValidating] = useState(false);
  const [isReporting, setIsReporting] = useState(false);
  const [validationResult, setValidationResult] = useState<string | null>(null);
  const [evidencePackageId, setEvidencePackageId] = useState<string | null>(null);

  const generatePoC = async () => {
    setIsGenerating(true);
    try {
      const body = source === "approval" ? { approvalId: finding.id } : { findingId: finding.id };
      const { data, error } = await supabase.functions.invoke("generate-poc", { body });
      if (error) throw error;
      if (data?.error) throw new Error(data.error);
      setScript(data.script || "");
      toast.success("PoC script generated");
    } catch (e: any) {
      toast.error(e.message || "Failed to generate PoC");
    } finally {
      setIsGenerating(false);
    }
  };

  const runValidation = async () => {
    if (!script.trim()) {
      toast.error("No script to validate");
      return;
    }
    setIsValidating(true);
    setTerminalOutput("[INIT] Validation engine starting...\n");
    setActiveTab("terminal");
    
    try {
      const { data, error } = await supabase.functions.invoke("validate-finding", {
        body: {
          findingId: source === "finding" ? finding.id : null,
          approvalId: source === "approval" ? finding.id : null,
          targetId: finding.target_id,
          script,
          action: "validate",
        },
      });
      if (error) throw error;
      if (data?.error) throw new Error(data.error);

      setTerminalOutput(data.terminalOutput || "No output captured.");
      setValidationResult(data.validationResult);
      setEvidencePackageId(data.evidencePackageId);
      toast.success(`Validation complete: ${data.validationResult}`);
    } catch (e: any) {
      setTerminalOutput((prev) => prev + `\n[ERROR] ${e.message}\n[ABORT] Validation failed.`);
      toast.error(e.message || "Validation failed");
    } finally {
      setIsValidating(false);
    }
  };

  const generateReport = async () => {
    if (!evidencePackageId) {
      toast.error("Run validation first to create an evidence package");
      return;
    }
    setIsReporting(true);
    setActiveTab("report");

    try {
      const { data, error } = await supabase.functions.invoke("validate-finding", {
        body: { findingId: evidencePackageId, action: "report" },
      });
      if (error) throw error;
      if (data?.error) throw new Error(data.error);

      setReport(data.report || "Report generation failed.");
      toast.success("Remediation report generated");
    } catch (e: any) {
      toast.error(e.message || "Failed to generate report");
    } finally {
      setIsReporting(false);
    }
  };

  const copyReport = () => {
    navigator.clipboard.writeText(report);
    toast.success("Report copied to clipboard");
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-card border-border max-w-4xl max-h-[90vh] overflow-hidden flex flex-col">
        <DialogHeader>
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-primary" />
            <DialogTitle className="font-mono text-primary text-sm">Validation Workspace</DialogTitle>
          </div>
          <div className="flex items-center gap-2 mt-1">
            <Badge variant="outline" className={`text-[9px] font-mono ${severityBadge[finding.severity]}`}>
              {finding.severity}
            </Badge>
            <span className="text-xs font-mono text-card-foreground">{finding.title}</span>
            {finding.cvss_score && (
              <Badge variant="outline" className="text-[9px] font-mono text-cyber-amber border-cyber-amber/30">
                CVSS {finding.cvss_score}
              </Badge>
            )}
            {validationResult && (
              <Badge variant="outline" className={`text-[9px] font-mono ${
                validationResult === "confirmed" ? "bg-cyber-red/20 text-cyber-red border-cyber-red/30" :
                validationResult === "likely" ? "bg-cyber-amber/20 text-cyber-amber border-cyber-amber/30" :
                "bg-muted text-muted-foreground border-border"
              }`}>
                {validationResult === "confirmed" ? "⚠ CONFIRMED" : validationResult === "likely" ? "LIKELY" : "INCONCLUSIVE"}
              </Badge>
            )}
          </div>
        </DialogHeader>

        <div className="flex gap-2 mb-2">
          <Button
            size="sm"
            variant="outline"
            className="font-mono text-[10px] gap-1 border-primary/30 text-primary hover:bg-primary/10"
            onClick={generatePoC}
            disabled={isGenerating}
          >
            {isGenerating ? <Loader2 className="h-3 w-3 animate-spin" /> : <Shield className="h-3 w-3" />}
            {isGenerating ? "Generating..." : "Generate PoC"}
          </Button>
          <Button
            size="sm"
            variant="outline"
            className="font-mono text-[10px] gap-1 border-cyber-amber/30 text-cyber-amber hover:bg-cyber-amber/10"
            onClick={runValidation}
            disabled={isValidating || !script.trim()}
          >
            {isValidating ? <Loader2 className="h-3 w-3 animate-spin" /> : <Play className="h-3 w-3" />}
            {isValidating ? "Validating..." : "Run Validation"}
          </Button>
          <Button
            size="sm"
            variant="outline"
            className="font-mono text-[10px] gap-1 border-cyber-cyan/30 text-cyber-cyan hover:bg-cyber-cyan/10"
            onClick={generateReport}
            disabled={isReporting || !evidencePackageId}
          >
            {isReporting ? <Loader2 className="h-3 w-3 animate-spin" /> : <FileText className="h-3 w-3" />}
            {isReporting ? "Generating..." : "Generate Report"}
          </Button>
        </div>

        <Tabs value={activeTab} onValueChange={setActiveTab} className="flex-1 flex flex-col min-h-0">
          <TabsList className="bg-muted border border-border">
            <TabsTrigger value="editor" className="font-mono text-[10px]">Script Editor</TabsTrigger>
            <TabsTrigger value="terminal" className="font-mono text-[10px]">
              Terminal Output
              {validationResult && (
                <span className={`ml-1 h-2 w-2 rounded-full inline-block ${
                  validationResult === "confirmed" ? "bg-cyber-red" : validationResult === "likely" ? "bg-cyber-amber" : "bg-muted-foreground"
                }`} />
              )}
            </TabsTrigger>
            <TabsTrigger value="report" className="font-mono text-[10px]">Remediation Report</TabsTrigger>
          </TabsList>

          <TabsContent value="editor" className="flex-1 min-h-0 mt-2">
            {script ? (
              <div className="h-[400px] border border-border rounded-md overflow-hidden">
                <Editor
                  height="100%"
                  language="python"
                  theme="vs-dark"
                  value={script}
                  onChange={(v) => setScript(v || "")}
                  options={{
                    minimap: { enabled: false },
                    fontSize: 12,
                    fontFamily: "JetBrains Mono, monospace",
                    lineNumbers: "on",
                    scrollBeyondLastLine: false,
                    wordWrap: "on",
                    padding: { top: 8 },
                  }}
                />
              </div>
            ) : (
              <div className="h-[400px] flex items-center justify-center border border-dashed border-border rounded-md">
                <div className="text-center">
                  <AlertTriangle className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
                  <p className="text-xs font-mono text-muted-foreground">
                    Click "Generate PoC" to create a validation script
                  </p>
                </div>
              </div>
            )}
          </TabsContent>

          <TabsContent value="terminal" className="flex-1 min-h-0 mt-2">
            <div className="h-[400px] bg-background border border-border rounded-md p-3 overflow-auto font-mono text-xs">
              {terminalOutput ? (
                <pre className="text-cyber-green whitespace-pre-wrap">{terminalOutput}</pre>
              ) : (
                <p className="text-muted-foreground">Terminal output will appear here after validation...</p>
              )}
              {isValidating && (
                <span className="text-cyber-amber animate-pulse">█</span>
              )}
            </div>
          </TabsContent>

          <TabsContent value="report" className="flex-1 min-h-0 mt-2">
            <div className="h-[400px] border border-border rounded-md overflow-auto">
              {report ? (
                <div className="p-4">
                  <div className="flex justify-end mb-2">
                    <Button variant="ghost" size="sm" className="font-mono text-[10px] gap-1" onClick={copyReport}>
                      <Copy className="h-3 w-3" /> Copy
                    </Button>
                  </div>
                  <pre className="text-xs font-mono text-card-foreground whitespace-pre-wrap">{report}</pre>
                </div>
              ) : (
                <div className="h-full flex items-center justify-center">
                  <div className="text-center">
                    <FileText className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
                    <p className="text-xs font-mono text-muted-foreground">
                      {evidencePackageId ? "Click 'Generate Report' to create a remediation report" : "Run validation first to enable report generation"}
                    </p>
                  </div>
                </div>
              )}
            </div>
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
}
