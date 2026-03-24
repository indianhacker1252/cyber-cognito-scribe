import { useState } from "react";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { supabase } from "@/integrations/supabase/client";
import { toast } from "sonner";
import {
  Loader2, Play, FileText, Shield, AlertTriangle, CheckCircle,
  Copy, Zap, BarChart3, ArrowRight, XCircle,
} from "lucide-react";
import Editor from "@monaco-editor/react";
import { storeEvidenceChain } from "@/services/AuditTrailStore";

interface AdaptiveValidationModalProps {
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

interface AdaptationStep {
  iteration: number;
  adaptationName: string;
  statusCode: number;
  navigated: boolean;
  reasoning: string;
  body?: string;
}

export default function AdaptiveValidationModal({
  open, onOpenChange, finding, source,
}: AdaptiveValidationModalProps) {
  const [activeTab, setActiveTab] = useState("analysis");
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isGeneratingPoc, setIsGeneratingPoc] = useState(false);
  const [isGeneratingReport, setIsGeneratingReport] = useState(false);

  const [filterClassification, setFilterClassification] = useState<string | null>(null);
  const [adaptationSteps, setAdaptationSteps] = useState<AdaptationStep[]>([]);
  const [overallResult, setOverallResult] = useState<string | null>(null);
  const [technicalSummary, setTechnicalSummary] = useState("");

  const [pocScript, setPocScript] = useState("");
  const [report, setReport] = useState("");
  const [chainId, setChainId] = useState<string | null>(null);

  const runAdaptiveAnalysis = async () => {
    setIsAnalyzing(true);
    setActiveTab("analysis");
    try {
      const { data, error } = await supabase.functions.invoke("adaptive-validate", {
        body: {
          action: "analyze",
          targetId: finding.target_id,
          payload: finding.payload_used || finding.parameter || "",
          context: {
            title: finding.title,
            severity: finding.severity,
            description: finding.description,
            cvssScore: finding.cvss_score,
            findingType: finding.finding_type,
          },
        },
      });
      if (error) throw error;
      if (data?.error) throw new Error(data.error);

      const sim = data.simulation;
      setFilterClassification(sim.filterClassification || "unknown");
      setAdaptationSteps(sim.iterations || []);
      setOverallResult(sim.overallResult || "inconclusive");
      setTechnicalSummary(sim.technicalSummary || "");

      // Store evidence chain
      const id = await storeEvidenceChain({
        findingId: source === "finding" ? finding.id : undefined,
        approvalId: source === "approval" ? finding.id : undefined,
        targetId: finding.target_id,
        result: {
          originalPayload: finding.payload_used || "",
          filterClassification: sim.filterClassification || "unknown",
          attempts: (sim.iterations || []).map((it: any, i: number) => ({
            iteration: i + 1,
            adaptationApplied: { type: "ai", name: it.adaptationName, description: it.reasoning, transform: (x: string) => x },
            transformedPayload: "",
            filterAnalysis: { classification: sim.filterClassification, confidence: 0.8, indicators: [], statusCode: it.statusCode, responseSnippet: it.body || "" },
            success: it.navigated,
            reasoning: it.reasoning,
          })),
          finalStatus: sim.overallResult === "verification_success" ? "verification_success" : "all_filtered",
        },
        aiReasoning: sim.technicalSummary,
      });
      setChainId(id);
      toast.success(`Adaptive analysis complete: ${sim.overallResult}`);
    } catch (e: any) {
      toast.error(e.message || "Analysis failed");
    } finally {
      setIsAnalyzing(false);
    }
  };

  const generateAdaptivePoc = async () => {
    setIsGeneratingPoc(true);
    setActiveTab("poc");
    try {
      const { data, error } = await supabase.functions.invoke("adaptive-validate", {
        body: {
          action: "generate-poc",
          context: {
            title: finding.title,
            severity: finding.severity,
            description: finding.description,
            cvssScore: finding.cvss_score,
            filterClassification,
            adaptationSteps,
            overallResult,
          },
        },
      });
      if (error) throw error;
      if (data?.error) throw new Error(data.error);
      setPocScript(data.script || "");
      toast.success("Technical evidence script generated");
    } catch (e: any) {
      toast.error(e.message || "PoC generation failed");
    } finally {
      setIsGeneratingPoc(false);
    }
  };

  const generateAuditReport = async () => {
    if (!chainId) {
      toast.error("Run adaptive analysis first");
      return;
    }
    setIsGeneratingReport(true);
    setActiveTab("report");
    try {
      const { data, error } = await supabase.functions.invoke("adaptive-validate", {
        body: {
          action: "report",
          chainId,
          context: {
            title: finding.title,
            severity: finding.severity,
            description: finding.description,
            cvssScore: finding.cvss_score,
            targetDomain: finding.target_id,
            filterClassification,
            adaptationSteps: adaptationSteps.map((s, i) => ({
              iteration: i + 1,
              adaptationName: s.adaptationName,
              description: s.reasoning,
              success: s.navigated,
              reasoning: s.reasoning,
            })),
            pocScript: pocScript.slice(0, 3000),
            verificationStatus: overallResult,
          },
        },
      });
      if (error) throw error;
      if (data?.error) throw new Error(data.error);
      setReport(data.report || "");
      toast.success("Audit report generated");
    } catch (e: any) {
      toast.error(e.message || "Report generation failed");
    } finally {
      setIsGeneratingReport(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-card border-border max-w-5xl max-h-[90vh] overflow-hidden flex flex-col">
        <DialogHeader>
          <div className="flex items-center gap-2">
            <Zap className="h-4 w-4 text-cyber-amber" />
            <DialogTitle className="font-mono text-cyber-amber text-sm">
              Adaptive Validation Engine
            </DialogTitle>
          </div>
          <div className="flex items-center gap-2 mt-1 flex-wrap">
            <Badge variant="outline" className={`text-[9px] font-mono ${severityBadge[finding.severity]}`}>
              {finding.severity}
            </Badge>
            <span className="text-xs font-mono text-card-foreground">{finding.title}</span>
            {finding.cvss_score && (
              <Badge variant="outline" className="text-[9px] font-mono text-cyber-amber border-cyber-amber/30">
                CVSS {finding.cvss_score}
              </Badge>
            )}
            {overallResult && (
              <Badge variant="outline" className={`text-[9px] font-mono ${
                overallResult === "verification_success"
                  ? "bg-cyber-green/20 text-cyber-green border-cyber-green/30"
                  : "bg-cyber-red/20 text-cyber-red border-cyber-red/30"
              }`}>
                {overallResult === "verification_success" ? "✓ VERIFIED" : "✗ FILTERED"}
              </Badge>
            )}
          </div>
        </DialogHeader>

        {/* Action Buttons */}
        <div className="flex gap-2 mb-2 flex-wrap">
          <Button
            size="sm" variant="outline"
            className="font-mono text-[10px] gap-1 border-cyber-amber/30 text-cyber-amber hover:bg-cyber-amber/10"
            onClick={runAdaptiveAnalysis}
            disabled={isAnalyzing}
          >
            {isAnalyzing ? <Loader2 className="h-3 w-3 animate-spin" /> : <BarChart3 className="h-3 w-3" />}
            {isAnalyzing ? "Analyzing..." : "Run Adaptive Analysis"}
          </Button>
          <Button
            size="sm" variant="outline"
            className="font-mono text-[10px] gap-1 border-primary/30 text-primary hover:bg-primary/10"
            onClick={generateAdaptivePoc}
            disabled={isGeneratingPoc || !filterClassification}
          >
            {isGeneratingPoc ? <Loader2 className="h-3 w-3 animate-spin" /> : <Shield className="h-3 w-3" />}
            {isGeneratingPoc ? "Generating..." : "Generate Evidence Script"}
          </Button>
          <Button
            size="sm" variant="outline"
            className="font-mono text-[10px] gap-1 border-cyber-cyan/30 text-cyber-cyan hover:bg-cyber-cyan/10"
            onClick={generateAuditReport}
            disabled={isGeneratingReport || !chainId}
          >
            {isGeneratingReport ? <Loader2 className="h-3 w-3 animate-spin" /> : <FileText className="h-3 w-3" />}
            {isGeneratingReport ? "Generating..." : "Generate Audit Report"}
          </Button>
        </div>

        <Tabs value={activeTab} onValueChange={setActiveTab} className="flex-1 flex flex-col min-h-0">
          <TabsList className="bg-muted border border-border">
            <TabsTrigger value="analysis" className="font-mono text-[10px]">
              Adaptation History
              {adaptationSteps.length > 0 && (
                <span className="ml-1 text-[8px] bg-cyber-amber/20 text-cyber-amber px-1 rounded">
                  {adaptationSteps.length}
                </span>
              )}
            </TabsTrigger>
            <TabsTrigger value="poc" className="font-mono text-[10px]">Evidence Script</TabsTrigger>
            <TabsTrigger value="report" className="font-mono text-[10px]">Audit Report</TabsTrigger>
          </TabsList>

          {/* Adaptation History Tab */}
          <TabsContent value="analysis" className="flex-1 min-h-0 mt-2">
            <ScrollArea className="h-[420px]">
              {adaptationSteps.length > 0 ? (
                <div className="space-y-3 pr-4">
                  {/* Filter classification */}
                  <div className="bg-muted rounded-lg p-3 border border-border">
                    <div className="flex items-center gap-2 mb-1">
                      <AlertTriangle className="h-3 w-3 text-cyber-amber" />
                      <span className="text-[10px] font-mono uppercase text-muted-foreground">Filter Classification</span>
                    </div>
                    <p className="text-xs font-mono text-card-foreground font-semibold">
                      {filterClassification?.replace(/_/g, " ").toUpperCase()}
                    </p>
                  </div>

                  {/* Adaptation steps */}
                  {adaptationSteps.map((step, idx) => (
                    <div key={idx} className={`rounded-lg border p-3 ${
                      step.navigated
                        ? "border-cyber-green/30 bg-cyber-green/5"
                        : "border-border bg-muted/30"
                    }`}>
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-2">
                          <span className="text-[9px] font-mono text-muted-foreground bg-muted px-1.5 py-0.5 rounded">
                            ITER {step.iteration || idx + 1}
                          </span>
                          <span className="text-xs font-mono text-card-foreground font-semibold">
                            {step.adaptationName}
                          </span>
                        </div>
                        <div className="flex items-center gap-1">
                          <Badge variant="outline" className={`text-[8px] font-mono ${
                            step.navigated
                              ? "text-cyber-green border-cyber-green/30"
                              : "text-cyber-red border-cyber-red/30"
                          }`}>
                            {step.statusCode}
                          </Badge>
                          {step.navigated ? (
                            <CheckCircle className="h-3 w-3 text-cyber-green" />
                          ) : (
                            <XCircle className="h-3 w-3 text-cyber-red" />
                          )}
                        </div>
                      </div>
                      <p className="text-[10px] font-mono text-muted-foreground">{step.reasoning}</p>
                      {idx < adaptationSteps.length - 1 && !step.navigated && (
                        <div className="flex justify-center mt-2">
                          <ArrowRight className="h-3 w-3 text-muted-foreground" />
                        </div>
                      )}
                    </div>
                  ))}

                  {/* Technical summary */}
                  {technicalSummary && (
                    <div className="bg-muted rounded-lg p-3 border border-border">
                      <span className="text-[10px] font-mono uppercase text-muted-foreground">Technical Summary</span>
                      <p className="text-xs font-mono text-card-foreground mt-1">{technicalSummary}</p>
                    </div>
                  )}
                </div>
              ) : (
                <div className="h-full flex items-center justify-center py-20">
                  <div className="text-center">
                    <BarChart3 className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
                    <p className="text-xs font-mono text-muted-foreground">
                      Click "Run Adaptive Analysis" to start the heuristic validation engine
                    </p>
                  </div>
                </div>
              )}
            </ScrollArea>
          </TabsContent>

          {/* PoC Script Tab */}
          <TabsContent value="poc" className="flex-1 min-h-0 mt-2">
            {pocScript ? (
              <div className="h-[420px] border border-border rounded-md overflow-hidden">
                <Editor
                  height="100%"
                  language="python"
                  theme="vs-dark"
                  value={pocScript}
                  onChange={(v) => setPocScript(v || "")}
                  options={{
                    minimap: { enabled: false },
                    fontSize: 12,
                    fontFamily: "JetBrains Mono, monospace",
                    lineNumbers: "on",
                    scrollBeyondLastLine: false,
                    wordWrap: "on",
                    padding: { top: 8 },
                    readOnly: false,
                  }}
                />
              </div>
            ) : (
              <div className="h-[420px] flex items-center justify-center border border-dashed border-border rounded-md">
                <div className="text-center">
                  <Shield className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
                  <p className="text-xs font-mono text-muted-foreground">
                    Run adaptive analysis first, then generate evidence script
                  </p>
                </div>
              </div>
            )}
          </TabsContent>

          {/* Audit Report Tab */}
          <TabsContent value="report" className="flex-1 min-h-0 mt-2">
            <div className="h-[420px] border border-border rounded-md overflow-auto">
              {report ? (
                <div className="p-4">
                  <div className="flex justify-end mb-2">
                    <Button
                      variant="ghost" size="sm"
                      className="font-mono text-[10px] gap-1"
                      onClick={() => { navigator.clipboard.writeText(report); toast.success("Report copied"); }}
                    >
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
                      {chainId ? "Click 'Generate Audit Report'" : "Run adaptive analysis first"}
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
