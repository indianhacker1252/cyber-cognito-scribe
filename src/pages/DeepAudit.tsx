import { useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { toast } from "sonner";
import {
  Shield, Scan, Copy, CheckCircle2, XCircle, AlertTriangle,
  Activity, Bug, GitCompare,
} from "lucide-react";

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

interface ScanResults {
  target: string;
  scanId: string;
  timestamp: string;
  owaspFindings: OwaspFinding[];
  cveFindings: CveFinding[];
  differentialResults: DiffResult[];
}

export default function DeepAudit() {
  const [targetUrl, setTargetUrl] = useState("");
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState<ScanResults | null>(null);

  const handleScan = async () => {
    if (!targetUrl.trim()) {
      toast.error("Enter a target URL");
      return;
    }
    setScanning(true);
    setResults(null);
    try {
      const { data, error } = await supabase.functions.invoke("cyberscope-deep-audit", {
        body: { targetUrl: targetUrl.trim() },
      });
      if (error) throw error;
      setResults(data as ScanResults);
      toast.success("Deep audit complete");
    } catch (e: any) {
      toast.error(e.message || "Scan failed");
    } finally {
      setScanning(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success("Copied to clipboard");
  };

  const severityColor = (s: string) => {
    switch (s) {
      case "critical": return "bg-cyber-red/20 text-cyber-red border-cyber-red/40";
      case "high": return "bg-cyber-amber/20 text-cyber-amber border-cyber-amber/40";
      case "medium": return "bg-yellow-500/20 text-yellow-400 border-yellow-500/40";
      default: return "bg-muted text-muted-foreground border-border";
    }
  };

  return (
    <div className="space-y-6">
      {/* HEADER */}
      <div className="space-y-1">
        <div className="flex items-center gap-3">
          <Shield className="h-7 w-7 text-primary" />
          <h1 className="text-2xl font-bold font-mono tracking-tight text-foreground text-glow-green">
            CyberScope Scanner: Deep Audit Engine
          </h1>
        </div>
        <p className="text-sm text-muted-foreground font-mono">
          Twin-Test Differential Analysis · CVE Correlation · DOM Crawling
        </p>
      </div>

      {/* INPUT AREA */}
      <Card className="border-primary/20 glow-green">
        <CardContent className="p-4">
          <div className="flex gap-3">
            <Input
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="https://target-infrastructure.example.com"
              className="flex-1 font-mono text-sm bg-background border-primary/30 focus:border-primary placeholder:text-muted-foreground/50"
              onKeyDown={(e) => e.key === "Enter" && handleScan()}
            />
            <Button
              onClick={handleScan}
              disabled={scanning}
              className="bg-primary text-primary-foreground hover:bg-primary/80 font-mono font-semibold px-6 glow-green whitespace-nowrap"
            >
              {scanning ? (
                <>
                  <Scan className="h-4 w-4 animate-spin" />
                  Scanning…
                </>
              ) : (
                <>
                  <Scan className="h-4 w-4" />
                  Initiate Deep Scan (Twin-Test Enabled)
                </>
              )}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* LOADING SKELETON */}
      {scanning && (
        <div className="space-y-4">
          {[1, 2, 3].map((i) => (
            <Skeleton key={i} className="h-20 w-full bg-muted/50" />
          ))}
        </div>
      )}

      {/* RESULTS */}
      {results && (
        <>
          {/* Stats bar */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <StatBox label="Scan ID" value={results.scanId.slice(0, 8)} icon={<Activity className="h-4 w-4" />} />
            <StatBox label="OWASP Hits" value={String(results.owaspFindings.length)} icon={<Bug className="h-4 w-4" />} />
            <StatBox label="CVEs Found" value={String(results.cveFindings.length)} icon={<AlertTriangle className="h-4 w-4" />} />
            <StatBox label="Diff Tests" value={String(results.differentialResults.length)} icon={<GitCompare className="h-4 w-4" />} />
          </div>

          {/* TABS */}
          <Tabs defaultValue="owasp" className="space-y-4">
            <TabsList className="bg-muted/50 border border-border font-mono">
              <TabsTrigger value="owasp" className="data-[state=active]:bg-primary/20 data-[state=active]:text-primary font-mono text-xs">
                OWASP Logic & DOM Analysis
              </TabsTrigger>
              <TabsTrigger value="cve" className="data-[state=active]:bg-primary/20 data-[state=active]:text-primary font-mono text-xs">
                CVE & Dependency Health
              </TabsTrigger>
              <TabsTrigger value="diff" className="data-[state=active]:bg-primary/20 data-[state=active]:text-primary font-mono text-xs">
                Differential Engine (FP)
              </TabsTrigger>
            </TabsList>

            {/* TAB 1: OWASP */}
            <TabsContent value="owasp">
              <Card className="border-border bg-card">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-mono text-primary flex items-center gap-2">
                    <Bug className="h-4 w-4" /> OWASP Logic & DOM Analysis Results
                  </CardTitle>
                </CardHeader>
                <CardContent className="p-0">
                  <Table>
                    <TableHeader>
                      <TableRow className="border-border hover:bg-transparent">
                        <TableHead className="font-mono text-[11px] text-muted-foreground">Discovered Parameter/Input</TableHead>
                        <TableHead className="font-mono text-[11px] text-muted-foreground">Test Signature</TableHead>
                        <TableHead className="font-mono text-[11px] text-muted-foreground">Control Response (Safe)</TableHead>
                        <TableHead className="font-mono text-[11px] text-muted-foreground">Anomaly Response (Payload)</TableHead>
                        <TableHead className="font-mono text-[11px] text-muted-foreground">Verification Status</TableHead>
                        <TableHead className="font-mono text-[11px] text-muted-foreground">PoC Generator</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {results.owaspFindings.map((f) => (
                        <TableRow key={f.id} className="border-border/50">
                          <TableCell className="font-mono text-xs text-foreground">{f.parameter}</TableCell>
                          <TableCell className="font-mono text-xs text-cyber-cyan">{f.testSignature}</TableCell>
                          <TableCell className="font-mono text-xs text-muted-foreground">{f.controlResponse.label}</TableCell>
                          <TableCell className="font-mono text-xs">
                            <span className={f.verificationStatus === "verified_critical" ? "text-cyber-red" : "text-muted-foreground"}>
                              {f.anomalyResponse.label}
                            </span>
                          </TableCell>
                          <TableCell>
                            {f.verificationStatus === "verified_critical" ? (
                              <Badge className="bg-primary/20 text-primary border border-primary/40 font-mono text-[10px] gap-1 glow-green">
                                <CheckCircle2 className="h-3 w-3" /> Verified Critical
                              </Badge>
                            ) : (
                              <Badge variant="secondary" className="font-mono text-[10px] gap-1 bg-muted text-muted-foreground border border-border">
                                <XCircle className="h-3 w-3" /> False Positive / WAF Block
                              </Badge>
                            )}
                          </TableCell>
                          <TableCell>
                            <button
                              onClick={() => copyToClipboard(f.pocCurl)}
                              className="flex items-center gap-1.5 text-[10px] font-mono text-cyber-cyan hover:text-primary transition-colors bg-muted/50 border border-border rounded px-2 py-1"
                            >
                              <Copy className="h-3 w-3" /> Copy curl
                            </button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </CardContent>
              </Card>
            </TabsContent>

            {/* TAB 2: CVE */}
            <TabsContent value="cve">
              <Card className="border-border bg-card">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-mono text-primary flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4" /> CVE & Dependency Health
                  </CardTitle>
                </CardHeader>
                <CardContent className="p-0">
                  <Table>
                    <TableHeader>
                      <TableRow className="border-border hover:bg-transparent">
                        <TableHead className="font-mono text-[11px] text-muted-foreground">Dependency</TableHead>
                        <TableHead className="font-mono text-[11px] text-muted-foreground">CVE ID</TableHead>
                        <TableHead className="font-mono text-[11px] text-muted-foreground">Severity</TableHead>
                        <TableHead className="font-mono text-[11px] text-muted-foreground">Description</TableHead>
                        <TableHead className="font-mono text-[11px] text-muted-foreground">Fix Version</TableHead>
                        <TableHead className="font-mono text-[11px] text-muted-foreground">Status</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {results.cveFindings.map((c) => (
                        <TableRow key={c.id} className="border-border/50">
                          <TableCell className="font-mono text-xs text-foreground font-semibold">{c.dependency}</TableCell>
                          <TableCell className="font-mono text-xs text-cyber-cyan">{c.cveId}</TableCell>
                          <TableCell>
                            <Badge className={`font-mono text-[10px] border ${severityColor(c.severity)}`}>
                              {c.severity.toUpperCase()}
                            </Badge>
                          </TableCell>
                          <TableCell className="font-mono text-xs text-muted-foreground max-w-[280px]">{c.description}</TableCell>
                          <TableCell className="font-mono text-xs text-primary">{c.fixVersion}</TableCell>
                          <TableCell>
                            <Badge className="bg-cyber-red/20 text-cyber-red border border-cyber-red/40 font-mono text-[10px]">
                              {c.status.toUpperCase()}
                            </Badge>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </CardContent>
              </Card>
            </TabsContent>

            {/* TAB 3: DIFFERENTIAL */}
            <TabsContent value="diff">
              <Card className="border-border bg-card">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-mono text-primary flex items-center gap-2">
                    <GitCompare className="h-4 w-4" /> Differential Engine — False Positive Elimination
                  </CardTitle>
                </CardHeader>
                <CardContent className="p-0">
                  <Table>
                    <TableHeader>
                      <TableRow className="border-border hover:bg-transparent">
                        <TableHead className="font-mono text-[11px] text-muted-foreground">Test Case</TableHead>
                        <TableHead className="font-mono text-[11px] text-muted-foreground">Twin-A (Payload)</TableHead>
                        <TableHead className="font-mono text-[11px] text-muted-foreground">Twin-B (Control)</TableHead>
                        <TableHead className="font-mono text-[11px] text-muted-foreground">Byte Delta</TableHead>
                        <TableHead className="font-mono text-[11px] text-muted-foreground">Verdict</TableHead>
                        <TableHead className="font-mono text-[11px] text-muted-foreground">Confidence</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {results.differentialResults.map((d) => (
                        <TableRow key={d.id} className="border-border/50">
                          <TableCell className="font-mono text-xs text-foreground">{d.testCase}</TableCell>
                          <TableCell className="font-mono text-xs text-cyber-red max-w-[200px]">{d.twinAResponse}</TableCell>
                          <TableCell className="font-mono text-xs text-muted-foreground max-w-[200px]">{d.twinBResponse}</TableCell>
                          <TableCell className="font-mono text-xs text-cyber-amber">{d.byteDelta}</TableCell>
                          <TableCell>
                            {d.verdict === "confirmed" ? (
                              <Badge className="bg-primary/20 text-primary border border-primary/40 font-mono text-[10px] gap-1 glow-green">
                                <CheckCircle2 className="h-3 w-3" /> CONFIRMED
                              </Badge>
                            ) : (
                              <Badge variant="secondary" className="font-mono text-[10px] gap-1 bg-muted text-muted-foreground border border-border">
                                <XCircle className="h-3 w-3" /> WAF BLOCKED
                              </Badge>
                            )}
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center gap-2">
                              <div className="w-16 h-1.5 rounded-full bg-muted overflow-hidden">
                                <div
                                  className={`h-full rounded-full ${d.confidence > 0.7 ? "bg-primary" : "bg-muted-foreground"}`}
                                  style={{ width: `${d.confidence * 100}%` }}
                                />
                              </div>
                              <span className="font-mono text-[10px] text-muted-foreground">
                                {(d.confidence * 100).toFixed(0)}%
                              </span>
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
        </>
      )}
    </div>
  );
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
