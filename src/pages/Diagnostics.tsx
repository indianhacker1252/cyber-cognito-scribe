import { useEffect, useMemo, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Loader2, RefreshCw, Download, ShieldAlert, Activity, Brain, GitBranch, Ban, AlertTriangle, Info } from "lucide-react";

type Report = {
  generatedAt: string;
  jobs: { status: string; count: number }[];
  runningJobs: any[];
  rpcFailures: any[];
  plannerTraces: any[];
  redirectNeutralized: { target_id: string; endpoint: string; note: string; ts: string }[];
  strategyDisables: { message: string; ts: string; target_id: string | null }[];
  credits: { remaining: number; total_granted: number; total_used: number } | null;
  aiExhaustion: any[];
  targetsSummary: { id: string; name: string | null; domain: string | null; status: string; findings: number }[];
};

export default function Diagnostics() {
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<Report | null>(null);

  const run = async () => {
    setLoading(true);
    try {
      const since = new Date(Date.now() - 24 * 3600 * 1000).toISOString();

      const [jobsRes, runningRes, logsRes, tracesRes, creditsRes, targetsRes, findingsRes] = await Promise.all([
        supabase.from("scan_jobs").select("status", { count: "exact", head: false }).gte("created_at", since),
        supabase.from("scan_jobs").select("id,job_type,status,target_id,started_at,attempts,priority").in("status", ["queued", "running"]).order("started_at", { ascending: false }).limit(50),
        supabase.from("scan_logs").select("id,target_id,log_type,message,metadata,created_at").gte("created_at", since).order("created_at", { ascending: false }).limit(600),
        supabase.from("planner_traces").select("id,target_id,trace_id,phase,decision,created_at").gte("created_at", since).order("created_at", { ascending: false }).limit(50),
        supabase.from("scan_credits").select("remaining,total_granted,total_used").maybeSingle(),
        supabase.from("target_workspaces").select("id,name,domain,status").order("updated_at", { ascending: false }).limit(20),
        supabase.from("vulnerability_findings").select("target_id").gte("created_at", since),
      ]);

      const logs = (logsRes.data ?? []) as any[];
      const rpcFailures = logs.filter((l) => /rpc|permission|forbidden|violates|constraint|failed|error/i.test(l.message || "") && l.log_type === "error");
      const redirectNeutralized = logs
        .filter((l) => /301|302|redirect|neutralized|trap/i.test(l.message || "") && /redirect|neutral|trap/i.test(l.message || ""))
        .map((l) => ({ target_id: l.target_id, endpoint: (l.metadata?.endpoint || l.metadata?.url || "-"), note: l.message, ts: l.created_at }));
      const strategyDisables = logs
        .filter((l) => /strategy engine/i.test(l.message || ""))
        .map((l) => ({ message: l.message, ts: l.created_at, target_id: l.target_id }));
      const aiExhaustion = logs.filter((l) => /402|429|exhaust|quota|rate.?limit|payment required/i.test(l.message || ""));

      const jobsAgg: Record<string, number> = {};
      for (const r of (jobsRes.data ?? []) as any[]) jobsAgg[r.status] = (jobsAgg[r.status] || 0) + 1;

      const findingsByTarget: Record<string, number> = {};
      for (const f of (findingsRes.data ?? []) as any[]) findingsByTarget[f.target_id] = (findingsByTarget[f.target_id] || 0) + 1;

      const rep: Report = {
        generatedAt: new Date().toISOString(),
        jobs: Object.entries(jobsAgg).map(([status, count]) => ({ status, count })),
        runningJobs: runningRes.data ?? [],
        rpcFailures: rpcFailures.slice(0, 30),
        plannerTraces: tracesRes.data ?? [],
        redirectNeutralized: redirectNeutralized.slice(0, 30),
        strategyDisables: strategyDisables.slice(0, 20),
        credits: (creditsRes.data as any) ?? null,
        aiExhaustion: aiExhaustion.slice(0, 20),
        targetsSummary: (targetsRes.data ?? []).map((t: any) => ({ ...t, findings: findingsByTarget[t.id] || 0 })),
      };
      setReport(rep);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { run(); }, []);

  const download = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `cyberscope-diagnostics-${Date.now()}.json`; a.click();
    URL.revokeObjectURL(url);
  };

  const summary = useMemo(() => {
    if (!report) return null;
    const totalJobs = report.jobs.reduce((s, j) => s + j.count, 0);
    const findings = report.targetsSummary.reduce((s, t) => s + t.findings, 0);
    return { totalJobs, findings };
  }, [report]);

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-mono text-primary text-glow-green">DIAGNOSTICS</h1>
          <p className="text-sm text-muted-foreground font-mono">One-click health & "why no findings" report — last 24h</p>
        </div>
        <div className="flex gap-2">
          <Button onClick={run} variant="outline" disabled={loading}>
            {loading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <RefreshCw className="h-4 w-4 mr-2" />}
            Regenerate
          </Button>
          <Button onClick={download} disabled={!report}>
            <Download className="h-4 w-4 mr-2" /> Export JSON
          </Button>
        </div>
      </div>

      {/* Strategy Engine explainer */}
      <Card className="border-amber-500/30">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-amber-400 text-base font-mono">
            <Info className="h-4 w-4" /> Why does it say "Strategy Engine disabled …"?
          </CardTitle>
        </CardHeader>
        <CardContent className="text-xs text-muted-foreground space-y-2 font-mono">
          <p>
            The Strategy Engine reads <code>strategy_weights</code> per tech-stack. When a vuln class has ≥5
            attempts and &lt;10% effectiveness on that stack, it's skipped to save AI credits. Protected
            classes (SQLi, XSS, SSRF, IDOR, SSTI, NoSQLi, auth-bypass) are <b>never disabled</b>.
          </p>
          <p>
            If you see it disable a lot, it usually means (a) the tech fingerprint was captured wrong, or
            (b) prior runs on that stack were all redirect-neutralized (e.g., 301 → /search) and got scored
            as failures. Purge <code>strategy_weights</code> for that stack to reset.
          </p>
        </CardContent>
      </Card>

      {/* Redirect neutralization */}
      <Card className="border-destructive/40">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-destructive text-base font-mono">
            <Ban className="h-4 w-4" /> Redirect Neutralization Shield
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {!report ? null : report.redirectNeutralized.length === 0 ? (
            <p className="text-xs text-muted-foreground font-mono">No redirect-neutralized endpoints detected in the last 24h.</p>
          ) : (
            <ScrollArea className="h-48">
              <div className="space-y-1">
                {report.redirectNeutralized.map((r, i) => (
                  <div key={i} className="text-[11px] font-mono border-l-2 border-destructive/50 pl-2 py-1">
                    <div className="text-destructive">{r.endpoint}</div>
                    <div className="text-muted-foreground">{r.note}</div>
                  </div>
                ))}
              </div>
            </ScrollArea>
          )}
          <p className="text-[11px] text-muted-foreground font-mono">
            These endpoints return a consistent 3xx to every payload, so mutations produce no signal. OWASP
            checks for A03/A05 on those endpoints are marked <b>neutralized</b> — try authenticated scans or
            direct API endpoints instead.
          </p>
        </CardContent>
      </Card>

      {/* Jobs */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Card>
          <CardHeader><CardTitle className="text-sm font-mono flex items-center gap-2"><Activity className="h-4 w-4" /> Job Status (24h)</CardTitle></CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {report?.jobs.map((j) => (
                <Badge key={j.status} variant="outline" className="font-mono">{j.status}: {j.count}</Badge>
              )) ?? <span className="text-xs text-muted-foreground">—</span>}
              {summary && <Badge className="font-mono">total: {summary.totalJobs}</Badge>}
            </div>
            <div className="mt-4">
              <div className="text-[11px] text-muted-foreground font-mono mb-1">Currently queued/running</div>
              <ScrollArea className="h-36">
                {report?.runningJobs.map((j) => (
                  <div key={j.id} className="text-[11px] font-mono flex justify-between border-b border-border/40 py-1">
                    <span>{j.job_type}</span>
                    <span className="text-muted-foreground">{j.status} · att {j.attempts}</span>
                  </div>
                ))}
              </ScrollArea>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle className="text-sm font-mono flex items-center gap-2"><ShieldAlert className="h-4 w-4" /> RPC / Function Failures</CardTitle></CardHeader>
          <CardContent>
            <ScrollArea className="h-48">
              {report?.rpcFailures.length === 0 && <p className="text-xs text-muted-foreground font-mono">Clean.</p>}
              {report?.rpcFailures.map((r) => (
                <div key={r.id} className="text-[11px] font-mono border-l-2 border-destructive/50 pl-2 py-1">
                  {r.message}
                </div>
              ))}
            </ScrollArea>
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle className="text-sm font-mono flex items-center gap-2"><Brain className="h-4 w-4" /> Planner Traces</CardTitle></CardHeader>
          <CardContent>
            <ScrollArea className="h-48">
              {report?.plannerTraces.length === 0 && <p className="text-xs text-muted-foreground font-mono">No AI planner decisions recorded — agent-planner may be blocked.</p>}
              {report?.plannerTraces.map((t) => (
                <div key={t.id} className="text-[11px] font-mono border-b border-border/40 py-1">
                  <span className="text-primary">{t.phase}</span> · {t.decision?.slice?.(0, 120) || "-"}
                </div>
              ))}
            </ScrollArea>
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle className="text-sm font-mono flex items-center gap-2"><AlertTriangle className="h-4 w-4" /> AI Exhaustion / Rate Limits</CardTitle></CardHeader>
          <CardContent>
            <ScrollArea className="h-48">
              {report?.aiExhaustion.length === 0 && <p className="text-xs text-muted-foreground font-mono">No 402/429/quota hits.</p>}
              {report?.aiExhaustion.map((r) => (
                <div key={r.id} className="text-[11px] font-mono border-l-2 border-amber-500/50 pl-2 py-1">{r.message}</div>
              ))}
            </ScrollArea>
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle className="text-sm font-mono flex items-center gap-2"><GitBranch className="h-4 w-4" /> Strategy Engine Decisions</CardTitle></CardHeader>
          <CardContent>
            <ScrollArea className="h-48">
              {report?.strategyDisables.length === 0 && <p className="text-xs text-muted-foreground font-mono">No strategy-engine activity.</p>}
              {report?.strategyDisables.map((r, i) => (
                <div key={i} className="text-[11px] font-mono border-b border-border/40 py-1">{r.message}</div>
              ))}
            </ScrollArea>
          </CardContent>
        </Card>

        <Card>
          <CardHeader><CardTitle className="text-sm font-mono">Credits</CardTitle></CardHeader>
          <CardContent className="text-xs font-mono space-y-1">
            <div>Remaining: <span className="text-primary">{report?.credits?.remaining ?? "—"}</span></div>
            <div>Granted: {report?.credits?.total_granted ?? "—"}</div>
            <div>Used: {report?.credits?.total_used ?? "—"}</div>
          </CardContent>
        </Card>
      </div>

      {/* Targets summary */}
      <Card>
        <CardHeader><CardTitle className="text-sm font-mono">Recent Targets — Findings vs Status</CardTitle></CardHeader>
        <CardContent>
          <ScrollArea className="h-56">
            <table className="w-full text-[11px] font-mono">
              <thead className="text-muted-foreground">
                <tr><th className="text-left py-1">Target</th><th>Status</th><th>Findings (24h)</th></tr>
              </thead>
              <tbody>
                {report?.targetsSummary.map((t) => (
                  <tr key={t.id} className="border-b border-border/40">
                    <td className="py-1">{t.name || t.domain || t.id}</td>
                    <td className="text-center">{t.status}</td>
                    <td className="text-center">{t.findings}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  );
}
