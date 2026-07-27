import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { CheckCircle2, Circle, AlertTriangle, ListChecks, Trash2, RefreshCw, Play } from "lucide-react";
import { toast } from "sonner";

type Row = {
  target_id: string;
  category: string;
  check_name: string;
  check_module: string | null;
  status: string | null;
  evidence_count: number | null;
  last_run_at: string | null;
  metadata?: any;
};

type JobRow = {
  target_id: string;
  job_type: string;
  status: string;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
  attempts: number | null;
  result?: any;
  payload?: any;
};

type AuditRow = {
  id: string;
  target_id: string;
  target_label: string;
  action: string;
  deleted_count: number;
  actor_id: string | null;
  created_at: string;
};

const CATEGORY_LABEL: Record<string, string> = {
  A01_broken_access_control: "A01 — Broken Access Control",
  A02_crypto_failures: "A02 — Cryptographic Failures",
  A03_injection: "A03 — Injection",
  A04_insecure_design: "A04 — Insecure Design",
  A05_misconfig: "A05 — Security Misconfiguration",
  A06_vuln_components: "A06 — Vulnerable Components",
  A07_auth_failures: "A07 — Auth Failures",
  A08_software_integrity: "A08 — Software Integrity",
  A09_logging: "A09 — Logging & Monitoring",
  A10_ssrf: "A10 — SSRF",
};

export default function OwaspChecklist() {
  const [rows, setRows] = useState<Row[]>([]);
  const [targets, setTargets] = useState<Record<string, { name: string; domain: string }>>({});
  const [jobs, setJobs] = useState<JobRow[]>([]);
  const [audits, setAudits] = useState<AuditRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<{ id: string; label: string } | null>(null);
  const [deleteConfirm, setDeleteConfirm] = useState("");

  const load = async () => {
    setLoading(true);
    const [{ data: checks }, { data: tgts }, { data: jobRows }, { data: auditRows }] = await Promise.all([
      supabase.from("owasp_checklist" as any).select("*").order("category").order("check_name"),
      supabase.from("target_workspaces").select("id,name,domain"),
      supabase.from("scan_jobs" as any).select("target_id,job_type,status,created_at,started_at,completed_at,error_message,attempts,result,payload").order("created_at", { ascending: false }).limit(2000),
      supabase.from("owasp_checklist_audit" as any).select("id,target_id,target_label,action,deleted_count,actor_id,created_at").order("created_at", { ascending: false }).limit(50),
    ]);
    setRows((checks as any) || []);
    setJobs((jobRows as any) || []);
    setAudits((auditRows as any) || []);
    const m: Record<string, { name: string; domain: string }> = {};
    (tgts || []).forEach((t: any) => (m[t.id] = { name: t.name || t.domain, domain: t.domain || "" }));
    setTargets(m);
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  const byTarget = new Map<string, Map<string, Row[]>>();
  for (const r of rows) {
    if (!byTarget.has(r.target_id)) byTarget.set(r.target_id, new Map());
    const cats = byTarget.get(r.target_id)!;
    if (!cats.has(r.category)) cats.set(r.category, []);
    cats.get(r.category)!.push(r);
  }

  // A check is "done" once the scanner module has executed for it. `evidence`
  // = vuln proven, `passed`/`complete` = explicitly cleared, `attempted` =
  // module ran but produced no finding (which is a valid "no-vuln" outcome
  // and MUST count toward progress — otherwise 83/83 attempted renders as 0%).
  const isDone = (s: string | null) =>
    s === "evidence" || s === "passed" || s === "complete" || s === "attempted";
  const hasEvidence = (s: string | null) => s === "evidence";

  const reseed = async (id: string) => {
    setBusy(id);
    try {
      const { error } = await supabase.rpc("seed_owasp_checklist" as any, { _target_id: id });
      if (error) throw error;
      toast.success("Checklist seeded"); await load();
    } catch (e: any) { toast.error(e.message || "Failed"); } finally { setBusy(null); }
  };

  const del = async () => {
    if (!deleteTarget) return;
    const expected = `DELETE ${deleteTarget.label}`;
    if (deleteConfirm !== expected) return;
    setBusy(deleteTarget.id);
    try {
      const { error } = await supabase.rpc("delete_owasp_checklist" as any, { _target_id: deleteTarget.id, _confirmation: expected });
      if (error) throw error;
      toast.success("Checklist deleted and audited");
      setDeleteTarget(null);
      setDeleteConfirm("");
      await load();
    } catch (e: any) { toast.error(e.message || "Failed"); } finally { setBusy(null); }
  };


  const moduleToJobType = (mod: string | null) => {
    const jobMap: Record<string, string> = {
      "advanced-fuzzer": "fuzz", "matrix-fuzzer": "matrix_fuzz", "form-attacker": "form_attack",
      "recon-juicy": "juicy", "recon-engine": "recon", "recon-deep": "recon",
      "ssrf-deep": "ssrf_deep", "js-deep-expand": "js_deep", "cve-to-exploit": "cve_exploit",
      "cve-version-matcher": "cve", "nvd-intel-sync": "nvd_sync", "subdomain-enum": "subdomain_enum",
      "auth-confusion-suite": "jwt_attack", "auth-deep": "advanced_detect", "auth-replay": "auth_replay",
      "graphql-attack": "graphql", "prototype-pollution-gadgets": "advanced_detect",
      "business-logic-fuzzer": "advanced_detect", "race-runner": "advanced_detect",
      "bac-tester": "advanced_detect", "differential-oracle": "differential",
      "dom-fuzz": "advanced_detect", "cache-attack": "advanced_detect",
      "desync-smuggling-v2": "advanced_detect", "vuln-scanner": "vuln_scan",
    };
    return mod ? (jobMap[mod] || "advanced_detect") : "unmapped";
  };

  const latestJob = (targetId: string, mod: string | null) => jobs.find((j) => j.target_id === targetId && j.job_type === moduleToJobType(mod));

  const dependencyReason = (row: Row) => {
    const job = latestJob(row.target_id, row.check_module);
    if (!row.check_module) return "Blocked: no scanner module mapped to this checklist item.";
    if (!job) return "Blocked: prerequisite scanner job was never queued or ran.";
    if (job.status === "failed") return `Blocked: ${job.job_type} failed${job.error_message ? ` — ${job.error_message}` : ""}.`;
    if (job.status === "queued") return `Waiting: ${job.job_type} is queued but has not run yet.`;
    if (job.status === "running") return `Waiting: ${job.job_type} is currently running.`;
    return `Blocked: ${job.job_type} completed but did not produce evidence for this check.`;
  };

  const lastRunLabel = (row: Row) => {
    const job = latestJob(row.target_id, row.check_module);
    const ts = row.last_run_at || job?.completed_at || job?.started_at || job?.created_at;
    return ts ? new Date(ts).toLocaleString() : "never";
  };

  const runMissing = async (id: string, force = false) => {
    setBusy(id);
    try {
      const { data, error } = await supabase.rpc("enqueue_missing_owasp_modules" as any, { _target_id: id, _force: force });
      if (error) throw error;
      const r = data as any;
      if (r?.active_jobs && !force) toast.info(`Scan still active — missing modules will queue when it ends (${r.active_jobs} active jobs).`);
      else toast.success(`Queued ${r?.queued ?? 0} missing scanner module${(r?.queued ?? 0) === 1 ? "" : "s"}`);
      await load();
    } catch (e: any) { toast.error(e.message || "Failed"); } finally { setBusy(null); }
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center gap-2">
        <ListChecks className="h-6 w-6 text-primary" />
        <h1 className="text-2xl font-bold">OWASP Checklist Progress</h1>
      </div>
      <p className="text-muted-foreground text-sm">
        Per-check progress across the OWASP Top 10 (82 checks). Missing items show the exact scanner
        module that is blocking the check — click "Run missing" to queue them.
      </p>

      {loading && <Card><CardContent className="p-12 text-center">Loading…</CardContent></Card>}
      {!loading && byTarget.size === 0 && (
        <Card><CardContent className="p-12 text-center text-muted-foreground">
          No checklist data. Create a target on <a href="/targets" className="underline">/targets</a> — it now auto-seeds.
        </CardContent></Card>
      )}

      {audits.length > 0 && (
        <Card>
          <CardHeader><CardTitle className="text-sm">OWASP deletion audit trail</CardTitle></CardHeader>
          <CardContent className="space-y-1 text-[11px] font-mono text-muted-foreground">
            {audits.slice(0, 8).map((a) => (
              <div key={a.id} className="flex flex-wrap items-center gap-2">
                <Badge variant="outline" className="text-[10px]">{a.deleted_count} rows</Badge>
                <span>{a.target_label}</span>
                <span>•</span>
                <span>{new Date(a.created_at).toLocaleString()}</span>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {Array.from(byTarget.entries()).map(([targetId, cats]) => {
        const all = Array.from(cats.values()).flat();
        const done = all.filter((r) => isDone(r.status)).length;
        const pct = all.length ? Math.round((done / all.length) * 100) : 0;
        const missing = all.filter((r) => !isDone(r.status));
        const t = targets[targetId];
        const label = t ? (t.name || t.domain || targetId) : targetId;
        const displayLabel = t ? `${t.name}${t.domain && t.domain !== t.name ? ` — ${t.domain}` : ""}` : `(orphaned target ${targetId.slice(0, 8)}…)`;

        return (
          <Card key={targetId}>
            <CardHeader>
              <CardTitle className="flex flex-wrap justify-between items-center gap-3">
                <span className="text-base">{displayLabel}</span>
                <div className="flex items-center gap-2 flex-wrap">
                  <Badge variant={pct === 100 ? "default" : pct >= 70 ? "secondary" : "destructive"}>
                    {done}/{all.length} ({pct}%)
                  </Badge>
                  <Button size="sm" variant="outline" disabled={busy === targetId || missing.length === 0 || !t}
                          onClick={() => runMissing(targetId, false)}>
                    <Play className="h-3 w-3 mr-1" /> Auto-rerun missing
                  </Button>
                  <Button size="sm" variant="outline" disabled={busy === targetId || missing.length === 0 || !t}
                          onClick={() => runMissing(targetId, true)}>
                    <Play className="h-3 w-3 mr-1" /> Run now
                  </Button>
                  <Button size="sm" variant="outline" disabled={busy === targetId || !t} onClick={() => reseed(targetId)}>
                    <RefreshCw className="h-3 w-3 mr-1" /> Re-seed
                  </Button>
                  <Button size="sm" variant="destructive" disabled={busy === targetId}
                          onClick={() => { setDeleteTarget({ id: targetId, label }); setDeleteConfirm(""); }}>
                    <Trash2 className="h-3 w-3 mr-1" /> Delete{!t ? " orphan" : ""}
                  </Button>
                </div>
              </CardTitle>
              <Progress value={pct} className="mt-3" />
            </CardHeader>
            <CardContent className="space-y-4">
              {missing.length > 0 && (
                <div className="rounded border border-destructive/40 bg-destructive/10 p-3 space-y-2">
                  <div className="flex items-center gap-2 text-sm font-semibold text-destructive">
                    <AlertTriangle className="h-4 w-4" /> Blocking modules ({missing.length} checks pending)
                  </div>
                  <div className="text-[11px] text-muted-foreground">
                    Full dependency chain for every missing check: checklist → scanner module → queue job → evidence result.
                  </div>
                  <div className="grid grid-cols-1 gap-2 text-[11px] font-mono">
                    {missing.slice(0, 40).map((m) => (
                      <div key={m.category + m.check_name} className="rounded border border-border bg-background/50 p-2 space-y-1">
                        <div className="flex items-center gap-2 min-w-0">
                        <Circle className="h-3 w-3 text-destructive shrink-0" />
                        <span className="truncate">{m.check_name}</span>
                        <span className="text-muted-foreground">→</span>
                        <Badge variant="outline" className="h-4 text-[10px] shrink-0">
                          {m.check_module || "unmapped"}
                        </Badge>
                          <span className="text-muted-foreground">→</span>
                          <Badge variant="outline" className="h-4 text-[10px] shrink-0">{moduleToJobType(m.check_module)}</Badge>
                        </div>
                        <div className="text-[10px] text-muted-foreground pl-5">{dependencyReason(m)}</div>
                        <div className="text-[10px] text-muted-foreground pl-5">last run: {lastRunLabel(m)}</div>
                      </div>
                    ))}
                    {missing.length > 40 && (
                      <div className="text-muted-foreground">+{missing.length - 40} more…</div>
                    )}
                  </div>
                </div>
              )}

              {Array.from(cats.entries()).map(([cat, list]) => {
                const catDone = list.filter((r) => isDone(r.status)).length;
                return (
                  <div key={cat} className="space-y-1">
                    <div className="flex justify-between text-sm font-medium">
                      <span>{CATEGORY_LABEL[cat] || cat}</span>
                      <span className="text-muted-foreground">{catDone}/{list.length}</span>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-1">
                      {list.map((r) => (
                        <div key={r.check_name} className="flex items-center gap-2 text-xs">
                          {hasEvidence(r.status)
                            ? <CheckCircle2 className="h-3.5 w-3.5 text-amber-500 shrink-0" />
                            : isDone(r.status)
                            ? <CheckCircle2 className="h-3.5 w-3.5 text-green-500 shrink-0" />
                            : <Circle className="h-3.5 w-3.5 text-muted-foreground shrink-0" />}
                          <span className="font-mono truncate">{r.check_name}</span>
                          {r.check_module && (
                            <span className="text-[10px] text-muted-foreground font-mono truncate">
                              [{r.check_module}]
                            </span>
                          )}
                          <span className="text-[10px] text-muted-foreground ml-auto shrink-0">{lastRunLabel(r)}</span>
                          {r.evidence_count ? <Badge variant="secondary" className="h-4 text-[10px]">{r.evidence_count}</Badge> : null}
                        </div>
                      ))}
                    </div>
                  </div>
                );
              })}
            </CardContent>
          </Card>
        );
      })}

      <Dialog open={!!deleteTarget} onOpenChange={(open) => { if (!open) { setDeleteTarget(null); setDeleteConfirm(""); } }}>
        <DialogContent>
          <DialogHeader><DialogTitle>Confirm OWASP checklist deletion</DialogTitle></DialogHeader>
          {deleteTarget && (
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">
                This deletes the checklist rows for <span className="font-mono text-foreground">{deleteTarget.label}</span> and writes an audit entry.
              </p>
              <div className="text-xs font-mono text-muted-foreground">Type exactly:</div>
              <code className="block rounded border border-border bg-muted p-2 text-xs">DELETE {deleteTarget.label}</code>
              <Input value={deleteConfirm} onChange={(e) => setDeleteConfirm(e.target.value)} className="font-mono text-xs" />
              <div className="flex justify-end gap-2">
                <Button variant="outline" onClick={() => { setDeleteTarget(null); setDeleteConfirm(""); }}>Cancel</Button>
                <Button variant="destructive" disabled={busy === deleteTarget.id || deleteConfirm !== `DELETE ${deleteTarget.label}`} onClick={del}>
                  <Trash2 className="h-3 w-3 mr-1" /> Delete checklist
                </Button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
