import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Button } from "@/components/ui/button";
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
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    const [{ data: checks }, { data: tgts }] = await Promise.all([
      supabase.from("owasp_checklist" as any).select("*").order("category").order("check_name"),
      supabase.from("target_workspaces").select("id,name,domain"),
    ]);
    setRows((checks as any) || []);
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

  const isDone = (s: string | null) => s === "evidence" || s === "passed" || s === "complete";

  const reseed = async (id: string) => {
    setBusy(id);
    try {
      const { error } = await supabase.rpc("seed_owasp_checklist" as any, { _target_id: id });
      if (error) throw error;
      toast.success("Checklist seeded"); await load();
    } catch (e: any) { toast.error(e.message || "Failed"); } finally { setBusy(null); }
  };

  const del = async (id: string, name: string) => {
    if (!confirm(`Delete OWASP checklist for ${name}?`)) return;
    setBusy(id);
    try {
      const { error } = await supabase.rpc("delete_owasp_checklist" as any, { _target_id: id });
      if (error) throw error;
      toast.success("Checklist deleted"); await load();
    } catch (e: any) { toast.error(e.message || "Failed"); } finally { setBusy(null); }
  };

  const runMissing = async (id: string, missing: Row[]) => {
    setBusy(id);
    try {
      // De-dup modules and enqueue one job per unique scanner
      const uniqModules = Array.from(new Set(missing.map((m) => m.check_module).filter(Boolean))) as string[];
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
      const jobs = uniqModules.map((mod) => ({
        target_id: id, job_type: jobMap[mod] || "advanced_detect", priority: 5, status: "queued",
        payload: { checklist_seed: mod }, next_run_at: new Date().toISOString(),
      }));
      if (jobs.length) {
        const { error } = await supabase.from("scan_jobs").insert(jobs);
        if (error) throw error;
      }
      toast.success(`Queued ${jobs.length} scanner${jobs.length === 1 ? "" : "s"}`);
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

      {Array.from(byTarget.entries()).map(([targetId, cats]) => {
        const all = Array.from(cats.values()).flat();
        const done = all.filter((r) => isDone(r.status)).length;
        const pct = all.length ? Math.round((done / all.length) * 100) : 0;
        const missing = all.filter((r) => !isDone(r.status));
        const t = targets[targetId];
        const label = t ? `${t.name}${t.domain && t.domain !== t.name ? ` — ${t.domain}` : ""}` : `(deleted target ${targetId.slice(0, 8)}…)`;

        return (
          <Card key={targetId}>
            <CardHeader>
              <CardTitle className="flex flex-wrap justify-between items-center gap-3">
                <span className="text-base">{label}</span>
                <div className="flex items-center gap-2 flex-wrap">
                  <Badge variant={pct === 100 ? "default" : pct >= 70 ? "secondary" : "destructive"}>
                    {done}/{all.length} ({pct}%)
                  </Badge>
                  <Button size="sm" variant="outline" disabled={busy === targetId || missing.length === 0}
                          onClick={() => runMissing(targetId, missing)}>
                    <Play className="h-3 w-3 mr-1" /> Run missing
                  </Button>
                  <Button size="sm" variant="outline" disabled={busy === targetId} onClick={() => reseed(targetId)}>
                    <RefreshCw className="h-3 w-3 mr-1" /> Re-seed
                  </Button>
                  <Button size="sm" variant="destructive" disabled={busy === targetId}
                          onClick={() => del(targetId, t?.name || "this target")}>
                    <Trash2 className="h-3 w-3 mr-1" /> Delete
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
                    Each check is blocked because its scanner module hasn't produced evidence yet:
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-1 text-[11px] font-mono">
                    {missing.slice(0, 40).map((m) => (
                      <div key={m.category + m.check_name} className="flex items-center gap-2 truncate">
                        <Circle className="h-3 w-3 text-destructive shrink-0" />
                        <span className="truncate">{m.check_name}</span>
                        <span className="text-muted-foreground">→</span>
                        <Badge variant="outline" className="h-4 text-[10px] shrink-0">
                          {m.check_module || "unmapped"}
                        </Badge>
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
                          {isDone(r.status)
                            ? <CheckCircle2 className="h-3.5 w-3.5 text-green-500 shrink-0" />
                            : <Circle className="h-3.5 w-3.5 text-muted-foreground shrink-0" />}
                          <span className="font-mono truncate">{r.check_name}</span>
                          {r.check_module && (
                            <span className="text-[10px] text-muted-foreground font-mono truncate">
                              [{r.check_module}]
                            </span>
                          )}
                          {r.evidence_count ? <Badge variant="secondary" className="ml-auto h-4 text-[10px]">{r.evidence_count}</Badge> : null}
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
    </div>
  );
}
