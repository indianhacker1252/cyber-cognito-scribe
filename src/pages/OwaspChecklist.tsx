import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { CheckCircle2, Circle, AlertTriangle, ListChecks } from "lucide-react";

type Row = {
  target_id: string;
  category: string;
  check_name: string;
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
  const [targets, setTargets] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      const [{ data: checks }, { data: tgts }] = await Promise.all([
        supabase.from("owasp_checklist" as any).select("*").order("category"),
        supabase.from("target_workspaces").select("id,name,domain"),
      ]);
      setRows((checks as any) || []);
      const m: Record<string, string> = {};
      (tgts || []).forEach((t: any) => (m[t.id] = t.name || t.domain));
      setTargets(m);
      setLoading(false);
    })();
  }, []);

  // group by target → category → checks
  const byTarget = new Map<string, Map<string, Row[]>>();
  for (const r of rows) {
    if (!byTarget.has(r.target_id)) byTarget.set(r.target_id, new Map());
    const cats = byTarget.get(r.target_id)!;
    if (!cats.has(r.category)) cats.set(r.category, []);
    cats.get(r.category)!.push(r);
  }

  const isDone = (s: string | null) => s === "evidence" || s === "passed" || s === "complete";

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center gap-2">
        <ListChecks className="h-6 w-6 text-primary" />
        <h1 className="text-2xl font-bold">OWASP Checklist Progress</h1>
      </div>
      <p className="text-muted-foreground text-sm">
        Per-check progress across the OWASP Top 10. Items in red are modules that
        never executed for this scan — re-run those scanners to close the gap.
      </p>

      {loading && <Card><CardContent className="p-12 text-center">Loading…</CardContent></Card>}
      {!loading && byTarget.size === 0 && (
        <Card><CardContent className="p-12 text-center text-muted-foreground">
          No checklist data yet. Start a scan to seed the checklist.
        </CardContent></Card>
      )}

      {Array.from(byTarget.entries()).map(([targetId, cats]) => {
        const all = Array.from(cats.values()).flat();
        const done = all.filter((r) => isDone(r.status)).length;
        const pct = all.length ? Math.round((done / all.length) * 100) : 0;
        const missing = all.filter((r) => !isDone(r.status));

        return (
          <Card key={targetId}>
            <CardHeader>
              <CardTitle className="flex justify-between items-center gap-3">
                <span>{targets[targetId] || targetId}</span>
                <div className="flex items-center gap-3">
                  <Badge variant={pct === 100 ? "default" : pct >= 70 ? "secondary" : "destructive"}>
                    {done}/{all.length} checks ({pct}%)
                  </Badge>
                </div>
              </CardTitle>
              <Progress value={pct} className="mt-3" />
            </CardHeader>
            <CardContent className="space-y-4">
              {missing.length > 0 && (
                <div className="rounded border border-destructive/40 bg-destructive/10 p-3">
                  <div className="flex items-center gap-2 text-sm font-semibold text-destructive mb-1">
                    <AlertTriangle className="h-4 w-4" /> Missing modules ({missing.length})
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {missing.slice(0, 30).map((m) => (
                      <Badge key={m.category + m.check_name} variant="outline" className="font-mono text-xs">
                        {m.check_name}
                      </Badge>
                    ))}
                    {missing.length > 30 && <Badge variant="outline">+{missing.length - 30} more</Badge>}
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
