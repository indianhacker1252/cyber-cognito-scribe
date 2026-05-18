import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ShieldCheck } from "lucide-react";

type Row = {
  target_id: string;
  owasp_category: string;
  checks_run: number;
  payloads_sent: number;
  findings_count: number;
  waf_blocked: number;
  last_run_at: string;
  metadata: any;
};

const ALL_CATEGORIES = [
  "A01:BAC", "A02:Crypto", "A03:Injection", "A04:Design", "A05:Misconfig",
  "A06:Components", "A07:Auth", "A08:Integrity", "A09:Logging", "A10:SSRF",
];

export default function OwaspCoverage() {
  const [rows, setRows] = useState<Row[]>([]);
  const [targets, setTargets] = useState<Record<string, string>>({});

  useEffect(() => {
    (async () => {
      const { data } = await supabase
        .from("owasp_coverage" as any)
        .select("*")
        .order("last_run_at", { ascending: false })
        .limit(500);
      setRows((data as any) || []);
      const { data: tgts } = await supabase.from("target_workspaces").select("id, target_name, target_url");
      const m: Record<string, string> = {};
      (tgts || []).forEach((t: any) => (m[t.id] = t.target_name || t.target_url));
      setTargets(m);
    })();
  }, []);

  // Aggregate per target × category (latest row wins because list is sorted desc)
  const agg = new Map<string, Map<string, Row>>();
  for (const r of rows) {
    if (!agg.has(r.target_id)) agg.set(r.target_id, new Map());
    const m = agg.get(r.target_id)!;
    if (!m.has(r.owasp_category)) m.set(r.owasp_category, r);
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center gap-2">
        <ShieldCheck className="h-6 w-6 text-primary" />
        <h1 className="text-2xl font-bold">OWASP Top 10 Coverage</h1>
      </div>
      <p className="text-muted-foreground text-sm">
        Proof of which OWASP categories were actively tested per target, how many payloads were sent,
        how many findings produced, and how many requests were blocked by a WAF.
      </p>

      {Array.from(agg.entries()).map(([targetId, cats]) => {
        const tested = cats.size;
        const totalPayloads = Array.from(cats.values()).reduce((a, b) => a + b.payloads_sent, 0);
        const totalWaf = Array.from(cats.values()).reduce((a, b) => a + b.waf_blocked, 0);
        return (
          <Card key={targetId}>
            <CardHeader>
              <CardTitle className="flex justify-between items-center">
                <span>{targets[targetId] || targetId}</span>
                <div className="flex gap-2">
                  <Badge variant={tested === 10 ? "default" : "secondary"}>{tested}/10 covered</Badge>
                  <Badge variant="outline">{totalPayloads} payloads</Badge>
                  {totalWaf > 0 && <Badge variant="destructive">WAF blocked {totalWaf}</Badge>}
                </div>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Category</TableHead>
                    <TableHead className="text-right">Checks</TableHead>
                    <TableHead className="text-right">Payloads</TableHead>
                    <TableHead className="text-right">Findings</TableHead>
                    <TableHead className="text-right">WAF blocks</TableHead>
                    <TableHead>Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {ALL_CATEGORIES.map((cat) => {
                    const row = cats.get(cat);
                    return (
                      <TableRow key={cat}>
                        <TableCell className="font-mono">{cat}</TableCell>
                        <TableCell className="text-right">{row?.checks_run ?? 0}</TableCell>
                        <TableCell className="text-right">{row?.payloads_sent ?? 0}</TableCell>
                        <TableCell className="text-right">{row?.findings_count ?? 0}</TableCell>
                        <TableCell className="text-right">{row?.waf_blocked ?? 0}</TableCell>
                        <TableCell>
                          {row
                            ? <Badge variant={row.findings_count ? "destructive" : "default"}>tested</Badge>
                            : <Badge variant="secondary">not tested</Badge>}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        );
      })}

      {agg.size === 0 && (
        <Card><CardContent className="p-12 text-center text-muted-foreground">
          No coverage data yet — run the template-runner against a target.
        </CardContent></Card>
      )}
    </div>
  );
}
