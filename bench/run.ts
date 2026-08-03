// Score CyberScope agent runs vs expected finding classes per lab.
// Usage:  SUPABASE_URL=… SUPABASE_SERVICE_ROLE_KEY=… tsx bench/run.ts
import { createClient } from "@supabase/supabase-js";
import expected from "./expected.json" with { type: "json" };
import fs from "node:fs";

const sb = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);
const since = new Date(Date.now() - 24 * 3600 * 1000).toISOString();

type LabKey = keyof typeof expected;
const report: Record<string, any> = { ts: new Date().toISOString(), labs: {} };

for (const [lab, cfg] of Object.entries(expected) as [LabKey, any][]) {
  const { data: targets } = await sb.from("target_workspaces").select("id,url,domain").ilike("url", `%${new URL(cfg.url).host}%`);
  const tgt = targets?.[0];
  if (!tgt) { report.labs[lab] = { skipped: "no target in DB" }; continue; }

  const { data: findings } = await sb.from("vulnerability_findings")
    .select("vuln_class,severity,proof_tier,created_at")
    .eq("target_id", tgt.id).gte("created_at", since);

  const foundClasses = new Set((findings ?? []).map(f => String(f.vuln_class ?? "").toLowerCase()));
  const expClasses: string[] = cfg.expected_classes;
  const hits = expClasses.filter(c => [...foundClasses].some(f => f.includes(c)));
  const precision = foundClasses.size ? hits.length / foundClasses.size : 0;
  const recall = expClasses.length ? hits.length / expClasses.length : 0;

  report.labs[lab] = {
    findings_total: findings?.length ?? 0,
    hits: hits.length,
    expected: expClasses.length,
    precision: +precision.toFixed(3),
    recall: +recall.toFixed(3),
    missed: expClasses.filter(c => !hits.includes(c)),
  };
}

const histPath = "bench/history.json";
const history = fs.existsSync(histPath) ? JSON.parse(fs.readFileSync(histPath, "utf8")) : [];
history.push(report); fs.writeFileSync(histPath, JSON.stringify(history.slice(-50), null, 2));

console.log(JSON.stringify(report, null, 2));
