// Score CyberScope agent runs vs expected finding classes per lab (Mythos L4 bench).
// Usage: SUPABASE_URL=… SUPABASE_SERVICE_ROLE_KEY=… tsx bench/run.ts
import { createClient } from "@supabase/supabase-js";
import expected from "./expected.json" with { type: "json" };
import fs from "node:fs";

const sb = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);
const since = new Date(Date.now() - 24 * 3600 * 1000).toISOString();

type LabKey = keyof typeof expected;
const report: Record<string, any> = { ts: new Date().toISOString(), labs: {}, aggregate: {} };
let totP = 0, totR = 0, labN = 0, totRejected = 0, totConfirmed = 0;

for (const [lab, cfg] of Object.entries(expected) as [LabKey, any][]) {
  const { data: targets } = await sb.from("target_workspaces").select("id,url,domain").ilike("url", `%${new URL(cfg.url).host}%`);
  const tgt = targets?.[0];
  if (!tgt) { report.labs[lab] = { skipped: "no target in DB" }; continue; }

  const [{ data: findings }, { data: metrics }, { data: experiences }] = await Promise.all([
    sb.from("vulnerability_findings")
      .select("vuln_class,severity,proof_tier,created_at").eq("target_id", tgt.id).gte("created_at", since),
    sb.from("agent_metrics")
      .select("metric,value,tags,created_at").eq("target_id", tgt.id).gte("created_at", since),
    sb.from("agent_experiences")
      .select("vuln_class,outcome,confidence,created_at").eq("target_id", tgt.id).gte("created_at", since),
  ]);

  const foundClasses = new Set((findings ?? []).map(f => String(f.vuln_class ?? "").toLowerCase()));
  const expClasses: string[] = cfg.expected_classes;
  const hits = expClasses.filter(c => [...foundClasses].some(f => f.includes(c)));
  const precision = foundClasses.size ? hits.length / foundClasses.size : 0;
  const recall = expClasses.length ? hits.length / expClasses.length : 0;

  const confirmed = (findings ?? []).filter(f => f.proof_tier === "confirmed" || f.proof_tier === "exploited").length;
  const rejected = (experiences ?? []).filter(e => e.outcome === "dead_end").length;

  const sum = (name: string) => (metrics ?? []).filter(m => m.metric === name).reduce((a, b) => a + Number(b.value), 0);

  report.labs[lab] = {
    findings_total: findings?.length ?? 0,
    confirmed, rejected_by_oracle: sum("findings_rejected_by_oracle"),
    hits: hits.length, expected: expClasses.length,
    precision: +precision.toFixed(3), recall: +recall.toFixed(3),
    f1: +(precision + recall ? (2 * precision * recall) / (precision + recall) : 0).toFixed(3),
    missed: expClasses.filter(c => !hits.includes(c)),
    metrics: {
      tool_calls: sum("tool_calls"),
      oracle_calls: sum("oracle_calls"),
      plan_coverage_avg: (() => {
        const xs = (metrics ?? []).filter(m => m.metric === "plan_coverage").map(m => Number(m.value));
        return xs.length ? +(xs.reduce((a, b) => a + b, 0) / xs.length).toFixed(3) : 0;
      })(),
    },
    experiences_learned: (experiences ?? []).length,
  };
  totP += precision; totR += recall; labN += 1;
  totConfirmed += confirmed; totRejected += rejected;
}

report.aggregate = {
  labs_scored: labN,
  precision_avg: labN ? +(totP / labN).toFixed(3) : 0,
  recall_avg: labN ? +(totR / labN).toFixed(3) : 0,
  confirmed_total: totConfirmed,
  rejected_total: totRejected,
};

const histPath = "bench/history.json";
const history = fs.existsSync(histPath) ? JSON.parse(fs.readFileSync(histPath, "utf8")) : [];
history.push(report); fs.writeFileSync(histPath, JSON.stringify(history.slice(-50), null, 2));

console.log(JSON.stringify(report, null, 2));
