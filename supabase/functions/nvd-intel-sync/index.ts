// NVD Intel Sync — pulls latest CVEs from NIST NVD (free, no key needed)
// and cross-references with target tech stacks to queue relevant tests.
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};
function db() {
  return createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
}
async function safeFetch(url: string, opts: RequestInit = {}, ms = 15000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { ...opts, signal: ctrl.signal });
  } finally {
    clearTimeout(t);
  }
}

async function fetchNvdCves(daysBack = 1, limit = 200): Promise<any[]> {
  const cves: any[] = [];
  try {
    const pubStart = new Date(Date.now() - daysBack * 86400000).toISOString().split(".")[0] + ".000";
    const pubEnd = new Date().toISOString().split(".")[0] + ".000";
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${pubStart}&pubEndDate=${pubEnd}&resultsPerPage=${Math.min(limit, 2000)}`;
    const r = await safeFetch(url, { headers: { "User-Agent": "SPECTER-VAPT/1.0" } }, 20000);
    if (!r.ok) return cves;
    const data = await r.json();
    for (const item of data.vulnerabilities || []) {
      const cve = item.cve;
      const desc = cve.descriptions?.find((d: any) => d.lang === "en")?.value || "";
      const cvss =
        cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ||
        cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore ||
        0;
      const severity = cvss >= 9 ? "critical" : cvss >= 7 ? "high" : cvss >= 4 ? "medium" : "low";
      cves.push({
        cve_id: cve.id,
        title: `${cve.id}: ${desc.slice(0, 120)}`,
        description: desc,
        cvss_score: cvss,
        severity,
        published: cve.published,
        references: (cve.references || []).slice(0, 5).map((r: any) => r.url),
        affected_products: (cve.configurations || [])
          .flatMap((c: any) =>
            (c.nodes || []).flatMap((n: any) => (n.cpeMatch || []).map((m: any) => m.criteria || "")),
          )
          .slice(0, 10),
      });
    }
  } catch (e) {
    console.error("NVD fetch error:", e);
  }
  return cves;
}

function scoreRelevance(cve: any, fingerprint: any): number {
  let score = 0;
  const full = `${cve.title} ${cve.description}`.toLowerCase();
  const server = (fingerprint?.server || "").toLowerCase();
  const framework = (fingerprint?.framework || "").toLowerCase();
  const waf = (fingerprint?.waf || "").toLowerCase();
  const techMap: Record<string, string[]> = {
    cloudflare: ["cloudflare", "cf-ray"],
    nginx: ["nginx"],
    apache: ["apache", "httpd"],
    iis: ["iis", "asp.net"],
    wordpress: ["wordpress", "wp-"],
    nextjs: ["next.js", "nextjs"],
    nodejs: ["node.js", "express"],
    django: ["django"],
    laravel: ["laravel", "php"],
    spring: ["spring", "tomcat"],
  };
  for (const [tech, kw] of Object.entries(techMap)) {
    if ((server + framework + waf).includes(tech) && kw.some((k) => full.includes(k))) score += 40;
  }
  if (cve.cvss_score >= 9) score += 30;
  else if (cve.cvss_score >= 7) score += 20;
  else if (cve.cvss_score >= 4) score += 10;
  if (/exploit|poc|rce|injection|bypass|0.day/i.test(full)) score += 15;
  if (/waf.bypass|firewall.bypass|cloudflare.bypass/i.test(full)) score += 25;
  return Math.min(score, 100);
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
  try {
    const supa = db();
    const body = await req.json().catch(() => ({}));
    const daysBack = body.daysBack || 1;
    const action = body.action || "full-sync";

    if (action === "relevance-check" && body.targetId) {
      const { data: recon } = await supa
        .from("agent_tasks")
        .select("result")
        .eq("target_id", body.targetId)
        .eq("task_type", "reconnaissance")
        .order("created_at", { ascending: false })
        .limit(1)
        .maybeSingle();
      const fingerprint = (recon?.result as any)?.tech_fingerprint || {};
      const { data: feeds } = await supa
        .from("nvd_intel")
        .select("*")
        .order("published", { ascending: false })
        .limit(200);
      const ranked = (feeds || [])
        .map((f) => ({ ...f, relevanceScore: scoreRelevance(f, fingerprint) }))
        .filter((f) => f.relevanceScore >= 30)
        .sort((a, b) => b.relevanceScore - a.relevanceScore)
        .slice(0, 10);
      return new Response(JSON.stringify({ success: true, relevant: ranked }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const nvdCves = await fetchNvdCves(daysBack, 200);
    let inserted = 0,
      skipped = 0,
      autoQueued = 0;

    for (const cve of nvdCves) {
      const { error } = await supa.from("nvd_intel").upsert(
        {
          cve_id: cve.cve_id,
          title: cve.title,
          description: cve.description,
          cvss_score: cve.cvss_score,
          severity: cve.severity,
          published: cve.published,
          references: cve.references,
          affected_products: cve.affected_products,
          synced_at: new Date().toISOString(),
        },
        { onConflict: "cve_id", ignoreDuplicates: true },
      );
      if (error) skipped++;
      else inserted++;
    }

    // Auto-match against ALL targets (running, completed, queued) — not just completed.
    // Users complained NVD was never checked because most targets sit in 'running'.
    const { data: targets } = await supa
      .from("target_workspaces")
      .select("id, domain, name, status")
      .in("status", ["completed", "running", "queued", "in_progress"])
      .limit(50);
    for (const target of targets || []) {
      const { data: recon } = await supa
        .from("agent_tasks")
        .select("result")
        .eq("target_id", target.id)
        .eq("task_type", "reconnaissance")
        .order("created_at", { ascending: false })
        .limit(1)
        .maybeSingle();
      const fingerprint = (recon?.result as any)?.tech_fingerprint || {};
      const high = nvdCves
        .map((c) => ({ ...c, score: scoreRelevance(c, fingerprint) }))
        .filter((c) => c.score >= 60 && c.cvss_score >= 7)
        .sort((a, b) => b.score - a.score)
        .slice(0, 3);
      for (const cve of high) {
        await supa.from("scan_logs").insert({
          target_id: target.id,
          log_type: "info",
          message: `🔴 NVD auto-match: ${cve.cve_id} (CVSS ${cve.cvss_score}, relevance ${cve.score}/100) — queuing targeted test`,
          metadata: { cve_id: cve.cve_id, cvss: cve.cvss_score, relevance: cve.score },
        });

        // Deduplication: skip if a cve job for this exact CVE+target is already
        // queued or running. Without this check, the cron fires hourly and creates
        // a new job every time — the same CVE appears 12+ times in a 12-hour scan log.
        const { data: existing } = await supa
          .from("scan_jobs")
          .select("id")
          .eq("target_id", target.id)
          .eq("job_type", "cve")
          .in("status", ["queued", "running"])
          .contains("payload", { cveId: cve.cve_id })
          .limit(1)
          .maybeSingle();
        if (existing) continue;

        await supa.from("scan_jobs").insert({
          target_id: target.id,
          job_type: "cve",
          status: "queued",
          priority: 8,
          payload: { cveId: cve.cve_id, cvssScore: cve.cvss_score, description: cve.description.slice(0, 500) },
          next_run_at: new Date().toISOString(),
        });
        autoQueued++;
      }
    }

    return new Response(JSON.stringify({ success: true, nvdFetched: nvdCves.length, inserted, skipped, autoQueued }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (e) {
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : "Unknown" }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
