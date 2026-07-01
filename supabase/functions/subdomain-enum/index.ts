// subdomain-enum — discover subdomains via crt.sh + small DNS-style wordlist probe,
// then persist into scan_assets so every downstream scanner fans out across them.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

const COMMON = [
  "www","api","app","dev","staging","stage","test","qa","uat","admin","portal","dashboard",
  "auth","login","sso","oauth","secure","my","account","accounts","beta","blog","cdn",
  "static","assets","img","images","media","mail","webmail","smtp","ftp","vpn","intranet",
  "internal","corp","office","files","docs","help","support","status","monitor","grafana",
  "kibana","jenkins","git","gitlab","gitea","jira","confluence","wiki","shop","store",
  "pay","billing","checkout","m","mobile","old","new","v1","v2","api-staging","api-dev"
];

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function normalizeHost(h: string): string {
  return String(h || "").trim().toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/^\*\./, "")
    .replace(/\/.*$/, "")
    .replace(/:\d+$/, "")
    .replace(/\.$/, "");
}

async function probe(host: string, ms = 4000): Promise<boolean> {
  for (const scheme of ["https","http"]) {
    const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), ms);
    try {
      const r = await fetch(`${scheme}://${host}`, { method: "HEAD", redirect: "manual", signal: ctrl.signal });
      clearTimeout(t);
      if (r.status > 0 && r.status < 600) return true;
    } catch { clearTimeout(t); /* try next scheme */ }
  }
  return false;
}

async function crtsh(apex: string): Promise<string[]> {
  try {
    const ctrl = new AbortController(); const t = setTimeout(() => ctrl.abort(), 12000);
    const r = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(apex)}&output=json`, { signal: ctrl.signal });
    clearTimeout(t);
    if (!r.ok) return [];
    const rows = await r.json().catch(() => []);
    const set = new Set<string>();
    for (const row of rows || []) {
      const nv: string = row?.name_value || "";
      for (const n of nv.split(/\s+/)) {
        const h = n.replace(/^\*\./, "").trim().toLowerCase();
        if (h && (h === apex || h.endsWith("." + apex))) set.add(h);
      }
    }
    return [...set];
  } catch { return []; }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  const ok = (b: unknown) => new Response(JSON.stringify(b), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });

  try {
    const { targetId } = await req.json().catch(() => ({}));
    if (!targetId) return ok({ ok: false, error: "targetId required" });
    const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
    const { data: tgt } = await db.from("target_workspaces").select("domain").eq("id", targetId).maybeSingle();
    const apex = String(tgt?.domain || "").trim().toLowerCase().replace(/^https?:\/\//,"").replace(/\/.*$/,"").replace(/:\d+$/,"");
    if (!apex) return ok({ ok: false, error: "no apex domain" });

    await db.from("scan_logs").insert({
      target_id: targetId, log_type: "action",
      message: `🌐 Subdomain enum starting for ${apex} (crt.sh + ${COMMON.length}-word DNS)`,
    });

    // 1) Passive: crt.sh
    const passive = await crtsh(apex);

    // 2) Active: small wordlist
    const candidates = new Set<string>([apex, ...passive, ...COMMON.map(w => `${w}.${apex}`)]);
    const alive: string[] = [];
    const queue = [...candidates];
    const CONCURRENCY = 8;
    await Promise.all(Array.from({ length: CONCURRENCY }, async () => {
      while (queue.length) {
        const h = queue.shift()!;
        if (await probe(h)) alive.push(h);
      }
    }));

    if (alive.length) {
      await db.from("scan_assets").upsert(
        alive.map((h) => ({
          target_id: targetId, host: h,
          base_url: `https://${h}`,
          source: h === apex ? "apex" : "subdomain",
        })),
        { onConflict: "target_id,host", ignoreDuplicates: true },
      );
    }

    await db.from("scan_logs").insert({
      target_id: targetId, log_type: "info",
      message: `🌐 Subdomain enum done: ${alive.length} live host(s) (passive ${passive.length}, brute ${COMMON.length})`,
      metadata: { alive, passive_count: passive.length, brute_count: COMMON.length },
    });

    // Fan out: queue recon-juicy + matrix-fuzz for each new host
    if (alive.length) {
      const jobs = alive.flatMap((h) => ([
        { target_id: targetId, job_type: "recon_juicy", priority: 6, status: "queued",
          payload: { host: h, base_url: `https://${h}` }, next_run_at: new Date().toISOString() },
        { target_id: targetId, job_type: "matrix_fuzz", priority: 5, status: "queued",
          payload: { host: h, base_url: `https://${h}` }, next_run_at: new Date(Date.now() + 5_000).toISOString() },
      ]));
      await db.from("scan_jobs").insert(jobs).then(() => {}, () => {});
    }

    return ok({ ok: true, apex, alive, passive_count: passive.length });
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: e instanceof Error ? e.message : "err" }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
