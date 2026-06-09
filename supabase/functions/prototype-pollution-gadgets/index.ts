// Prototype Pollution & Gadget Chain detector.
// Crawls JS bundles, finds polluting sinks + known gadget signatures, probes endpoints with PP payloads.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { safeFetch, readBodySafe } from "../_shared/safe-fetch.ts";

const cors = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type" };
const db = () => createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

const SINKS = [
  { name: "Object.assign", regex: /Object\.assign\s*\(\s*[^,]+,\s*[A-Za-z_$][\w$]*\s*\)/g },
  { name: "lodash.merge",  regex: /\b_?\.merge\s*\(/g },
  { name: "lodash.set",    regex: /\b_?\.set\s*\(/g },
  { name: "jquery.extend(true)", regex: /\$\.extend\s*\(\s*true/g },
  { name: "Object spread mass-assign", regex: /\{\s*\.\.\.[A-Za-z_$][\w$]*\s*,\s*\.\.\.req\.(body|query|params)/g },
];
const GADGETS = [
  { name: "jQuery getScript gadget", regex: /\.getScript\s*\(/ },
  { name: "Express render gadget", regex: /res\.render\s*\(/ },
  { name: "Lodash template gadget", regex: /_\.template\s*\(/ },
];
const PP_PAYLOADS = [
  { name: "json-proto", body: { "__proto__": { "polluted": "yes_pp_2026" } } },
  { name: "json-ctor",  body: { "constructor": { "prototype": { "polluted": "yes_pp_2026" } } } },
];

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const { targetId } = await req.json();
    const supa = db();
    const { data: target } = await supa.from("target_workspaces").select("domain").eq("id", targetId).maybeSingle();
    const base = target?.domain?.startsWith("http") ? target.domain : `https://${target?.domain}`;
    const { data: eps } = await supa.from("discovered_endpoints").select("url,method,parameters").eq("target_id", targetId).limit(50);
    const findings: any[] = [];

    // 1. SAST on JS assets
    try {
      const r = await safeFetch(base, {}, 6000);
      const html = await readBodySafe(r, 64 * 1024);
      const jsUrls = [...html.matchAll(/<script[^>]+src=["']([^"']+\.js[^"']*)["']/g)].map(m => m[1]).slice(0, 8);
      for (const u of jsUrls) {
        const abs = u.startsWith("http") ? u : new URL(u, base).toString();
        try {
          const jr = await safeFetch(abs, {}, 7000);
          const js = await readBodySafe(jr, 200 * 1024);
          const hitSinks = SINKS.filter(s => s.regex.test(js)).map(s => s.name);
          const hitGadgets = GADGETS.filter(g => g.regex.test(js)).map(g => g.name);
          if (hitSinks.length) {
            findings.push({
              target_id: targetId, title: `Prototype-pollution sink in ${abs.split("/").pop()}`,
              severity: hitGadgets.length ? "high" : "medium",
              description: `Static analysis found pollution sink(s): ${hitSinks.join(", ")}${hitGadgets.length ? ` + reachable gadgets: ${hitGadgets.join(", ")}` : ""}`,
              affected_url: abs, payload: hitSinks[0],
              vuln_class: "prototype_pollution", confidence_score: hitGadgets.length ? 0.75 : 0.5,
              source: "prototype-pollution-gadgets",
              proof_tier: hitGadgets.length ? "suspected" : "indicator",
              evidence: { sinks: hitSinks, gadgets: hitGadgets },
            });
          }
        } catch {}
      }
    } catch {}

    // 2. Dynamic: POST PP payload to JSON endpoints, then GET and look for echoed "polluted"
    for (const ep of (eps || []).slice(0, 15)) {
      if (!["POST", "PUT", "PATCH"].includes(ep.method?.toUpperCase() || "")) continue;
      for (const p of PP_PAYLOADS) {
        try {
          await safeFetch(ep.url, { method: ep.method, headers: { "Content-Type": "application/json" }, body: JSON.stringify(p.body) }, 5000);
          const verify = await safeFetch(ep.url, { method: "GET" }, 5000);
          const vbody = await readBodySafe(verify, 8000);
          if (vbody.includes("yes_pp_2026")) {
            findings.push({
              target_id: targetId, title: `Prototype Pollution CONFIRMED (${p.name})`,
              severity: "critical",
              description: `Endpoint accepted ${p.name} pollution payload; injected property reflected on subsequent request — server-side prototype pollution.`,
              affected_url: ep.url, payload: JSON.stringify(p.body),
              vuln_class: "prototype_pollution", confidence_score: 0.95,
              source: "prototype-pollution-gadgets", proof_tier: "exploited",
              evidence: { verifyBody: vbody.slice(0, 400) },
            });
          }
        } catch {}
      }
    }

    if (findings.length) await supa.from("vulnerability_findings").insert(findings);
    await supa.from("scan_logs").insert({
      target_id: targetId, log_type: findings.length ? "warning" : "info",
      message: `🧬 Prototype-Pollution scan: ${findings.length} sink/gadget findings`,
      metadata: { count: findings.length },
    });

    return new Response(JSON.stringify({ findings: findings.length }), { headers: { ...cors, "Content-Type": "application/json" } });
  } catch (e) {
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : String(e) }), { status: 200, headers: { ...cors, "Content-Type": "application/json" } });
  }
});
