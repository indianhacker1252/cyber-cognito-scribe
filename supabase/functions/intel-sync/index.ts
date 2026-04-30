import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { createEvidencePackage } from "../_shared/proof-packages.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

function supabaseAdmin() {
  return createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!
  );
}

async function safeFetch(url: string, opts: RequestInit = {}, timeoutMs = 8000): Promise<Response> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try { return await fetch(url, { ...opts, signal: ctrl.signal }); }
  finally { clearTimeout(timer); }
}

// ─── Source Fetchers ────────────────────────────────────

async function fetchGitHubAdvisories(limit = 50) {
  const reports: any[] = [];
  try {
    for (let page = 1; page <= Math.ceil(limit / 100); page++) {
      const perPage = Math.min(limit - reports.length, 100);
      if (perPage <= 0) break;
      const resp = await fetch(
        `https://api.github.com/advisories?type=reviewed&per_page=${perPage}&page=${page}`,
        { headers: { Accept: "application/vnd.github+json", "User-Agent": "CyberScope-Scanner/1.0", "X-GitHub-Api-Version": "2022-11-28" } }
      );
      if (resp.ok) {
        const advisories = await resp.json();
        if (advisories.length === 0) break;
        for (const adv of advisories) {
          const techStack = (adv.vulnerabilities || []).map((v: any) => v.package?.name).filter(Boolean);
          reports.push({
            source: "github-advisory",
            report_id: adv.ghsa_id || adv.cve_id || `gh-${Date.now()}-${reports.length}`,
            title: adv.summary || "Untitled",
            raw_summary: (adv.description || "").slice(0, 1000),
            severity: adv.severity || "medium",
            source_url: adv.html_url || "",
            affected_tech_stack: techStack,
            vulnerability_class: adv.cwe_ids?.[0] || null,
            cve_ids: adv.cve_id ? [adv.cve_id] : [],
          });
        }
      } else break;
      await new Promise((r) => setTimeout(r, 300));
    }
  } catch (e) { console.error("GitHub Advisory error:", e); }
  return reports;
}

async function fetchExploitDB(limit = 50) {
  const reports: any[] = [];
  try {
    const resp = await fetch("https://www.exploit-db.com/rss.xml", { headers: { "User-Agent": "CyberScope-Scanner/1.0" } });
    if (resp.ok) {
      const xml = await resp.text();
      const items = xml.match(/<item>[\s\S]*?<\/item>/g) || [];
      for (const item of items.slice(0, limit)) {
        const title = item.match(/<title>(.*?)<\/title>/)?.[1] || "Untitled";
        const link = item.match(/<link>(.*?)<\/link>/)?.[1] || "";
        const desc = item.match(/<description>(.*?)<\/description>/)?.[1] || "";
        reports.push({
          source: "exploit-db",
          report_id: `edb-${link.split("/").pop() || Date.now()}-${reports.length}`,
          title: decodeXml(title),
          raw_summary: decodeXml(desc).slice(0, 1000),
          severity: "high",
          source_url: link,
          affected_tech_stack: [],
        });
      }
    }
  } catch (e) { console.error("ExploitDB error:", e); }
  return reports;
}

function decodeXml(s: string): string {
  return s.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/<!\[CDATA\[(.*?)\]\]>/g, "$1");
}

// ─── AI Interpretation ─────────────────────────────────

async function aiInterpretReport(report: any): Promise<any> {
  const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
  if (!LOVABLE_API_KEY) return heuristicInterpret(report);

  try {
    const resp = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${LOVABLE_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash-lite",
        messages: [
          { role: "system", content: "You are a security intelligence analyst. Extract structured vulnerability data from disclosed security reports. Return via the tool." },
          { role: "user", content: `Analyze this disclosed security report:\n\nTitle: ${report.title}\nSummary: ${(report.raw_summary || "").slice(0, 500)}\nSeverity: ${report.severity}\n\nExtract: vulnerability class, specific payloads, affected tech stack, WAF bypass logic, bypass techniques, signal strength (high/medium/low), and OWASP category.` },
        ],
        tools: [{
          type: "function",
          function: {
            name: "report_intelligence",
            description: "Report extracted security intelligence",
            parameters: {
              type: "object",
              properties: {
                vulnerabilityClass: { type: "string" },
                specificPayloads: { type: "array", items: { type: "string" } },
                affectedTechStack: { type: "array", items: { type: "string" } },
                wafBypassLogic: { type: "string" },
                bypassTechniques: { type: "array", items: { type: "string" } },
                signalStrength: { type: "string", enum: ["high", "medium", "low"] },
                owaspCategory: { type: "string" },
              },
              required: ["vulnerabilityClass", "specificPayloads", "affectedTechStack", "signalStrength"],
              additionalProperties: false,
            },
          },
        }],
        tool_choice: { type: "function", function: { name: "report_intelligence" } },
      }),
    });

    if (resp.status === 429 || resp.status === 402) return heuristicInterpret(report);
    if (resp.ok) {
      const data = await resp.json();
      const toolCall = data.choices?.[0]?.message?.tool_calls?.[0];
      if (toolCall) return JSON.parse(toolCall.function.arguments);
    }
  } catch (e) { console.error("AI interpret error:", e); }
  return heuristicInterpret(report);
}

function heuristicInterpret(report: any) {
  const text = `${report.title} ${report.raw_summary}`.toLowerCase();
  const vulnMap: Record<string, string[]> = {
    sqli: ["sql injection", "sqli", "blind sql"], rxss: ["xss", "cross-site scripting"],
    ssrf: ["ssrf", "server-side request"], cmdi: ["command injection", "rce", "remote code"],
    ssti: ["ssti", "template injection"], idor: ["idor", "insecure direct object"],
    "path-traversal": ["path traversal", "directory traversal", "lfi"],
    xxe: ["xxe", "xml external"], "auth-bypass": ["authentication bypass", "auth bypass"],
    deserialization: ["deserialization", "insecure deserialization"],
  };
  let vulnClass = "unknown";
  for (const [cls, kw] of Object.entries(vulnMap)) {
    if (kw.some((k) => text.includes(k))) { vulnClass = cls; break; }
  }
  const techKw = ["nginx", "apache", "node.js", "django", "flask", "spring", "laravel", "wordpress", "php", "python", "java", "jenkins", "docker", "kubernetes", "express", "rails", "ruby"];
  const stack = techKw.filter((t) => text.includes(t));
  const bypassKw = ["bypass", "waf bypass", "filter bypass", "encoding bypass", "double encoding", "null byte", "unicode"];
  const bypasses = bypassKw.filter((b) => text.includes(b));
  return {
    vulnerabilityClass: vulnClass, specificPayloads: [], affectedTechStack: stack,
    wafBypassLogic: bypasses.length > 0 ? bypasses.join("; ") : null,
    bypassTechniques: bypasses,
    signalStrength: bypasses.length > 0 ? "high" : stack.length > 0 ? "medium" : "low",
    owaspCategory: "Unknown",
  };
}

// ─── Template Generation ────────────────────────────────

function generateTemplate(vulnClass: string, payloads: string[], bypasses: string[]) {
  const classPayloads: Record<string, string[]> = {
    sqli: ["' AND '1'='1", "' OR 1=1--", "' UNION SELECT NULL--"],
    rxss: ["<cyberscope>", '"><svg onload=alert(1)>'],
    ssrf: ["http://127.0.0.1:80", "http://169.254.169.254/latest/meta-data/"],
    cmdi: ["; echo cyberscope", "| echo cyberscope"],
    ssti: ["{{1337*2}}", "${1337*2}", "<%= 1337*2 %>"],
    "path-traversal": ["....//....//etc/passwd", "..%2f..%2f..%2fetc/passwd"],
  };
  const allPayloads = [...payloads, ...(classPayloads[vulnClass] || classPayloads.sqli)];
  return {
    vulnClass,
    payloads: [...new Set(allPayloads)],
    bypasses,
    detectionRules: vulnClass === "sqli" ? ["sql_error", "length_diff"] : vulnClass === "rxss" ? ["body_contains"] : ["status_diff"],
  };
}

function templateToScript(template: any): string {
  const pList = template.payloads.map((p: string) => `    "${p.replace(/"/g, '\\"')}"`).join(",\n");
  return `#!/usr/bin/env python3
"""CyberScope Intel Template: ${template.vulnClass}"""
import requests, sys, time
TARGET = sys.argv[1] if len(sys.argv) > 1 else "{{TARGET_URL}}"
payloads = [\n${pList}\n]
baseline = requests.get(TARGET, timeout=15)
for p in payloads:
    time.sleep(0.3)
    r = requests.get(TARGET, params={"test": p}, timeout=15)
    if abs(len(r.text) - len(baseline.text)) > 50 or r.status_code != baseline.status_code:
        print(f"[+] HIT: {p[:60]}")
`;
}

// ─── Target Matching ────────────────────────────────────

async function findMatchingTargets(db: any, techStack: string[]) {
  if (techStack.length === 0) return [];
  const { data: targets } = await db.from("target_workspaces").select("id, name, domain").eq("status", "completed");
  if (!targets) return [];

  const matches: any[] = [];
  for (const t of targets) {
    const { data: recon } = await db.from("agent_tasks").select("result")
      .eq("target_id", t.id).eq("task_type", "reconnaissance").eq("status", "completed")
      .order("created_at", { ascending: false }).limit(1).single();
    if (!recon?.result) continue;
    const fp = (recon.result as any).tech_fingerprint || {};
    const tTech = [fp.server, fp.framework, fp.poweredBy].filter(Boolean).map((s: string) => s.toLowerCase());
    const matched = techStack.filter((s) => tTech.some((tt: string) => tt.includes(s.toLowerCase())));
    if (matched.length > 0) matches.push({ ...t, matchedTech: matched });
  }
  return matches;
}

// ─── Auto-Test Intel Templates on Matching Targets ──────

async function autoTestTemplateOnTarget(
  db: any,
  feedId: string,
  targetId: string,
  targetDomain: string,
  template: any,
  vulnClass: string
): Promise<{ tested: boolean; confirmed: boolean; findingId?: string }> {
  if (!targetDomain) return { tested: false, confirmed: false };

  const baseUrl = targetDomain.startsWith("http") ? targetDomain : `https://${targetDomain}`;
  const payloads = template?.payloads || [];
  if (payloads.length === 0) return { tested: false, confirmed: false };

  // Get endpoints for this target
  const { data: endpoints } = await db.from("discovered_endpoints")
    .select("url, parameters").eq("target_id", targetId).limit(10);

  if (!endpoints || endpoints.length === 0) return { tested: false, confirmed: false };

  let confirmed = false;
  let bestPayload = "";
  let bestEvidence = "";
  let bestRequest: any = null;
  let bestBaseline: any = null;
  let bestMutated: any = null;

  for (const ep of endpoints.slice(0, 5)) {
    const params = (ep.parameters || {}) as Record<string, string>;
    const paramNames = Object.keys(params);
    if (paramNames.length === 0) continue;

    for (const payload of payloads.slice(0, 5)) {
      for (const paramName of paramNames.slice(0, 3)) {
        try {
          // Baseline request
          const baseResp = await safeFetch(ep.url, {
            method: "GET",
            headers: { "User-Agent": "CyberScope-Scanner/1.0" },
            redirect: "manual",
          }, 6000);
          const baseBody = await baseResp.text();

          // Mutated request
          const url = new URL(ep.url);
          url.searchParams.set(paramName, payload);
          const mutResp = await safeFetch(url.toString(), {
            method: "GET",
            headers: { "User-Agent": "CyberScope-Scanner/1.0" },
            redirect: "manual",
          }, 6000);
          const mutBody = await mutResp.text();

          // Deterministic proof only — no promotion from status/length drift alone
          const lenDiff = Math.abs(mutBody.length - baseBody.length);
          const sqlError = /sql syntax|SQLSTATE|ORA-|pg_query|unclosed quotation/i.test(mutBody) && !/sql syntax|SQLSTATE|ORA-|pg_query|unclosed quotation/i.test(baseBody);
          const xssProof = vulnClass === "rxss" && mutBody.includes("<cyberscope>") && !baseBody.includes("<cyberscope>");
          const cmdProof = vulnClass === "cmdi" && /cyberscope_marker|uid=\d+\(/i.test(mutBody) && !/cyberscope_marker|uid=\d+\(/i.test(baseBody);
          // Use the unique 1337*2=2674 marker (not 7*7=49 which appears in many normal pages),
          // and require the literal payload is NOT reflected verbatim (verbatim = template not evaluated).
          const sstiProof = vulnClass === "ssti" && /\b2674\b/.test(mutBody) && !/\b2674\b/.test(baseBody) && !mutBody.includes("{{1337*2}}") && !mutBody.includes("<%= 1337*2 %>");
          const fileProof = vulnClass === "path-traversal" && /root:.*:0:0|\/bin\/bash/i.test(mutBody) && !/root:.*:0:0|\/bin\/bash/i.test(baseBody);
          const hasEvidence = sqlError || xssProof || cmdProof || sstiProof || fileProof;

          if (hasEvidence) {
            confirmed = true;
            bestPayload = payload;
            bestEvidence = `Deterministic proof: baseline(${baseResp.status}, ${baseBody.length}B) vs mutated(${mutResp.status}, ${mutBody.length}B). Delta: ${lenDiff}B.`;
            bestRequest = {
              method: "GET",
              url: url.toString(),
              headers: { "User-Agent": "CyberScope-Scanner/1.0" },
              payload,
              parameter: paramName,
            };
            bestBaseline = { status: baseResp.status, body: baseBody, length: baseBody.length };
            bestMutated = { status: mutResp.status, body: mutBody, length: mutBody.length, headers: Object.fromEntries(mutResp.headers.entries()) };
            break;
          }

          await new Promise((r) => setTimeout(r, 200));
        } catch { /* skip */ }
      }
      if (confirmed) break;
    }
    if (confirmed) break;
  }

  if (confirmed) {
    // Create finding in pending_approvals for high/critical or auto-accept
    const severity = vulnClass === "sqli" || vulnClass === "cmdi" || vulnClass === "ssrf" ? "high" : "medium";
    const isHighSev = severity === "high" || severity === "critical";

    if (isHighSev) {
      const { data: finding } = await db.from("pending_approvals").insert({
        target_id: targetId,
        finding_type: `intel-auto-test-${vulnClass}`,
        severity,
        title: `🔴 Intel-Confirmed: ${vulnClass.toUpperCase()} (auto-tested from disclosure)`,
        description: `Automatically tested from intel feed and CONFIRMED.\n\n**Evidence:** ${bestEvidence}\n\n**Payload:** \`${bestPayload}\`\n\n**Source:** Intel Feed ${feedId}`,
        payload_used: bestPayload,
        confidence_level: "high",
        confidence_score: 85,
        ai_verified: true,
        ai_verification_notes: `Auto-tested from intel feed. Differential analysis confirmed vulnerability.`,
        triage_reasoning: `Intel-driven auto-test confirmed via differential analysis`,
        request_data: bestRequest,
        baseline_response: bestBaseline,
        mutated_response: bestMutated,
        evidence: { intelFeedId: feedId, vulnClass, payload: bestPayload, evidence: bestEvidence },
      }).select("id").single();

      if (finding?.id) {
        await createEvidencePackage(db, {
          targetId,
          approvalId: finding.id,
          title: `Intel-confirmed ${vulnClass.toUpperCase()}`,
          proofSummary: `${bestEvidence} Intel feed ${feedId} mapped to the target and reproduced with an exploit request.`,
          request: bestRequest,
          baselineResponse: bestBaseline,
          mutatedResponse: bestMutated,
          validationStatus: "verified",
          cveIds: [feedId],
        });
      }

      return { tested: true, confirmed: true, findingId: finding?.id };
    } else {
      const { data: finding } = await db.from("vulnerability_findings").insert({
        target_id: targetId,
        title: `Intel-Confirmed: ${vulnClass.toUpperCase()} (auto-tested)`,
        severity,
        description: `Auto-tested from intel feed.\n\n**Evidence:** ${bestEvidence}\n\n**Payload:** \`${bestPayload}\``,
        payload: bestPayload,
        confidence_score: 75,
        confidence_level: "medium",
        ai_verified: true,
        triage_reasoning: `Intel-driven auto-test. ${bestEvidence}`,
        validation_status: "auto-tested",
      }).select("id").single();

      if (finding?.id) {
        const evidenceId = await createEvidencePackage(db, {
          targetId,
          findingId: finding.id,
          title: `Intel-confirmed ${vulnClass.toUpperCase()}`,
          proofSummary: `${bestEvidence} Intel feed ${feedId} reproduced with proof on target ${targetId}.`,
          request: bestRequest,
          baselineResponse: bestBaseline,
          mutatedResponse: bestMutated,
          validationStatus: "verified",
          cveIds: [feedId],
        });
        if (evidenceId) await db.from("vulnerability_findings").update({ evidence_package_id: evidenceId }).eq("id", finding.id);
      }

      return { tested: true, confirmed: true };
    }
  }

  // Store negative experience
  await db.from("experience_vault").insert({
    vuln_class: vulnClass,
    payload_used: payloads[0] || "",
    outcome: "false_positive",
    confidence_score: 20,
    reward_score: -3,
    target_id: targetId,
    tech_stack: { source: "intel-auto-test" },
    metadata: { intelFeedId: feedId, tested: true, confirmed: false },
  });

  return { tested: true, confirmed: false };
}

// ─── Main Handler ───────────────────────────────────────

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  try {
    const body = await req.json();
    const action = body.action || "full-sync";
    const db = supabaseAdmin();

    // ── Interpret single report ──
    if (action === "interpret-report") {
      const interpretation = await aiInterpretReport(body.report);
      return new Response(JSON.stringify({ interpretation }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // ── Trigger rescan ──
    if (action === "trigger-rescan") {
      const { targetId, vulnClass, intelFeedId } = body;
      if (!targetId) {
        return new Response(JSON.stringify({ error: "targetId required" }), {
          status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      const { data: eps } = await db.from("discovered_endpoints").select("id").eq("target_id", targetId).limit(1);
      if (!eps || eps.length === 0) {
        return new Response(JSON.stringify({ error: "No endpoints — run recon first", triggered: false }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      await db.from("agent_tasks").insert({
        target_id: targetId, task_type: "intel-delta-scan", status: "pending",
        thought_log: [{ type: "info", message: `Intel-driven delta scan for ${vulnClass || "all"}`, intelFeedId, timestamp: new Date().toISOString() }],
      });

      await db.from("scan_logs").insert({
        target_id: targetId, log_type: "info",
        message: `🔄 Intel-driven rescan triggered for ${vulnClass || "all"} (from feed ${intelFeedId || "manual"})`,
        metadata: { intelFeedId, vulnClass },
      });

      const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
      const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
      fetch(`${supabaseUrl}/functions/v1/vuln-scanner`, {
        method: "POST",
        headers: { Authorization: `Bearer ${serviceKey}`, "Content-Type": "application/json" },
        body: JSON.stringify({ targetId }),
      }).catch(e => console.error("Rescan trigger error:", e));

      return new Response(JSON.stringify({ triggered: true, message: `Rescan triggered for target ${targetId}` }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // ── Full Sync Pipeline ──
    const { data: syncRun } = await db.from("intel_sync_runs").insert({ status: "running" }).select().single();
    const syncRunId = syncRun?.id;

    // Step 1: Fetch from all sources
    const [ghReports, edbReports] = await Promise.all([
      fetchGitHubAdvisories(100),
      fetchExploitDB(100),
    ]);
    const allReports = [...ghReports, ...edbReports];
    const reportsFetched = allReports.length;

    // Step 2: Deduplicate
    const { data: existingFeeds } = await db.from("intel_feeds").select("report_id");
    const existingIds = new Set((existingFeeds || []).map((f: any) => f.report_id));
    const newReports = allReports.filter((r) => !existingIds.has(r.report_id));

    let reportsProcessed = 0;
    let templatesGenerated = 0;
    let rescansTriggered = 0;
    let autoTestsRun = 0;
    let autoTestsConfirmed = 0;

    // Step 3: Process new reports
    for (const report of newReports) {
      try {
        const intel = await aiInterpretReport(report);
        const template = generateTemplate(intel.vulnerabilityClass, intel.specificPayloads || [], intel.bypassTechniques || []);
        const script = templateToScript(template);

        const { data: feed } = await db.from("intel_feeds").insert({
          source: report.source, source_url: report.source_url, report_id: report.report_id,
          title: report.title, vulnerability_class: intel.vulnerabilityClass,
          severity: report.severity,
          affected_tech_stack: intel.affectedTechStack || report.affected_tech_stack || [],
          extracted_payloads: intel.specificPayloads || [],
          bypass_techniques: intel.bypassTechniques || [],
          waf_bypass_logic: intel.wafBypassLogic,
          raw_summary: report.raw_summary,
          ai_interpretation: JSON.stringify(intel),
          test_template: template, template_script: script,
          template_language: "python",
          signal_strength: intel.signalStrength || "medium",
          status: "processed", processed_at: new Date().toISOString(),
        }).select().single();

        reportsProcessed++;
        templatesGenerated++;

        // Step 4: Cross-reference with targets & AUTO-TEST
        if (feed && intel.signalStrength !== "low") {
          const techStack = intel.affectedTechStack || [];
          const matches = await findMatchingTargets(db, techStack);

          if (matches.length > 0) {
            await db.from("intel_feeds").update({
              matched_targets: matches.map((m: any) => ({ id: m.id, name: m.name, domain: m.domain })),
              rescan_triggered: true,
            }).eq("id", feed.id);

            for (const match of matches.slice(0, 5)) {
              // Auto-test template on matching target
              if (match.domain && intel.signalStrength === "high") {
                const testResult = await autoTestTemplateOnTarget(
                  db, feed.id, match.id, match.domain, template, intel.vulnerabilityClass
                );
                autoTestsRun++;
                if (testResult.confirmed) autoTestsConfirmed++;

                await db.from("intel_notifications").insert({
                  intel_feed_id: feed.id, target_id: match.id,
                  notification_type: testResult.confirmed ? "auto_test_confirmed" : "auto_test_negative",
                  title: testResult.confirmed
                    ? `🔴 AUTO-CONFIRMED: ${intel.vulnerabilityClass.toUpperCase()} on ${match.name}`
                    : `🟡 Auto-tested ${intel.vulnerabilityClass} on ${match.name} — not confirmed`,
                  message: testResult.confirmed
                    ? `"${report.title}" was automatically tested and CONFIRMED on ${match.name}. Finding created in approvals.`
                    : `"${report.title}" was tested on ${match.name} but no vulnerability confirmed.`,
                  action_url: report.source_url,
                });
              } else {
                await db.from("intel_notifications").insert({
                  intel_feed_id: feed.id, target_id: match.id,
                  notification_type: "match_found",
                  title: `🔴 New ${intel.vulnerabilityClass} disclosure matches ${match.name}`,
                  message: `"${report.title}" may affect ${match.name} (matched: ${match.matchedTech.join(", ")}). Click "Rescan" to test.`,
                  action_url: report.source_url,
                });
              }
              rescansTriggered++;
            }
          }
        }

        // Store payloads in experience vault
        if (intel.specificPayloads?.length > 0) {
          for (const payload of intel.specificPayloads.slice(0, 5)) {
            await db.from("experience_vault").insert({
              vuln_class: intel.vulnerabilityClass, payload_used: payload,
              outcome: "intel_imported", confidence_score: 60, reward_score: 5,
              tech_stack: { source: report.source, imported: true },
              metadata: { intelFeedId: feed?.id, source: report.source },
            });
          }
        }

        await new Promise((r) => setTimeout(r, 150));
      } catch (e) {
        console.error("Error processing report:", report.report_id, e);
      }
    }

    if (syncRunId) {
      await db.from("intel_sync_runs").update({
        completed_at: new Date().toISOString(),
        reports_fetched: reportsFetched, reports_processed: reportsProcessed,
        templates_generated: templatesGenerated, rescans_triggered: rescansTriggered,
        status: "completed",
      }).eq("id", syncRunId);
    }

    return new Response(
      JSON.stringify({
        success: true, syncRunId, reportsFetched, newReports: newReports.length,
        reportsProcessed, templatesGenerated, rescansTriggered,
        autoTestsRun, autoTestsConfirmed,
      }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (e) {
    console.error("Intel sync error:", e);
    return new Response(
      JSON.stringify({ error: e instanceof Error ? e.message : "Unknown error" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
