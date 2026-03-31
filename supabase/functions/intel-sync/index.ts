import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

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

// ─── Source Fetchers ────────────────────────────────────

async function fetchGitHubAdvisories(limit = 15) {
  const reports: any[] = [];
  try {
    const resp = await fetch(
      `https://api.github.com/advisories?type=reviewed&per_page=${limit}`,
      {
        headers: {
          Accept: "application/vnd.github+json",
          "User-Agent": "CyberScope-Scanner/1.0",
          "X-GitHub-Api-Version": "2022-11-28",
        },
      }
    );
    if (resp.ok) {
      const advisories = await resp.json();
      for (const adv of advisories) {
        const techStack = (adv.vulnerabilities || [])
          .map((v: any) => v.package?.name)
          .filter(Boolean);
        reports.push({
          source: "github-advisory",
          report_id: adv.ghsa_id || adv.cve_id || `gh-${Date.now()}`,
          title: adv.summary || "Untitled",
          raw_summary: (adv.description || "").slice(0, 1000),
          severity: adv.severity || "medium",
          source_url: adv.html_url || "",
          affected_tech_stack: techStack,
          vulnerability_class: adv.cwe_ids?.[0] || null,
        });
      }
    }
  } catch (e) {
    console.error("GitHub Advisory error:", e);
  }
  return reports;
}

async function fetchExploitDB(limit = 10) {
  const reports: any[] = [];
  try {
    const resp = await fetch("https://www.exploit-db.com/rss.xml", {
      headers: { "User-Agent": "CyberScope-Scanner/1.0" },
    });
    if (resp.ok) {
      const xml = await resp.text();
      const items = xml.match(/<item>[\s\S]*?<\/item>/g) || [];
      for (const item of items.slice(0, limit)) {
        const title = item.match(/<title>(.*?)<\/title>/)?.[1] || "Untitled";
        const link = item.match(/<link>(.*?)<\/link>/)?.[1] || "";
        const desc = item.match(/<description>(.*?)<\/description>/)?.[1] || "";
        reports.push({
          source: "exploit-db",
          report_id: `edb-${link.split("/").pop() || Date.now()}`,
          title: decodeXml(title),
          raw_summary: decodeXml(desc).slice(0, 1000),
          severity: "high",
          source_url: link,
          affected_tech_stack: [],
        });
      }
    }
  } catch (e) {
    console.error("ExploitDB error:", e);
  }
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
      headers: {
        Authorization: `Bearer ${LOVABLE_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "google/gemini-3-flash-preview",
        messages: [
          {
            role: "system",
            content: "You are a security intelligence analyst. Extract structured vulnerability data from disclosed security reports. Return via the tool.",
          },
          {
            role: "user",
            content: `Analyze this disclosed security report:\n\nTitle: ${report.title}\nSummary: ${report.raw_summary}\nSeverity: ${report.severity}\n\nExtract: vulnerability class, specific payloads, affected tech stack, WAF bypass logic, bypass techniques, signal strength (high/medium/low), and OWASP category.`,
          },
        ],
        tools: [
          {
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
          },
        ],
        tool_choice: { type: "function", function: { name: "report_intelligence" } },
      }),
    });

    if (resp.ok) {
      const data = await resp.json();
      const toolCall = data.choices?.[0]?.message?.tool_calls?.[0];
      if (toolCall) return JSON.parse(toolCall.function.arguments);
    }
  } catch (e) {
    console.error("AI interpret error:", e);
  }

  return heuristicInterpret(report);
}

function heuristicInterpret(report: any) {
  const text = `${report.title} ${report.raw_summary}`.toLowerCase();
  const vulnMap: Record<string, string[]> = {
    sqli: ["sql injection", "sqli", "blind sql"], rxss: ["xss", "cross-site scripting"],
    ssrf: ["ssrf", "server-side request"], cmdi: ["command injection", "rce", "remote code"],
    ssti: ["ssti", "template injection"], idor: ["idor", "insecure direct object"],
    "path-traversal": ["path traversal", "directory traversal", "lfi"],
  };
  let vulnClass = "unknown";
  for (const [cls, kw] of Object.entries(vulnMap)) {
    if (kw.some((k) => text.includes(k))) { vulnClass = cls; break; }
  }
  const techKw = ["nginx", "apache", "node.js", "django", "flask", "spring", "laravel", "wordpress", "php", "python", "java", "jenkins"];
  const stack = techKw.filter((t) => text.includes(t));
  const bypassKw = ["bypass", "waf bypass", "filter bypass", "encoding bypass", "double encoding"];
  const bypasses = bypassKw.filter((b) => text.includes(b));
  return {
    vulnerabilityClass: vulnClass,
    specificPayloads: [],
    affectedTechStack: stack,
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
    ssti: ["{{7*7}}", "${7*7}"],
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

// ─── Main Handler ───────────────────────────────────────

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  try {
    const body = await req.json();
    const action = body.action || "full-sync";
    const db = supabaseAdmin();

    // ── Interpret single report (called from frontend) ──
    if (action === "interpret-report") {
      const interpretation = await aiInterpretReport(body.report);
      return new Response(JSON.stringify({ interpretation }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // ── Full Sync Pipeline ──
    const { data: syncRun } = await db.from("intel_sync_runs").insert({
      status: "running",
    }).select().single();

    const syncRunId = syncRun?.id;

    // Step 1: Fetch from all sources
    const [ghReports, edbReports] = await Promise.all([
      fetchGitHubAdvisories(15),
      fetchExploitDB(10),
    ]);
    const allReports = [...ghReports, ...edbReports];
    const reportsFetched = allReports.length;

    // Step 2: Deduplicate against existing feeds
    const { data: existingFeeds } = await db.from("intel_feeds").select("report_id");
    const existingIds = new Set((existingFeeds || []).map((f: any) => f.report_id));
    const newReports = allReports.filter((r) => !existingIds.has(r.report_id));

    let reportsProcessed = 0;
    let templatesGenerated = 0;
    let rescansTriggered = 0;

    // Step 3: Process each new report
    for (const report of newReports.slice(0, 20)) {
      try {
        // AI interpretation
        const intel = await aiInterpretReport(report);

        // Generate template
        const template = generateTemplate(
          intel.vulnerabilityClass,
          intel.specificPayloads || [],
          intel.bypassTechniques || []
        );
        const script = templateToScript(template);

        // Store in intel_feeds
        const { data: feed } = await db.from("intel_feeds").insert({
          source: report.source,
          source_url: report.source_url,
          report_id: report.report_id,
          title: report.title,
          vulnerability_class: intel.vulnerabilityClass,
          severity: report.severity,
          affected_tech_stack: intel.affectedTechStack || report.affected_tech_stack || [],
          extracted_payloads: intel.specificPayloads || [],
          bypass_techniques: intel.bypassTechniques || [],
          waf_bypass_logic: intel.wafBypassLogic,
          raw_summary: report.raw_summary,
          ai_interpretation: JSON.stringify(intel),
          test_template: template,
          template_script: script,
          signal_strength: intel.signalStrength || "medium",
          status: "processed",
          processed_at: new Date().toISOString(),
        }).select().single();

        reportsProcessed++;
        templatesGenerated++;

        // Step 4: Cross-reference with targets
        if (feed && intel.signalStrength !== "low") {
          const techStack = intel.affectedTechStack || [];
          const matches = await findMatchingTargets(db, techStack);

          if (matches.length > 0) {
            // Update feed with matched targets
            await db.from("intel_feeds").update({
              matched_targets: matches.map((m: any) => ({ id: m.id, name: m.name })),
              rescan_triggered: true,
            }).eq("id", feed.id);

            // Create notifications
            for (const match of matches.slice(0, 3)) {
              await db.from("intel_notifications").insert({
                intel_feed_id: feed.id,
                target_id: match.id,
                notification_type: "match_found",
                title: `🔴 New ${intel.vulnerabilityClass} disclosure matches ${match.name}`,
                message: `"${report.title}" may affect ${match.name} (matched: ${match.matchedTech.join(", ")}). Re-verification initiated.`,
                action_url: report.source_url,
              });
              rescansTriggered++;
            }
          }
        }

        // Store in experience vault (Phase 8 integration)
        if (intel.specificPayloads?.length > 0) {
          for (const payload of intel.specificPayloads.slice(0, 3)) {
            await db.from("experience_vault").insert({
              vuln_class: intel.vulnerabilityClass,
              payload_used: payload,
              outcome: "intel_imported",
              confidence_score: 60,
              reward_score: 5,
              tech_stack: { source: report.source, imported: true },
              metadata: { intelFeedId: feed?.id, source: report.source },
            });
          }
        }

        await new Promise((r) => setTimeout(r, 200));
      } catch (e) {
        console.error("Error processing report:", report.report_id, e);
      }
    }

    // Update sync run
    if (syncRunId) {
      await db.from("intel_sync_runs").update({
        completed_at: new Date().toISOString(),
        reports_fetched: reportsFetched,
        reports_processed: reportsProcessed,
        templates_generated: templatesGenerated,
        rescans_triggered: rescansTriggered,
        status: "completed",
      }).eq("id", syncRunId);
    }

    return new Response(
      JSON.stringify({
        success: true,
        syncRunId,
        reportsFetched,
        newReports: newReports.length,
        reportsProcessed,
        templatesGenerated,
        rescansTriggered,
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
