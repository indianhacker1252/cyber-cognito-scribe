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

async function log(
  db: ReturnType<typeof createClient>,
  targetId: string,
  taskId: string,
  type: "thought" | "action" | "result" | "error" | "info",
  message: string,
  metadata: Record<string, unknown> = {}
) {
  await db.from("scan_logs").insert({
    target_id: targetId,
    task_id: taskId,
    log_type: type,
    message,
    metadata,
  });
}

// ─── SAFE PAYLOADS ONLY ──────────────────────────────────
// Blocklist: never send destructive payloads
const FORBIDDEN_PATTERNS = [
  /drop\s+table/i, /truncate/i, /delete\s+from/i, /rm\s+-rf/i,
  /shutdown/i, /<script[^>]*>.*<\/script>/i, /exec\s*\(/i,
  /xp_cmdshell/i, /eval\s*\(/i,
];

function isSafePayload(payload: string): boolean {
  return !FORBIDDEN_PATTERNS.some((p) => p.test(payload));
}

// ─── 1. HEURISTIC ROUTER ────────────────────────────────
// Maps parameter names to vulnerability classes

interface VulnCheck {
  paramName: string;
  paramValue: string;
  vulnClasses: string[];
  url: string;
  endpointId: string;
}

function classifyParameters(
  endpoints: Array<{ id: string; url: string; parameters: Record<string, string> }>
): VulnCheck[] {
  const checks: VulnCheck[] = [];

  const paramClassMap: Record<string, string[]> = {
    // SSRF / Open Redirect
    url: ["ssrf", "open-redirect"],
    redirect: ["open-redirect"],
    redirect_url: ["open-redirect"],
    redirect_uri: ["open-redirect"],
    return_url: ["open-redirect"],
    next: ["open-redirect"],
    callback: ["ssrf", "open-redirect"],
    dest: ["open-redirect"],
    target: ["ssrf"],
    uri: ["ssrf"],
    link: ["ssrf", "open-redirect"],
    // SQLi / IDOR
    id: ["sqli", "idor"],
    user_id: ["idor"],
    item_id: ["sqli", "idor"],
    order_id: ["sqli", "idor"],
    product_id: ["sqli", "idor"],
    category: ["sqli"],
    sort: ["sqli"],
    order: ["sqli"],
    // XSS
    q: ["rxss"],
    search: ["rxss"],
    query: ["rxss"],
    keyword: ["rxss"],
    name: ["rxss"],
    message: ["rxss"],
    comment: ["rxss"],
    // Path traversal
    file: ["path-traversal"],
    path: ["path-traversal"],
    page: ["path-traversal", "lfi"],
    template: ["ssti", "lfi"],
    include: ["lfi"],
    // SSTI
    lang: ["ssti"],
    view: ["ssti"],
  };

  for (const ep of endpoints) {
    const params = ep.parameters || {};
    for (const [paramName, paramValue] of Object.entries(params)) {
      const key = paramName.toLowerCase();
      const vulnClasses = paramClassMap[key] || [];
      if (vulnClasses.length > 0) {
        checks.push({
          paramName,
          paramValue: String(paramValue),
          vulnClasses,
          url: ep.url,
          endpointId: ep.id,
        });
      }
    }
  }

  return checks;
}

// ─── 2. BASELINE DIFFERENTIAL VALIDATOR ──────────────────

interface DiffResult {
  isVulnerable: boolean;
  vulnClass: string;
  confidence: "high" | "medium" | "low";
  baseline: { status: number; length: number };
  mutated: { status: number; length: number };
  truePayload: string;
  falsePayload: string;
}

async function runDifferentialTest(
  baseUrl: string,
  paramName: string,
  paramValue: string,
  vulnClass: string
): Promise<DiffResult | null> {
  // Define safe boolean test pairs per vuln class
  const testPairs: Record<string, { truthy: string; falsy: string }> = {
    sqli: {
      truthy: `${paramValue} AND 1=1`,
      falsy: `${paramValue} AND 1=0`,
    },
    rxss: {
      truthy: `${paramValue}<cyberscope>`,
      falsy: `${paramValue}`,
    },
    "open-redirect": {
      truthy: "https://safe-test.cyberscope.local",
      falsy: paramValue,
    },
    ssrf: {
      truthy: "http://127.0.0.1:1",
      falsy: paramValue,
    },
    idor: {
      truthy: "999999",
      falsy: paramValue,
    },
    "path-traversal": {
      truthy: "....//....//etc/hostname",
      falsy: paramValue,
    },
    ssti: {
      truthy: "{{7*7}}",
      falsy: "{{invalid}}",
    },
    lfi: {
      truthy: "....//....//etc/hostname",
      falsy: paramValue,
    },
  };

  const pair = testPairs[vulnClass];
  if (!pair) return null;

  // Safety check
  if (!isSafePayload(pair.truthy) || !isSafePayload(pair.falsy)) return null;

  try {
    const url = new URL(baseUrl);

    // Baseline (truthy)
    url.searchParams.set(paramName, pair.truthy);
    const trueResp = await fetch(url.toString(), {
      method: "GET",
      headers: { "User-Agent": "CyberScope-Scanner/1.0" },
      redirect: "manual",
    });
    const trueBody = await trueResp.text();

    // Small delay to avoid rate limiting
    await new Promise((r) => setTimeout(r, 300));

    // Mutated (falsy)
    url.searchParams.set(paramName, pair.falsy);
    const falseResp = await fetch(url.toString(), {
      method: "GET",
      headers: { "User-Agent": "CyberScope-Scanner/1.0" },
      redirect: "manual",
    });
    const falseBody = await falseResp.text();

    const result: DiffResult = {
      isVulnerable: false,
      vulnClass,
      confidence: "low",
      baseline: { status: trueResp.status, length: trueBody.length },
      mutated: { status: falseResp.status, length: falseBody.length },
      truePayload: pair.truthy,
      falsePayload: pair.falsy,
    };

    // Differential analysis
    if (vulnClass === "sqli") {
      const lengthDiff = Math.abs(trueBody.length - falseBody.length);
      const statusDiff = trueResp.status !== falseResp.status;
      if (lengthDiff > 50 || statusDiff) {
        result.isVulnerable = true;
        result.confidence = lengthDiff > 200 || statusDiff ? "high" : "medium";
      }
    } else if (vulnClass === "rxss") {
      if (trueBody.includes("<cyberscope>")) {
        result.isVulnerable = true;
        result.confidence = "high";
      }
    } else if (vulnClass === "open-redirect") {
      const location = trueResp.headers.get("location") || "";
      if (
        trueResp.status >= 300 &&
        trueResp.status < 400 &&
        location.includes("safe-test.cyberscope.local")
      ) {
        result.isVulnerable = true;
        result.confidence = "high";
      }
    } else if (vulnClass === "ssrf") {
      // Different status or significant body difference suggests processing
      if (trueResp.status !== falseResp.status) {
        result.isVulnerable = true;
        result.confidence = "medium";
      }
    } else if (vulnClass === "idor") {
      if (trueResp.status === 200 && falseResp.status === 200) {
        const lengthDiff = Math.abs(trueBody.length - falseBody.length);
        if (lengthDiff > 100) {
          result.isVulnerable = true;
          result.confidence = "medium";
        }
      }
    } else if (vulnClass === "ssti") {
      if (trueBody.includes("49")) {
        result.isVulnerable = true;
        result.confidence = "high";
      }
    } else if (vulnClass === "path-traversal" || vulnClass === "lfi") {
      if (
        trueBody.includes("root:") ||
        trueBody.includes("/bin/") ||
        trueBody.length !== falseBody.length
      ) {
        result.isVulnerable = true;
        result.confidence = trueBody.includes("root:") ? "high" : "medium";
      }
    }

    return result;
  } catch (e) {
    console.error(`Differential test error for ${vulnClass}:`, e);
    return null;
  }
}

// ─── 3. CVE VERSION CORRELATION ──────────────────────────

interface CveResult {
  cveId: string;
  description: string;
  severity: string;
  cvssScore: number;
}

async function queryCveDatabase(
  techStack: Record<string, string | undefined>
): Promise<CveResult[]> {
  const results: CveResult[] = [];

  // Build search queries from tech fingerprint
  const searchTerms: string[] = [];
  if (techStack.server) searchTerms.push(techStack.server);
  if (techStack.poweredBy) searchTerms.push(techStack.poweredBy);
  if (techStack.framework) searchTerms.push(techStack.framework);

  for (const term of searchTerms) {
    try {
      // Query NVD API (free, no key needed for basic queries)
      const resp = await fetch(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(
          term
        )}&resultsPerPage=10`,
        { headers: { "User-Agent": "CyberScope-Scanner/1.0" } }
      );

      if (resp.ok) {
        const data = await resp.json();
        for (const vuln of data.vulnerabilities || []) {
          const cve = vuln.cve;
          const metrics =
            cve.metrics?.cvssMetricV31?.[0]?.cvssData ||
            cve.metrics?.cvssMetricV30?.[0]?.cvssData;
          results.push({
            cveId: cve.id,
            description:
              cve.descriptions?.find(
                (d: { lang: string }) => d.lang === "en"
              )?.value || "No description",
            severity: metrics?.baseSeverity || "UNKNOWN",
            cvssScore: metrics?.baseScore || 0,
          });
        }
      }

      // Rate limit: NVD allows ~5 requests per 30 seconds without API key
      await new Promise((r) => setTimeout(r, 6500));
    } catch (e) {
      console.error(`NVD query error for "${term}":`, e);
    }
  }

  return results;
}

// ─── 4. AI-POWERED VULNERABILITY ANALYSIS ────────────────

async function aiAnalyzeFindings(
  domain: string,
  diffResults: DiffResult[],
  cveResults: CveResult[],
  techStack: Record<string, string | undefined>
): Promise<{
  assessments: Array<{
    title: string;
    severity: string;
    description: string;
    remediation: string;
  }>;
}> {
  const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");
  if (!LOVABLE_API_KEY) return { assessments: [] };

  const vulnFindings = diffResults.filter((r) => r.isVulnerable);
  if (vulnFindings.length === 0 && cveResults.length === 0) return { assessments: [] };

  const prompt = `You are a senior penetration tester reviewing findings for ${domain}.

Tech Stack: ${JSON.stringify(techStack)}

Differential Test Results (${vulnFindings.length} potential vulns):
${vulnFindings
  .map(
    (r) =>
      `- ${r.vulnClass}: baseline(status=${r.baseline.status}, len=${r.baseline.length}) vs mutated(status=${r.mutated.status}, len=${r.mutated.length}), confidence=${r.confidence}`
  )
  .join("\n")}

CVE Matches (${cveResults.length}):
${cveResults
  .slice(0, 10)
  .map((c) => `- ${c.cveId}: ${c.severity} (${c.cvssScore}) - ${c.description.slice(0, 100)}`)
  .join("\n")}

For each real finding, provide a professional assessment with title, severity (critical/high/medium/low), description, and remediation advice.`;

  try {
    const resp = await fetch(
      "https://ai.gateway.lovable.dev/v1/chat/completions",
      {
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
              content:
                "You are a VAPT analyst. Return structured assessments via the tool.",
            },
            { role: "user", content: prompt },
          ],
          tools: [
            {
              type: "function",
              function: {
                name: "report_assessments",
                description: "Report vulnerability assessments",
                parameters: {
                  type: "object",
                  properties: {
                    assessments: {
                      type: "array",
                      items: {
                        type: "object",
                        properties: {
                          title: { type: "string" },
                          severity: {
                            type: "string",
                            enum: ["critical", "high", "medium", "low"],
                          },
                          description: { type: "string" },
                          remediation: { type: "string" },
                        },
                        required: [
                          "title",
                          "severity",
                          "description",
                          "remediation",
                        ],
                        additionalProperties: false,
                      },
                    },
                  },
                  required: ["assessments"],
                  additionalProperties: false,
                },
              },
            },
          ],
          tool_choice: {
            type: "function",
            function: { name: "report_assessments" },
          },
        }),
      }
    );

    if (resp.ok) {
      const data = await resp.json();
      const toolCall = data.choices?.[0]?.message?.tool_calls?.[0];
      if (toolCall) {
        return JSON.parse(toolCall.function.arguments);
      }
    }
  } catch (e) {
    console.error("AI analysis error:", e);
  }

  return { assessments: [] };
}

// ─── 5. MAIN VULN SCAN PIPELINE ─────────────────────────

serve(async (req) => {
  if (req.method === "OPTIONS")
    return new Response(null, { headers: corsHeaders });

  try {
    const { targetId } = await req.json();
    if (!targetId) {
      return new Response(
        JSON.stringify({ error: "targetId is required" }),
        {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    const db = supabaseAdmin();

    // Fetch target
    const { data: target } = await db
      .from("target_workspaces")
      .select("*")
      .eq("id", targetId)
      .single();

    if (!target) {
      return new Response(
        JSON.stringify({ error: "Target not found" }),
        {
          status: 404,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    // Create agent task
    const { data: task } = await db
      .from("agent_tasks")
      .insert({
        target_id: targetId,
        task_type: "vulnerability-scan",
        status: "running",
      })
      .select()
      .single();

    const taskId = task!.id;

    await db
      .from("target_workspaces")
      .update({ status: "scanning" })
      .eq("id", targetId);

    await log(db, targetId, taskId, "info", "Vulnerability scan pipeline started");

    // ── Fetch discovered endpoints ──
    const { data: endpoints } = await db
      .from("discovered_endpoints")
      .select("*")
      .eq("target_id", targetId);

    if (!endpoints || endpoints.length === 0) {
      await log(db, targetId, taskId, "error", "No endpoints found — run recon first");
      await db.from("agent_tasks").update({ status: "failed", result: { error: "No endpoints" } }).eq("id", taskId);
      return new Response(
        JSON.stringify({ error: "No endpoints discovered. Run recon first." }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    await log(db, targetId, taskId, "action", `Loaded ${endpoints.length} endpoints for analysis`);

    // ── Step 1: Heuristic Parameter Classification ──
    await log(db, targetId, taskId, "thought", "Classifying parameters by vulnerability type (HeuristicRouter)");
    const vulnChecks = classifyParameters(
      endpoints.map((ep) => ({
        id: ep.id,
        url: ep.url,
        parameters: (ep.parameters as Record<string, string>) || {},
      }))
    );
    await log(
      db, targetId, taskId, "result",
      `HeuristicRouter classified ${vulnChecks.length} parameter-vuln pairs across ${new Set(vulnChecks.map((c) => c.endpointId)).size} endpoints`
    );

    // ── Step 2: Differential Analysis (BaselineValidator) ──
    await log(db, targetId, taskId, "thought", "Running safe differential analysis (BaselineValidator)");
    const diffResults: DiffResult[] = [];
    const maxTests = Math.min(vulnChecks.length, 20); // Rate limiting: max 20 tests

    for (let i = 0; i < maxTests; i++) {
      const check = vulnChecks[i];
      for (const vulnClass of check.vulnClasses) {
        await log(db, targetId, taskId, "action", `Testing ${check.paramName} for ${vulnClass} at ${check.url}`);
        const result = await runDifferentialTest(
          check.url,
          check.paramName,
          check.paramValue,
          vulnClass
        );
        if (result) {
          diffResults.push(result);
          if (result.isVulnerable) {
            await log(
              db, targetId, taskId, "result",
              `⚠️ POTENTIAL ${vulnClass.toUpperCase()}: ${check.paramName} at ${check.url} (confidence: ${result.confidence})`
            );
          }
        }
        // Rate limit between tests
        await new Promise((r) => setTimeout(r, 500));
      }
    }

    const vulnFindings = diffResults.filter((r) => r.isVulnerable);
    await log(db, targetId, taskId, "result", `BaselineValidator found ${vulnFindings.length} potential vulnerabilities out of ${diffResults.length} tests`);

    // ── Step 3: CVE Correlation ──
    await log(db, targetId, taskId, "thought", "Querying NVD for CVE correlation (CveMapper)");

    // Get tech fingerprint from the latest recon task
    const { data: reconTask } = await db
      .from("agent_tasks")
      .select("result")
      .eq("target_id", targetId)
      .eq("task_type", "reconnaissance")
      .eq("status", "completed")
      .order("created_at", { ascending: false })
      .limit(1)
      .single();

    const techStack = (reconTask?.result as any)?.tech_fingerprint || {};
    const cveResults = await queryCveDatabase(techStack);
    await log(db, targetId, taskId, "result", `CveMapper found ${cveResults.length} potentially relevant CVEs`);

    // ── Step 4: AI Assessment ──
    await log(db, targetId, taskId, "thought", "Running AI vulnerability assessment");
    const aiAssessments = await aiAnalyzeFindings(
      target.domain || "unknown",
      diffResults,
      cveResults,
      techStack
    );
    await log(db, targetId, taskId, "result", `AI produced ${aiAssessments.assessments.length} assessments`);

    // ── Step 5: HITL Approval Gate ──
    await log(db, targetId, taskId, "thought", "Routing findings to HITL approval queue (ApprovalGate)");

    let approvalCount = 0;

    // Push differential findings to approval queue
    for (const diff of vulnFindings) {
      const matchingCheck = vulnChecks.find(
        (c) => c.vulnClasses.includes(diff.vulnClass)
      );

      const severityMap: Record<string, string> = {
        high: "high",
        medium: "medium",
        low: "low",
      };

      await db.from("pending_approvals").insert({
        target_id: targetId,
        endpoint_id: matchingCheck?.endpointId || null,
        finding_type: `differential-${diff.vulnClass}`,
        severity: severityMap[diff.confidence] || "medium",
        title: `Potential ${diff.vulnClass.toUpperCase()} via differential analysis`,
        description: `Parameter "${matchingCheck?.paramName}" showed differential response behavior indicating possible ${diff.vulnClass}`,
        parameter: matchingCheck?.paramName,
        payload_used: diff.truePayload,
        baseline_response: diff.baseline,
        mutated_response: diff.mutated,
        evidence: {
          vulnClass: diff.vulnClass,
          confidence: diff.confidence,
          url: matchingCheck?.url,
        },
      });
      approvalCount++;
    }

    // Push CVE findings to approval queue
    for (const cve of cveResults.slice(0, 10)) {
      const severityMap: Record<string, string> = {
        CRITICAL: "critical",
        HIGH: "high",
        MEDIUM: "medium",
        LOW: "low",
      };

      await db.from("pending_approvals").insert({
        target_id: targetId,
        finding_type: "cve-correlation",
        severity: severityMap[cve.severity] || "medium",
        title: `${cve.cveId} — ${cve.description.slice(0, 80)}`,
        description: cve.description,
        cve_ids: [cve.cveId],
        cvss_score: cve.cvssScore,
        evidence: {
          techStack,
          cveId: cve.cveId,
          severity: cve.severity,
          requiresHumanVerification: true,
        },
      });
      approvalCount++;
    }

    // Push AI assessments to approval queue
    for (const assessment of aiAssessments.assessments) {
      await db.from("pending_approvals").insert({
        target_id: targetId,
        finding_type: "ai-assessment",
        severity: assessment.severity,
        title: assessment.title,
        description: `${assessment.description}\n\n**Remediation:** ${assessment.remediation}`,
        evidence: {
          source: "ai-analysis",
          remediation: assessment.remediation,
        },
      });
      approvalCount++;
    }

    await log(
      db, targetId, taskId, "info",
      `✅ Vulnerability scan complete — ${approvalCount} findings pushed to HITL approval queue`
    );

    // Update task
    await db.from("agent_tasks").update({
      status: "completed",
      result: {
        parameters_classified: vulnChecks.length,
        differential_tests: diffResults.length,
        vulns_found: vulnFindings.length,
        cves_matched: cveResults.length,
        ai_assessments: aiAssessments.assessments.length,
        approvals_queued: approvalCount,
      },
    }).eq("id", taskId);

    await db.from("target_workspaces").update({ status: "completed" }).eq("id", targetId);

    return new Response(
      JSON.stringify({
        success: true,
        parametersClassified: vulnChecks.length,
        differentialTests: diffResults.length,
        vulnsFound: vulnFindings.length,
        cvesMatched: cveResults.length,
        approvalsQueued: approvalCount,
      }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (e) {
    console.error("Vuln scanner error:", e);
    return new Response(
      JSON.stringify({
        error: e instanceof Error ? e.message : "Unknown error",
      }),
      {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      }
    );
  }
});
