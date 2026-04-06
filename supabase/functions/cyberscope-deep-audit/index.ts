import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

async function safeFetch(url: string, opts: RequestInit = {}, timeoutMs = 8000): Promise<Response> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try { return await fetch(url, { ...opts, signal: ctrl.signal }); }
  finally { clearTimeout(timer); }
}

// ─── Triple-Verification FP Elimination ─────────────────
// Each finding goes through 3 independent checks:
// 1. Differential Twin-Test (send payload vs clean, compare)
// 2. Timing Analysis (measure response time delta)
// 3. Repeat Consistency (send same payload 3x, check if response is consistent)

interface TripleVerification {
  differentialPass: boolean;
  timingPass: boolean;
  consistencyPass: boolean;
  overallVerdict: "verified_critical" | "likely_vuln" | "needs_review" | "false_positive";
  confidence: number;
  details: string;
}

async function tripleVerify(
  targetUrl: string,
  paramName: string,
  payload: string,
  cleanValue: string,
  vulnClass: string
): Promise<TripleVerification> {
  const result: TripleVerification = {
    differentialPass: false, timingPass: false, consistencyPass: false,
    overallVerdict: "false_positive", confidence: 0, details: "",
  };

  const headers = { "User-Agent": "CyberScope-TripleVerify/1.0" };

  try {
    // 1. Differential Twin-Test
    const cleanUrl = new URL(targetUrl);
    cleanUrl.searchParams.set(paramName, cleanValue);
    const payloadUrl = new URL(targetUrl);
    payloadUrl.searchParams.set(paramName, payload);

    const [cleanResp, payloadResp] = await Promise.all([
      safeFetch(cleanUrl.toString(), { headers, redirect: "manual" }, 6000).then(async r => ({ status: r.status, body: await r.text(), len: 0 })),
      safeFetch(payloadUrl.toString(), { headers, redirect: "manual" }, 6000).then(async r => ({ status: r.status, body: await r.text(), len: 0 })),
    ]);
    cleanResp.len = cleanResp.body.length;
    payloadResp.len = payloadResp.body.length;

    const lenDiff = Math.abs(payloadResp.len - cleanResp.len);
    const lenRatio = lenDiff / Math.max(cleanResp.len, 1);
    const statusDiff = payloadResp.status !== cleanResp.status;

    // Check for execution evidence
    const execEvidence =
      (vulnClass === "sqli" && /sql syntax|SQLSTATE|ORA-|pg_query|unclosed quotation/i.test(payloadResp.body) && !/sql syntax|SQLSTATE/i.test(cleanResp.body)) ||
      (vulnClass === "rxss" && (payloadResp.body.includes("<cyberscope>") || payloadResp.body.includes("onerror=cyberscope"))) ||
      (vulnClass === "cmdi" && payloadResp.body.includes("cyberscope_marker")) ||
      (vulnClass === "ssti" && /\b49\b/.test(payloadResp.body) && !/\b49\b/.test(cleanResp.body)) ||
      (vulnClass === "path-traversal" && /root:.*:0:0/.test(payloadResp.body));

    result.differentialPass = execEvidence || lenRatio > 0.15 || statusDiff;

    // 2. Timing Analysis — send payload with timing measurement
    await new Promise(r => setTimeout(r, 100));
    const t1 = Date.now();
    await safeFetch(payloadUrl.toString(), { headers, redirect: "manual" }, 8000);
    const payloadTime = Date.now() - t1;

    const t2 = Date.now();
    await safeFetch(cleanUrl.toString(), { headers, redirect: "manual" }, 8000);
    const cleanTime = Date.now() - t2;

    const timeDelta = payloadTime - cleanTime;
    result.timingPass = timeDelta > 2000; // >2s difference suggests time-based injection

    // 3. Consistency Check — send payload 3x, check responses are similar
    await new Promise(r => setTimeout(r, 100));
    const consistencyLengths: number[] = [];
    for (let i = 0; i < 3; i++) {
      try {
        const r = await safeFetch(payloadUrl.toString(), { headers, redirect: "manual" }, 6000);
        const b = await r.text();
        consistencyLengths.push(b.length);
        await new Promise(r => setTimeout(r, 100));
      } catch { consistencyLengths.push(-1); }
    }

    const validLengths = consistencyLengths.filter(l => l >= 0);
    if (validLengths.length >= 2) {
      const avgLen = validLengths.reduce((a, b) => a + b, 0) / validLengths.length;
      const variance = validLengths.reduce((acc, l) => acc + Math.abs(l - avgLen), 0) / validLengths.length;
      const varianceRatio = variance / Math.max(avgLen, 1);
      result.consistencyPass = varianceRatio < 0.05; // <5% variance = consistent = real behavior
    }

    // Combine scores
    const checks = [result.differentialPass, result.timingPass, result.consistencyPass];
    const passCount = checks.filter(Boolean).length;

    if (execEvidence && result.consistencyPass) {
      result.overallVerdict = "verified_critical";
      result.confidence = 0.95;
    } else if (passCount >= 2) {
      result.overallVerdict = "verified_critical";
      result.confidence = 0.85 + (passCount * 0.05);
    } else if (passCount === 1 && result.differentialPass) {
      result.overallVerdict = "likely_vuln";
      result.confidence = 0.65;
    } else if (passCount === 1) {
      result.overallVerdict = "needs_review";
      result.confidence = 0.40;
    } else {
      result.overallVerdict = "false_positive";
      result.confidence = 0.12;
    }

    result.details = `Diff: ${result.differentialPass ? "PASS" : "FAIL"} (delta=${lenDiff}B, ratio=${(lenRatio*100).toFixed(1)}%), Timing: ${result.timingPass ? "PASS" : "FAIL"} (delta=${timeDelta}ms), Consistency: ${result.consistencyPass ? "PASS" : "FAIL"}${execEvidence ? " [EXEC EVIDENCE]" : ""}`;
  } catch (e) {
    result.details = `Verification error: ${e instanceof Error ? e.message : "Unknown"}`;
  }

  return result;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const { targetUrl } = await req.json();

    if (!targetUrl || typeof targetUrl !== "string") {
      return new Response(
        JSON.stringify({ error: "targetUrl is required" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const headers = { "User-Agent": "CyberScope-DeepAudit/1.0" };

    // ── Step 1: Crawl target for parameters ──
    let baseBody = "";
    let baseStatus = 0;
    let serverHeader = "";
    let poweredBy = "";
    try {
      const resp = await safeFetch(targetUrl, { headers, redirect: "follow" }, 8000);
      baseBody = await resp.text();
      baseStatus = resp.status;
      serverHeader = resp.headers.get("server") || "";
      poweredBy = resp.headers.get("x-powered-by") || "";
    } catch { /* skip */ }

    // Extract form inputs and links from the page
    const inputRegex = /name\s*=\s*["']([^"']+)["']/gi;
    const discoveredParams: string[] = [];
    let match;
    while ((match = inputRegex.exec(baseBody)) !== null) {
      discoveredParams.push(match[1]);
    }

    // Also extract URL query params from links
    const linkRegex = /href\s*=\s*["']([^"']*\?[^"']+)["']/gi;
    while ((match = linkRegex.exec(baseBody)) !== null) {
      try {
        const url = new URL(match[1], targetUrl);
        url.searchParams.forEach((_, k) => { if (!discoveredParams.includes(k)) discoveredParams.push(k); });
      } catch { /* skip */ }
    }

    // Common params to test if none found
    if (discoveredParams.length === 0) {
      discoveredParams.push("id", "search", "q", "page", "cat", "name");
    }

    // ── Step 2: Run OWASP tests with triple-verification ──
    const testPayloads: Array<{ param: string; vulnClass: string; payload: string; clean: string; testSig: string }> = [];

    for (const param of discoveredParams.slice(0, 8)) {
      testPayloads.push(
        { param, vulnClass: "sqli", payload: `1' AND '1'='1`, clean: "1", testSig: "SQL Syntax Check — Boolean Differential" },
        { param, vulnClass: "rxss", payload: `<cyberscope>`, clean: "test", testSig: "DOM Reflection — XSS Probe" },
        { param, vulnClass: "cmdi", payload: `; echo cyberscope_marker`, clean: "test", testSig: "Command Injection — Marker Echo" },
      );
    }

    const owaspFindings: any[] = [];
    const differentialResults: any[] = [];

    for (const test of testPayloads.slice(0, 12)) {
      try {
        const verification = await tripleVerify(targetUrl, test.param, test.payload, test.clean, test.vulnClass);

        // Build control & anomaly response info
        const cleanUrl = new URL(targetUrl);
        cleanUrl.searchParams.set(test.param, test.clean);
        const payloadUrl = new URL(targetUrl);
        payloadUrl.searchParams.set(test.param, test.payload);

        const controlResp = await safeFetch(cleanUrl.toString(), { headers, redirect: "manual" }, 5000);
        const controlBody = await controlResp.text();
        const anomalyResp = await safeFetch(payloadUrl.toString(), { headers, redirect: "manual" }, 5000);
        const anomalyBody = await anomalyResp.text();

        const byteDelta = anomalyBody.length - controlBody.length;
        const bytePct = ((byteDelta / Math.max(controlBody.length, 1)) * 100).toFixed(1);

        owaspFindings.push({
          id: crypto.randomUUID(),
          parameter: `${test.param} (${test.vulnClass.toUpperCase()})`,
          testSignature: test.testSig,
          controlResponse: { status: controlResp.status, bytes: controlBody.length, label: `${controlResp.status} · ${(controlBody.length/1024).toFixed(1)} KB` },
          anomalyResponse: { status: anomalyResp.status, bytes: anomalyBody.length, label: `${anomalyResp.status} · ${(anomalyBody.length/1024).toFixed(1)} KB (${byteDelta > 0 ? "+" : ""}${bytePct}%)` },
          verificationStatus: verification.overallVerdict,
          severity: verification.overallVerdict === "verified_critical" ? "critical" : verification.overallVerdict === "likely_vuln" ? "high" : "info",
          pocCurl: `curl -s '${payloadUrl.toString()}' -H 'User-Agent: CyberScope/1.0'`,
          tripleVerification: verification.details,
        });

        differentialResults.push({
          id: crypto.randomUUID(),
          testCase: `${test.vulnClass.toUpperCase()} on ${test.param}`,
          twinAResponse: `${anomalyResp.status} — ${(anomalyBody.length/1024).toFixed(1)} KB`,
          twinBResponse: `${controlResp.status} — ${(controlBody.length/1024).toFixed(1)} KB`,
          byteDelta: `${byteDelta > 0 ? "+" : ""}${byteDelta} bytes (${bytePct}%)`,
          verdict: verification.overallVerdict === "verified_critical" || verification.overallVerdict === "likely_vuln" ? "confirmed" : verification.overallVerdict === "false_positive" ? "false_positive" : "waf_blocked",
          confidence: verification.confidence,
          tripleCheck: verification.details,
        });

        await new Promise(r => setTimeout(r, 200));
      } catch { /* skip test */ }
    }

    // ── Step 3: CVE correlation from detected headers ──
    const cveFindings: any[] = [];
    const techTerms = [serverHeader, poweredBy].filter(Boolean);

    for (const term of techTerms.slice(0, 2)) {
      try {
        const nvdResp = await safeFetch(
          `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(term)}&resultsPerPage=5`,
          { headers: { "User-Agent": "CyberScope/1.0" } }, 6000
        );
        if (nvdResp.ok) {
          const data = await nvdResp.json();
          for (const vuln of (data.vulnerabilities || []).slice(0, 5)) {
            const cve = vuln.cve;
            const metrics = cve.metrics?.cvssMetricV31?.[0]?.cvssData || cve.metrics?.cvssMetricV30?.[0]?.cvssData;
            cveFindings.push({
              id: crypto.randomUUID(),
              dependency: term,
              cveId: cve.id,
              severity: (metrics?.baseSeverity || "medium").toLowerCase(),
              description: cve.descriptions?.find((d: { lang: string }) => d.lang === "en")?.value || "No description",
              fixVersion: "See NVD",
              status: "vulnerable",
            });
          }
        }
        await new Promise(r => setTimeout(r, 500));
      } catch { /* skip */ }
    }

    const mockResults = {
      target: targetUrl,
      scanId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      owaspFindings,
      cveFindings,
      differentialResults,
      discoveredParams,
      tripleVerificationEnabled: true,
    };

    return new Response(JSON.stringify(mockResults), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
      status: 200,
    });
  } catch (err) {
    return new Response(
      JSON.stringify({ error: err.message }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
