import { corsHeaders } from "@supabase/supabase-js/cors";

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

    // Simulate processing delay
    await new Promise((r) => setTimeout(r, 1500));

    const mockResults = {
      target: targetUrl,
      scanId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      owaspFindings: [
        {
          id: crypto.randomUUID(),
          parameter: "search_query (GET /search)",
          testSignature: "SQL Syntax Check — UNION SELECT",
          controlResponse: { status: 200, bytes: 14832, label: "200 OK · 14.8 KB" },
          anomalyResponse: { status: 200, bytes: 18456, label: "200 OK · 18.5 KB (+24.4%)" },
          verificationStatus: "verified_critical",
          severity: "critical",
          pocCurl: `curl -s '${targetUrl}/search?query=1%27+UNION+SELECT+NULL,username,password+FROM+users--' -H 'User-Agent: CyberScope/1.0'`,
        },
        {
          id: crypto.randomUUID(),
          parameter: "comment_body (POST /feedback)",
          testSignature: "DOM Reflection — XSS via <script>",
          controlResponse: { status: 200, bytes: 9210, label: "200 OK · 9.2 KB" },
          anomalyResponse: { status: 403, bytes: 1024, label: "403 Forbidden · 1.0 KB" },
          verificationStatus: "false_positive",
          severity: "info",
          pocCurl: `curl -s -X POST '${targetUrl}/feedback' -d 'body=<script>alert(1)</script>' -H 'Content-Type: application/x-www-form-urlencoded'`,
        },
        {
          id: crypto.randomUUID(),
          parameter: "— (Response Headers)",
          testSignature: "CVE Header Check — X-Powered-By Leak",
          controlResponse: { status: 200, bytes: 512, label: "200 OK · 0.5 KB" },
          anomalyResponse: { status: 200, bytes: 512, label: "200 OK · Header: PHP/7.4.3" },
          verificationStatus: "verified_critical",
          severity: "high",
          pocCurl: `curl -sI '${targetUrl}/' | grep -i 'x-powered-by'`,
        },
      ],
      cveFindings: [
        {
          id: crypto.randomUUID(),
          dependency: "PHP 7.4.3",
          cveId: "CVE-2024-2756",
          severity: "high",
          description: "Cookie bypass vulnerability in PHP < 8.1.28",
          fixVersion: "8.1.28+",
          status: "vulnerable",
        },
        {
          id: crypto.randomUUID(),
          dependency: "Apache 2.4.49",
          cveId: "CVE-2021-41773",
          severity: "critical",
          description: "Path traversal and file disclosure via crafted URI",
          fixVersion: "2.4.51+",
          status: "vulnerable",
        },
        {
          id: crypto.randomUUID(),
          dependency: "jQuery 1.12.4",
          cveId: "CVE-2020-11023",
          severity: "medium",
          description: "XSS when passing HTML from untrusted sources",
          fixVersion: "3.5.0+",
          status: "outdated",
        },
      ],
      differentialResults: [
        {
          id: crypto.randomUUID(),
          testCase: "SQL UNION on /search",
          twinAResponse: "18.5 KB — contains extra table rows",
          twinBResponse: "14.8 KB — standard response",
          byteDelta: "+3624 bytes (+24.4%)",
          verdict: "confirmed",
          confidence: 0.94,
        },
        {
          id: crypto.randomUUID(),
          testCase: "XSS <script> on /feedback",
          twinAResponse: "403 Forbidden — WAF blocked",
          twinBResponse: "200 OK — normal form submit",
          byteDelta: "-8186 bytes (-88.9%)",
          verdict: "waf_blocked",
          confidence: 0.12,
        },
        {
          id: crypto.randomUUID(),
          testCase: "SSRF via url= param on /proxy",
          twinAResponse: "200 OK — returned internal banner",
          twinBResponse: "200 OK — public content only",
          byteDelta: "+892 bytes (+11.2%)",
          verdict: "confirmed",
          confidence: 0.87,
        },
      ],
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
