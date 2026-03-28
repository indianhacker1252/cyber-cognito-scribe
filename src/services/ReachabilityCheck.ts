import { supabase } from "@/integrations/supabase/client";

export interface ReachabilityResult {
  isReachable: boolean;
  reason: string;
  protections: string[];
  riskLevel: "critical" | "high" | "medium" | "low" | "info";
}

/**
 * Dynamic Reachability Analyzer
 * Maps the network path and checks if the vulnerable endpoint is actually
 * exposed to the public internet or protected by WAF/firewall.
 */
export async function checkReachability(
  targetUrl: string,
  vulnClass: string
): Promise<ReachabilityResult> {
  const protections: string[] = [];
  let isReachable = true;
  let reason = "Endpoint appears publicly accessible";

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);

    const resp = await fetch(targetUrl, {
      method: "HEAD",
      headers: { "User-Agent": "CyberScope-Reachability/1.0" },
      redirect: "manual",
      signal: controller.signal,
    });
    clearTimeout(timeout);

    const headers = Object.fromEntries(resp.headers.entries());

    // Check for WAF signatures
    const wafSignatures: Record<string, string> = {
      "x-sucuri-id": "Sucuri WAF",
      "x-cdn": "CDN Protection",
      "cf-ray": "Cloudflare WAF",
      "x-akamai-transformed": "Akamai WAF",
      "x-aws-waf": "AWS WAF",
      "x-azure-ref": "Azure Front Door",
      "server": "",
    };

    for (const [header, wafName] of Object.entries(wafSignatures)) {
      if (headers[header]) {
        if (header === "server") {
          const val = headers[header].toLowerCase();
          if (val.includes("cloudflare")) protections.push("Cloudflare WAF");
          if (val.includes("akamaighost")) protections.push("Akamai CDN");
          if (val.includes("bigip")) protections.push("F5 BIG-IP WAF");
          if (val.includes("imperva")) protections.push("Imperva WAF");
        } else {
          protections.push(wafName);
        }
      }
    }

    // Check for CSP that would block XSS
    if (vulnClass === "rxss" || vulnClass === "stored-xss") {
      const csp = headers["content-security-policy"] || "";
      if (csp.includes("script-src") && !csp.includes("'unsafe-inline'")) {
        protections.push("CSP blocks inline scripts");
      }
    }

    // 403 on HEAD often means firewall blocking
    if (resp.status === 403) {
      isReachable = false;
      reason = "Endpoint returned 403 — likely behind firewall/ACL";
    } else if (resp.status === 0 || resp.status >= 500) {
      isReachable = false;
      reason = "Endpoint unreachable or returning server errors";
    }

    if (protections.length > 0 && isReachable) {
      reason = `Endpoint reachable but protected by: ${protections.join(", ")}`;
    }
  } catch (err) {
    isReachable = false;
    reason = `Network error: ${err instanceof Error ? err.message : "unreachable"}`;
  }

  const riskLevel: ReachabilityResult["riskLevel"] =
    !isReachable ? "info" :
    protections.length >= 2 ? "low" :
    protections.length === 1 ? "medium" : "high";

  return { isReachable, reason, protections, riskLevel };
}
