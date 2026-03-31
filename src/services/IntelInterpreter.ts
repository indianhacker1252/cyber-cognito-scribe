/**
 * IntelInterpreter.ts — Report-to-Logic Parser
 * Uses AI to "read" human-written security reports and extract
 * structured intelligence: vuln class, payloads, tech stack, bypass logic.
 */

import { supabase } from "@/integrations/supabase/client";

export interface ParsedIntelligence {
  vulnerabilityClass: string;
  specificPayloads: string[];
  affectedTechStack: string[];
  wafBypassLogic: string | null;
  bypassTechniques: string[];
  attackVector: string;
  impactDescription: string;
  signalStrength: "high" | "medium" | "low";
  owaspCategory: string;
  confidence: number;
}

/**
 * Use AI to interpret a disclosed security report and extract actionable intelligence.
 */
export async function interpretReport(params: {
  title: string;
  summary: string;
  source: string;
  severity: string;
  vulnClass?: string;
}): Promise<ParsedIntelligence> {
  try {
    const { data, error } = await supabase.functions.invoke("intel-sync", {
      body: {
        action: "interpret-report",
        report: params,
      },
    });

    if (error) throw error;

    if (data?.interpretation) {
      return data.interpretation;
    }
  } catch (e) {
    console.error("AI interpretation failed, using heuristic fallback:", e);
  }

  // Heuristic fallback when AI is unavailable
  return heuristicInterpretation(params);
}

/**
 * Heuristic fallback: extract intelligence from report text without AI.
 */
function heuristicInterpretation(params: {
  title: string;
  summary: string;
  severity: string;
  vulnClass?: string;
}): ParsedIntelligence {
  const text = `${params.title} ${params.summary}`.toLowerCase();

  // Classify vulnerability
  const vulnPatterns: Record<string, string[]> = {
    sqli: ["sql injection", "sqli", "blind sql", "union select", "boolean-based"],
    rxss: ["xss", "cross-site scripting", "reflected xss", "dom xss", "stored xss"],
    ssrf: ["ssrf", "server-side request forgery", "internal service"],
    cmdi: ["command injection", "os command", "rce", "remote code execution"],
    ssti: ["ssti", "template injection", "server-side template"],
    idor: ["idor", "insecure direct object", "access control", "authorization bypass"],
    "path-traversal": ["path traversal", "directory traversal", "lfi", "local file inclusion"],
    xxe: ["xxe", "xml external entity", "xml injection"],
    csrf: ["csrf", "cross-site request forgery"],
    "auth-bypass": ["authentication bypass", "auth bypass", "login bypass"],
    deserialization: ["deserialization", "insecure deserialization", "pickle", "java serial"],
    "open-redirect": ["open redirect", "redirect", "url redirect"],
  };

  let detectedClass = params.vulnClass || "unknown";
  for (const [cls, keywords] of Object.entries(vulnPatterns)) {
    if (keywords.some((k) => text.includes(k))) {
      detectedClass = cls;
      break;
    }
  }

  // Extract potential payloads from text
  const payloadPatterns = [
    /['"`].*(?:OR|AND|UNION|SELECT|INSERT).*['"`]/gi,
    /<\/?(?:script|img|svg|iframe|object)\b[^>]*>/gi,
    /\{\{.*?\}\}/g,
    /\$\{.*?\}/g,
    /\.\.\/|\.\.\\|%2e%2e/gi,
    /;.*(?:ls|cat|id|whoami|echo)/gi,
    /http:\/\/(?:127\.0\.0\.1|169\.254|localhost)/gi,
  ];

  const payloads: string[] = [];
  for (const pattern of payloadPatterns) {
    const matches = text.match(pattern);
    if (matches) payloads.push(...matches.slice(0, 3));
  }

  // Detect tech stack mentions
  const techKeywords = [
    "nginx", "apache", "iis", "node.js", "express", "django", "flask",
    "spring", "rails", "laravel", "wordpress", "drupal", "joomla",
    "react", "angular", "vue", "php", "python", "java", "ruby",
    "jenkins", "gitlab", "kubernetes", "docker", "aws", "azure", "gcp",
  ];
  const techStack = techKeywords.filter((t) => text.includes(t));

  // Detect bypass techniques
  const bypassKeywords = [
    "bypass", "waf bypass", "filter bypass", "encoding bypass",
    "double encoding", "null byte", "unicode", "case variation",
    "content-type bypass", "method override", "header injection",
  ];
  const bypasses = bypassKeywords.filter((b) => text.includes(b));

  // WAF bypass logic
  const wafBypass = text.includes("waf") || text.includes("firewall")
    ? bypasses.join("; ") || "Generic WAF bypass mentioned"
    : null;

  // OWASP mapping
  const owaspMap: Record<string, string> = {
    sqli: "A03:2021", rxss: "A03:2021", ssrf: "A10:2021", cmdi: "A03:2021",
    ssti: "A03:2021", idor: "A01:2021", "path-traversal": "A01:2021",
    xxe: "A05:2021", csrf: "A01:2021", "auth-bypass": "A07:2021",
    deserialization: "A08:2021", "open-redirect": "A01:2021",
  };

  // Signal strength based on content richness
  const signalStrength: "high" | "medium" | "low" =
    payloads.length > 0 && bypasses.length > 0 ? "high" :
    payloads.length > 0 || techStack.length > 0 ? "medium" : "low";

  return {
    vulnerabilityClass: detectedClass,
    specificPayloads: payloads,
    affectedTechStack: techStack,
    wafBypassLogic: wafBypass,
    bypassTechniques: bypasses,
    attackVector: detectedClass === "ssrf" ? "network" : "application",
    impactDescription: `${params.severity} severity ${detectedClass} vulnerability`,
    signalStrength,
    owaspCategory: owaspMap[detectedClass] || "Unknown",
    confidence: payloads.length > 0 ? 75 : techStack.length > 0 ? 55 : 35,
  };
}

/**
 * Batch interpret multiple reports.
 */
export async function batchInterpret(
  reports: Array<{ title: string; summary: string; source: string; severity: string; vulnClass?: string }>
): Promise<ParsedIntelligence[]> {
  const results: ParsedIntelligence[] = [];
  for (const report of reports) {
    const result = await interpretReport(report);
    results.push(result);
    // Rate limit: 200ms between AI calls
    await new Promise((r) => setTimeout(r, 200));
  }
  return results;
}
