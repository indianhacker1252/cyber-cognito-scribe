/**
 * PeerReview.ts — Automated Debating / Skeptic Reviewer
 * When a Solver Agent claims a bug, a Reviewer Agent tries to
 * disprove it. Only findings that survive scrutiny are confirmed.
 */

import { supabase } from "@/integrations/supabase/client";

export interface ReviewChallenge {
  challengeType: string;
  argument: string;
  severity: "critical" | "major" | "minor";
}

export interface PeerReviewResult {
  verdict: "upheld" | "disputed" | "needs_retest";
  challenges: ReviewChallenge[];
  skepticScore: number; // 0-100, higher = more suspicious
  finalConfidence: number;
  reasoning: string;
}

/**
 * Spawn a Reviewer Agent to scrutinize a finding.
 */
export async function peerReviewFinding(params: {
  findingTitle: string;
  vulnClass: string;
  severity: string;
  payload: string;
  responseBody: string;
  baselineBody: string;
  statusCode: number;
  baselineStatus: number;
  techStack: Record<string, string | undefined>;
  solverConfidence: number;
  executionEvidence?: string;
}): Promise<PeerReviewResult> {
  const challenges: ReviewChallenge[] = [];

  // 1. Honeypot detection
  if (params.responseBody.length > 10000 && params.statusCode === 200) {
    const suspiciousPatterns = ["trap", "honeypot", "canary", "deception"];
    if (suspiciousPatterns.some(p => params.responseBody.toLowerCase().includes(p))) {
      challenges.push({
        challengeType: "honeypot_suspected",
        argument: "Response contains deception/honeypot indicators — may be a trap",
        severity: "critical",
      });
    }
  }

  // 2. Backported patch check
  const serverHeader = (params.techStack.server || "").toLowerCase();
  const backportIndicators = [".el", ".deb", "ubuntu", ".amzn", ".fc", "rhel", "centos"];
  if (backportIndicators.some(ind => serverHeader.includes(ind))) {
    challenges.push({
      challengeType: "backported_patch",
      argument: `Server header suggests enterprise distro (${serverHeader}) — patch may be backported`,
      severity: "major",
    });
  }

  // 3. WAF/CDN false response check
  const wafIndicators = ["cloudflare", "akamai", "incapsula", "sucuri", "barracuda", "f5"];
  if (wafIndicators.some(w => params.responseBody.toLowerCase().includes(w) || serverHeader.includes(w))) {
    challenges.push({
      challengeType: "waf_interference",
      argument: "WAF/CDN detected — response may be modified by security layer",
      severity: "major",
    });
  }

  // 4. Generic error page check
  const genericErrors = ["page not found", "error occurred", "something went wrong", "access denied"];
  if (genericErrors.some(e => params.responseBody.toLowerCase().includes(e))) {
    challenges.push({
      challengeType: "generic_error",
      argument: "Response contains generic error page — may not indicate actual vulnerability",
      severity: "minor",
    });
  }

  // 5. Inconsistent evidence check
  if (params.statusCode >= 400 && params.solverConfidence > 70) {
    challenges.push({
      challengeType: "status_confidence_mismatch",
      argument: `HTTP ${params.statusCode} with high confidence (${params.solverConfidence}%) — suspicious mismatch`,
      severity: "major",
    });
  }

  // 6. Payload reflection vs execution distinction
  if (params.vulnClass === "rxss" && params.responseBody.includes(params.payload)) {
    const escaped = params.responseBody.includes(`&lt;`) || params.responseBody.includes(`&gt;`);
    if (escaped) {
      challenges.push({
        challengeType: "escaped_reflection",
        argument: "Payload is reflected but HTML-escaped — XSS may not be exploitable",
        severity: "critical",
      });
    }
  }

  // 7. Timing variability check for time-based attacks
  if (params.vulnClass === "sqli" && params.executionEvidence?.includes("time")) {
    challenges.push({
      challengeType: "timing_variability",
      argument: "Time-based detection can be affected by network latency — requires multiple samples",
      severity: "minor",
    });
  }

  // Calculate skeptic score
  const skepticScore = Math.min(100, challenges.reduce((acc, c) => {
    if (c.severity === "critical") return acc + 35;
    if (c.severity === "major") return acc + 20;
    return acc + 10;
  }, 0));

  // Adjust confidence based on challenges
  const confidencePenalty = skepticScore * 0.6;
  const finalConfidence = Math.max(0, Math.min(100, params.solverConfidence - confidencePenalty));

  let verdict: PeerReviewResult["verdict"];
  if (challenges.some(c => c.severity === "critical")) {
    verdict = "disputed";
  } else if (skepticScore > 40) {
    verdict = "needs_retest";
  } else {
    verdict = "upheld";
  }

  // Use AI for deeper review if available
  try {
    const { data } = await supabase.functions.invoke("deep-signal-triage", {
      body: {
        finding: {
          findingTitle: params.findingTitle,
          vulnClass: params.vulnClass,
          severity: params.severity,
          payload: params.payload,
          baselineResponse: { body: params.baselineBody.substring(0, 500), status: params.baselineStatus },
          mutatedResponse: { body: params.responseBody.substring(0, 500), status: params.statusCode },
          confidenceScore: params.solverConfidence,
          techStack: params.techStack,
          peerChallenges: challenges,
        },
      },
    });

    if (data?.verdict === "demote" && verdict === "upheld") {
      verdict = "disputed";
    }
  } catch {
    // AI review unavailable, use heuristic result
  }

  const reasoning = challenges.length > 0
    ? `Reviewer found ${challenges.length} concern(s): ${challenges.map(c => c.challengeType).join(", ")}`
    : "No concerns found — finding appears legitimate";

  return { verdict, challenges, skepticScore, finalConfidence, reasoning };
}
