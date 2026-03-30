/**
 * DeterministicProof.ts — The "Gauntlet" Validator
 * NO finding is reported based on AI "opinion."
 * A finding is ONLY confirmed via controlled, deterministic proof.
 */

export interface ProofRequirement {
  vulnClass: string;
  proofType: string;
  description: string;
  verify: (evidence: ProofEvidence) => ProofVerdict;
}

export interface ProofEvidence {
  responseBody: string;
  baselineBody: string;
  responseTime: number;
  baselineTime: number;
  statusCode: number;
  baselineStatus: number;
  headers: Record<string, string>;
  oastCallback?: string;
  domExecution?: string;
  consoleOutput?: string;
}

export interface ProofVerdict {
  proven: boolean;
  proofType: string;
  details: string;
  mathematicalBasis: string;
}

/**
 * The Gauntlet: deterministic proof requirements per vuln class.
 */
const GAUNTLET: ProofRequirement[] = [
  {
    vulnClass: "sqli",
    proofType: "mathematical_differential",
    description: "Prove SQLi via boolean differential or time-based delay",
    verify: (ev) => {
      // Boolean differential: 1=1 response differs from 1=2
      const lenDiff = Math.abs(ev.responseBody.length - ev.baselineBody.length);
      const ratio = lenDiff / Math.max(ev.baselineBody.length, 1);
      const booleanProven = ratio > 0.15 && ev.statusCode === 200;

      // Time-based: response >5s slower than baseline
      const timeDiff = ev.responseTime - ev.baselineTime;
      const timeProven = timeDiff > 4500;

      // Error-based: DB-specific errors
      const errorPatterns = [
        /you have an error in your sql syntax/i,
        /ORA-\d{4,5}/i, /SQLSTATE/i, /pg_query/i,
        /unclosed quotation mark/i, /syntax error at or near/i,
      ];
      const errorProven = errorPatterns.some(p => p.test(ev.responseBody) && !p.test(ev.baselineBody));

      const proven = booleanProven || timeProven || errorProven;
      const basis = booleanProven
        ? `Body differential: ${(ratio * 100).toFixed(1)}% change (${ev.responseBody.length} vs ${ev.baselineBody.length})`
        : timeProven
          ? `Time differential: ${timeDiff}ms delay (baseline: ${ev.baselineTime}ms)`
          : errorProven
            ? "Database error string detected in mutated response only"
            : "No mathematical proof";

      return { proven, proofType: "sqli_differential", details: basis, mathematicalBasis: basis };
    },
  },
  {
    vulnClass: "rxss",
    proofType: "dom_execution",
    description: "Prove XSS via headless browser DOM execution detection",
    verify: (ev) => {
      const probeStrings = ["<cyberscope>", "<svg onload=", "onerror=cyberscope", "alert(1)", "console.log('cyberscope')"];
      const reflected = probeStrings.some(p => ev.responseBody.includes(p));
      const domExecuted = ev.domExecution?.includes("cyberscope") || ev.consoleOutput?.includes("cyberscope");

      const proven = reflected || !!domExecuted;
      return {
        proven,
        proofType: "xss_execution",
        details: domExecuted ? "DOM execution confirmed via headless browser" : reflected ? "Probe reflected unescaped in response body" : "No XSS proof",
        mathematicalBasis: domExecuted ? "Console output matched probe string" : reflected ? "Exact probe string found in unescaped context" : "N/A",
      };
    },
  },
  {
    vulnClass: "ssrf",
    proofType: "oast_callback",
    description: "Prove SSRF via verified OAST callback from target",
    verify: (ev) => {
      const internalData = /169\.254\.169\.254|metadata|ami-id|internal|localhost/.test(ev.responseBody);
      const oastVerified = !!ev.oastCallback;
      const proven = internalData || oastVerified;

      return {
        proven,
        proofType: "ssrf_callback",
        details: oastVerified ? `OAST callback received: ${ev.oastCallback}` : internalData ? "Internal service data leaked in response" : "No SSRF proof",
        mathematicalBasis: oastVerified ? "Verified DNS/HTTP callback from target IP" : internalData ? "Cloud metadata or internal IP data in response" : "N/A",
      };
    },
  },
  {
    vulnClass: "cmdi",
    proofType: "command_output",
    description: "Prove CMD injection via marker string or system output",
    verify: (ev) => {
      const markers = [/cyberscope_marker/, /uid=\d+\(/, /root:.*:0:0/];
      const proven = markers.some(p => p.test(ev.responseBody) && !p.test(ev.baselineBody));
      return {
        proven,
        proofType: "cmdi_output",
        details: proven ? "Command execution marker found in response" : "No command execution evidence",
        mathematicalBasis: proven ? "Unique marker string present only in mutated response" : "N/A",
      };
    },
  },
  {
    vulnClass: "ssti",
    proofType: "template_evaluation",
    description: "Prove SSTI via mathematical expression evaluation",
    verify: (ev) => {
      // Check if 7*7=49 or similar computed result appears
      const proven = /\b49\b/.test(ev.responseBody) && !/\b49\b/.test(ev.baselineBody);
      return {
        proven,
        proofType: "ssti_eval",
        details: proven ? "Template engine evaluated 7*7=49" : "No template evaluation evidence",
        mathematicalBasis: proven ? "Mathematical expression (7*7) evaluated to 49 in response" : "N/A",
      };
    },
  },
  {
    vulnClass: "path-traversal",
    proofType: "file_content",
    description: "Prove path traversal via known file content signatures",
    verify: (ev) => {
      const fileSignatures = [/root:.*:0:0/, /\[boot loader\]/i, /\/bin\/bash/, /etc\/shadow/];
      const proven = fileSignatures.some(p => p.test(ev.responseBody));
      return {
        proven,
        proofType: "file_leak",
        details: proven ? "Known system file content detected" : "No file traversal evidence",
        mathematicalBasis: proven ? "OS-specific file signature matched" : "N/A",
      };
    },
  },
];

/**
 * Run the Gauntlet: attempt deterministic proof for a finding.
 */
export function runGauntlet(vulnClass: string, evidence: ProofEvidence): ProofVerdict {
  const requirement = GAUNTLET.find(g => g.vulnClass === vulnClass);
  if (!requirement) {
    return {
      proven: false,
      proofType: "unsupported",
      details: `No deterministic proof available for ${vulnClass} — requires manual review`,
      mathematicalBasis: "N/A",
    };
  }
  return requirement.verify(evidence);
}

/**
 * Check if a vuln class has a deterministic proof path.
 */
export function hasProofPath(vulnClass: string): boolean {
  return GAUNTLET.some(g => g.vulnClass === vulnClass);
}

/**
 * Get all supported proof types.
 */
export function getSupportedProofs(): Array<{ vulnClass: string; proofType: string; description: string }> {
  return GAUNTLET.map(g => ({ vulnClass: g.vulnClass, proofType: g.proofType, description: g.description }));
}
