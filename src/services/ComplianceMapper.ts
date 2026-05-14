// Static heuristic mapping from finding type / title → OWASP Top 10 (2021) + CWE.
// No external lookup, deterministic, used by the PDF report.

export interface ComplianceTags {
  owasp: string;       // e.g. "A03:2021 — Injection"
  cwe: string;         // e.g. "CWE-89"
  cwe_name: string;    // e.g. "SQL Injection"
}

const RULES: Array<{ rx: RegExp; owasp: string; cwe: string; cwe_name: string }> = [
  { rx: /sqli|sql.?injection|sql_inj/i,            owasp: "A03:2021 — Injection",                     cwe: "CWE-89",  cwe_name: "SQL Injection" },
  { rx: /xss|cross.?site.?script|dom.?xss/i,       owasp: "A03:2021 — Injection",                     cwe: "CWE-79",  cwe_name: "Cross-site Scripting" },
  { rx: /cmd.?inj|command.?injection|rce|remote.?code/i, owasp: "A03:2021 — Injection",               cwe: "CWE-77",  cwe_name: "Command Injection" },
  { rx: /ssti|template.?injection/i,               owasp: "A03:2021 — Injection",                     cwe: "CWE-1336",cwe_name: "Server-Side Template Injection" },
  { rx: /xxe|xml.?external/i,                      owasp: "A05:2021 — Security Misconfiguration",    cwe: "CWE-611", cwe_name: "XML External Entity" },
  { rx: /ssrf|server.?side.?request/i,             owasp: "A10:2021 — Server-Side Request Forgery",  cwe: "CWE-918", cwe_name: "Server-Side Request Forgery" },
  { rx: /idor|insecure.?direct|broken.?access|bola/i, owasp: "A01:2021 — Broken Access Control",     cwe: "CWE-639", cwe_name: "Authorization Bypass" },
  { rx: /open.?redirect|redirect.?hijack/i,        owasp: "A01:2021 — Broken Access Control",        cwe: "CWE-601", cwe_name: "Open Redirect" },
  { rx: /lfi|local.?file|path.?traversal/i,        owasp: "A01:2021 — Broken Access Control",        cwe: "CWE-22",  cwe_name: "Path Traversal" },
  { rx: /csrf|cross.?site.?request/i,              owasp: "A01:2021 — Broken Access Control",        cwe: "CWE-352", cwe_name: "Cross-Site Request Forgery" },
  { rx: /auth.?bypass|broken.?auth|jwt|session/i,  owasp: "A07:2021 — Identification & Auth Failures", cwe: "CWE-287", cwe_name: "Improper Authentication" },
  { rx: /crypto|weak.?cipher|tls|ssl/i,            owasp: "A02:2021 — Cryptographic Failures",       cwe: "CWE-327", cwe_name: "Use of Broken Cryptographic Algorithm" },
  { rx: /prototype.?pollution/i,                   owasp: "A08:2021 — Software & Data Integrity",    cwe: "CWE-1321",cwe_name: "Prototype Pollution" },
  { rx: /deserial/i,                               owasp: "A08:2021 — Software & Data Integrity",    cwe: "CWE-502", cwe_name: "Deserialization of Untrusted Data" },
  { rx: /smuggl/i,                                 owasp: "A05:2021 — Security Misconfiguration",    cwe: "CWE-444", cwe_name: "HTTP Request Smuggling" },
  { rx: /cors|cross.?origin/i,                     owasp: "A05:2021 — Security Misconfiguration",    cwe: "CWE-942", cwe_name: "Permissive CORS Policy" },
  { rx: /header|misconfig|csp|hsts|cookie/i,       owasp: "A05:2021 — Security Misconfiguration",    cwe: "CWE-16",  cwe_name: "Configuration" },
  { rx: /info.?disclos|exposure|stack.?trace|secret/i, owasp: "A04:2021 — Insecure Design",          cwe: "CWE-200", cwe_name: "Information Exposure" },
  { rx: /vuln.?component|outdated|cve/i,           owasp: "A06:2021 — Vulnerable & Outdated Components", cwe: "CWE-1104", cwe_name: "Use of Unmaintained 3rd-Party Components" },
  { rx: /log|monitor/i,                            owasp: "A09:2021 — Logging & Monitoring",         cwe: "CWE-778", cwe_name: "Insufficient Logging" },
];

export function classifyFinding(typeOrTitle: string): ComplianceTags {
  const s = typeOrTitle || "";
  for (const r of RULES) if (r.rx.test(s)) return { owasp: r.owasp, cwe: r.cwe, cwe_name: r.cwe_name };
  return { owasp: "A04:2021 — Insecure Design", cwe: "CWE-693", cwe_name: "Protection Mechanism Failure" };
}

// Derive a CVSS 3.1 vector from severity when none is recorded.
// Conservative defaults — auditors should override with manual scoring.
export function deriveCvssVector(sev: string, cvssScore?: number | null): { vector: string; score: number } {
  const map: Record<string, { vector: string; score: number }> = {
    critical: { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", score: 9.8 },
    high:     { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", score: 7.5 },
    medium:   { vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N", score: 5.4 },
    low:      { vector: "CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N", score: 3.1 },
    info:     { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", score: 0.0 },
  };
  const m = map[(sev || "info").toLowerCase()] || map.info;
  return { vector: m.vector, score: cvssScore ?? m.score };
}

export function reproSteps(method: string, url: string, payload: string | null | undefined, paramHint?: string): string[] {
  const steps: string[] = [];
  steps.push(`Open a terminal with curl available, or use Burp Suite / Caido to replay the request.`);
  steps.push(`Send the request below to the affected endpoint.`);
  const safeUrl = url || "<TARGET_URL>";
  if (payload) {
    const param = paramHint || "input";
    steps.push(`curl -i -X ${method || "GET"} '${safeUrl}' --data-urlencode '${param}=${payload.replace(/'/g, "\\'")}'`);
  } else {
    steps.push(`curl -i -X ${method || "GET"} '${safeUrl}'`);
  }
  steps.push(`Inspect the response — look for the indicators noted in "Verification" below.`);
  steps.push(`If a browser POC is available (DOM XSS, open redirect), open the affected URL in an incognito window with the payload encoded in the parameter.`);
  return steps;
}
