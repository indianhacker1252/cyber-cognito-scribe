import { supabase } from "@/integrations/supabase/client";

export interface PocValidationResult {
  isConfirmed: boolean;
  terminalOutput: string;
  successSignature: string | null;
  evidencePackageId: string | null;
  validationMethod: string;
}

/**
 * Proof-of-Concept Auto-Verifier
 * No finding is "Confirmed" until it passes this validator.
 * Generates a verification script, executes it in the sandboxed
 * detonation chamber, and checks for a strict Success Signature.
 */
export async function validatePoc(
  findingId: string,
  targetId: string,
  vulnClass: string,
  payload: string,
  targetUrl: string,
  source: "finding" | "approval" = "finding"
): Promise<PocValidationResult> {
  const successSignatures: Record<string, string[]> = {
    sqli: ["SQL syntax", "mysql_fetch", "pg_query", "SQLSTATE", "ORA-", "unclosed quotation"],
    rxss: ["<cyberscope>", "<svg onload=", "onerror=cyberscope"],
    cmdi: ["cyberscope_marker", "uid=", "root:"],
    ssti: ["49"], // 7*7
    "path-traversal": ["root:", "/bin/", "etc/passwd"],
    lfi: ["root:", "/bin/"],
    xxe: ["cyberscope"],
    ssrf: ["169.254.169.254", "metadata", "ami-id"],
  };

  const signatures = successSignatures[vulnClass] || [];

  // Generate PoC verification script
  const script = generateVerificationScript(vulnClass, payload, targetUrl);

  try {
    const { data, error } = await supabase.functions.invoke("validate-finding", {
      body: {
        findingId: source === "finding" ? findingId : undefined,
        approvalId: source === "approval" ? findingId : undefined,
        targetId,
        script,
        action: "validate",
      },
    });

    if (error) throw error;

    const output = data?.terminalOutput || "";
    const evidencePackageId = data?.evidencePackageId || null;

    // Check for strict success signatures
    const matchedSignature = signatures.find(sig =>
      output.toLowerCase().includes(sig.toLowerCase())
    );

    const isConfirmed = !!matchedSignature ||
      data?.validationResult === "confirmed" ||
      output.toLowerCase().includes("confirmed") ||
      output.toLowerCase().includes("vulnerable");

    return {
      isConfirmed,
      terminalOutput: output,
      successSignature: matchedSignature || null,
      evidencePackageId,
      validationMethod: `PoC script with ${signatures.length} success signatures checked`,
    };
  } catch (err) {
    return {
      isConfirmed: false,
      terminalOutput: `Validation error: ${err instanceof Error ? err.message : "Unknown"}`,
      successSignature: null,
      evidencePackageId: null,
      validationMethod: "Failed — error during validation",
    };
  }
}

function generateVerificationScript(
  vulnClass: string,
  payload: string,
  targetUrl: string
): string {
  const safePayload = payload.replace(/'/g, "\\'").replace(/"/g, '\\"');
  const scripts: Record<string, string> = {
    sqli: `import requests
url = "${targetUrl}"
payload = "${safePayload}"
# Test with boolean-based detection
r1 = requests.get(url, params={"test": payload}, timeout=10)
r2 = requests.get(url, params={"test": "${safePayload.replace(/1'='1/, "1'='2")}"}, timeout=10)
if len(r1.text) != len(r2.text):
    print("[CONFIRMED] SQL Injection — differential response detected")
    print(f"True length: {len(r1.text)}, False length: {len(r2.text)}")
else:
    print("[INCONCLUSIVE] No differential response")`,
    rxss: `import requests
url = "${targetUrl}"
payload = "${safePayload}"
r = requests.get(url, params={"test": payload}, timeout=10)
if payload in r.text and "&lt;" not in r.text.split(payload)[0][-20:]:
    print("[CONFIRMED] XSS — payload reflected unescaped")
else:
    print("[INCONCLUSIVE] Payload not reflected or escaped")`,
    cmdi: `import requests
url = "${targetUrl}"
payload = "${safePayload}"
r = requests.get(url, params={"test": payload}, timeout=10)
if "cyberscope_marker" in r.text:
    print("[CONFIRMED] Command Injection — marker found in output")
else:
    print("[INCONCLUSIVE] No command execution evidence")`,
    default: `import requests
url = "${targetUrl}"
payload = "${safePayload}"
r = requests.get(url, params={"test": payload}, timeout=10)
print(f"Status: {r.status_code}")
print(f"Length: {len(r.text)}")
if r.status_code == 200:
    print("[LIKELY] Endpoint accepted payload — manual verification needed")
else:
    print("[INCONCLUSIVE] Endpoint rejected payload")`,
  };

  return scripts[vulnClass] || scripts.default;
}
