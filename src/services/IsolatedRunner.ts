/**
 * IsolatedRunner.ts — Isolated Attack Machine Abstraction
 * Every exploit attempt runs in a temporary, isolated environment
 * to prevent context contamination. Evidence is extracted before teardown.
 */

import { supabase } from "@/integrations/supabase/client";

export interface IsolatedExecution {
  executionId: string;
  containerId: string;
  status: "created" | "running" | "completed" | "destroyed";
  output: string;
  exitCode: number;
  evidence: ExtractedEvidence | null;
  duration: number;
}

export interface ExtractedEvidence {
  stdout: string;
  stderr: string;
  networkCapture: string[];
  filesCreated: string[];
  exitCode: number;
  timestamp: string;
}

/**
 * Execute a validation script in an isolated environment.
 * Uses the validate-finding edge function which provides sandboxed execution.
 */
export async function runIsolated(params: {
  script: string;
  language: "python" | "bash" | "curl";
  targetUrl: string;
  findingId?: string;
  approvalId?: string;
  targetId: string;
  timeout?: number;
}): Promise<IsolatedExecution> {
  const executionId = crypto.randomUUID();
  const startTime = Date.now();

  try {
    const { data, error } = await supabase.functions.invoke("validate-finding", {
      body: {
        findingId: params.findingId,
        approvalId: params.approvalId,
        targetId: params.targetId,
        script: params.script,
        action: "isolated-validate",
        executionId,
        timeout: params.timeout || 30000,
      },
    });

    if (error) throw error;

    const duration = Date.now() - startTime;

    return {
      executionId,
      containerId: data?.containerId || executionId,
      status: "completed",
      output: data?.terminalOutput || "",
      exitCode: data?.exitCode ?? 0,
      evidence: {
        stdout: data?.terminalOutput || "",
        stderr: data?.stderr || "",
        networkCapture: data?.networkCapture || [],
        filesCreated: data?.filesCreated || [],
        exitCode: data?.exitCode ?? 0,
        timestamp: new Date().toISOString(),
      },
      duration,
    };
  } catch (err) {
    return {
      executionId,
      containerId: "",
      status: "destroyed",
      output: `Isolated execution failed: ${err instanceof Error ? err.message : "Unknown"}`,
      exitCode: 1,
      evidence: null,
      duration: Date.now() - startTime,
    };
  }
}

/**
 * Generate an isolated validation script for a specific vuln class.
 */
export function generateIsolatedScript(
  vulnClass: string,
  payload: string,
  targetUrl: string,
  language: "python" | "curl" = "python"
): string {
  const safePayload = payload.replace(/'/g, "\\'").replace(/"/g, '\\"');

  if (language === "curl") {
    return `curl -s -o /dev/null -w "%{http_code}|%{size_download}|%{time_total}" "${targetUrl}?test=${encodeURIComponent(payload)}"`;
  }

  const scripts: Record<string, string> = {
    sqli: `import requests, time
url = "${targetUrl}"
# Boolean differential test
t1 = time.time()
r1 = requests.get(url, params={"test": "${safePayload}"}, timeout=15)
d1 = time.time() - t1
t2 = time.time()
r2 = requests.get(url, params={"test": "1 AND 1=2"}, timeout=15)
d2 = time.time() - t2
diff = abs(len(r1.text) - len(r2.text))
ratio = diff / max(len(r2.text), 1)
print(f"TRUE_LEN={len(r1.text)} FALSE_LEN={len(r2.text)} DIFF={diff} RATIO={ratio:.4f}")
print(f"TRUE_TIME={d1:.3f}s FALSE_TIME={d2:.3f}s")
if ratio > 0.15: print("[PROVEN] Boolean differential confirmed")
elif d1 > d2 + 4: print("[PROVEN] Time-based differential confirmed")
else: print("[UNPROVEN] No mathematical differential")`,

    rxss: `import requests
url = "${targetUrl}"
probe = "<cyberscope>"
r = requests.get(url, params={"test": probe}, timeout=15)
if probe in r.text:
    idx = r.text.index(probe)
    ctx = r.text[max(0,idx-50):idx+len(probe)+50]
    if "&lt;" not in ctx and "&gt;" not in ctx:
        print(f"[PROVEN] XSS probe reflected unescaped at index {idx}")
    else:
        print("[UNPROVEN] Probe reflected but HTML-escaped")
else:
    print("[UNPROVEN] Probe not reflected")`,

    ssrf: `import requests
url = "${targetUrl}"
ssrf_targets = ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:80/"]
for t in ssrf_targets:
    r = requests.get(url, params={"test": t}, timeout=15)
    if "ami-id" in r.text or "metadata" in r.text or "127.0.0.1" in r.text:
        print(f"[PROVEN] SSRF response contains internal data for {t}")
        break
else:
    print("[UNPROVEN] No internal data leaked")`,

    cmdi: `import requests
url = "${targetUrl}"
marker = "cyberscope_cmd_proof"
payloads = ["; echo " + marker, "| echo " + marker, "$" + "(echo " + marker + ")"]
for p in payloads:
    r = requests.get(url, params={"test": p}, timeout=15)
    if marker in r.text:
        print(f"[PROVEN] Command injection — marker found with payload: {p}")
        break
else:
    print("[UNPROVEN] No command execution evidence")`,
  };

  return scripts[vulnClass] || scripts.sqli;
}
