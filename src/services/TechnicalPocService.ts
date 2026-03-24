/**
 * TechnicalPocService - Technical Evidence Generator
 * Generates deterministic Proof of Concept scripts that reproduce
 * verified security gaps in a controlled, non-destructive manner.
 */

export interface PocConfig {
  targetUrl: string;
  method: string;
  payload: string;
  adaptationName: string;
  headers?: Record<string, string>;
  auditToken?: string;
}

export function generatePythonPoC(config: PocConfig): string {
  const token = config.auditToken || `CYBERSCOPE-${Date.now()}`;
  const headerLines = Object.entries(config.headers || {})
    .map(([k, v]) => `    "${k}": "${v}",`)
    .join("\n");

  return `#!/usr/bin/env python3
"""
CyberScope Scanner - Technical Evidence Script
================================================
Purpose: Demonstrate verified security gap in controlled environment
Audit Token: ${token}
Adaptation Method: ${config.adaptationName}
Generated: ${new Date().toISOString()}

IMPORTANT: This script is for authorized security auditing only.
The X-CyberScope-Token header identifies this as an authorized test.
"""

import requests
import sys
import json
from datetime import datetime

TARGET_URL = "${config.targetUrl}"
AUDIT_TOKEN = "${token}"

def run_verification():
    """Execute the verification test with the successful adaptation."""
    print(f"[{datetime.now().isoformat()}] CyberScope Verification Starting...")
    print(f"[INFO] Target: {TARGET_URL}")
    print(f"[INFO] Method: ${config.method}")
    print(f"[INFO] Adaptation: ${config.adaptationName}")
    print(f"[INFO] Audit Token: {AUDIT_TOKEN}")
    print("-" * 60)

    headers = {
        "X-CyberScope-Token": AUDIT_TOKEN,
        "User-Agent": "CyberScope-Scanner/5.0 (Authorized Security Audit)",
${headerLines}
    }

    payload = ${JSON.stringify(config.payload)}

    try:
        response = requests.${config.method.toLowerCase()}(
            TARGET_URL,
            headers=headers,
            data=payload,
            timeout=10,
            verify=True
        )

        print(f"\\n[RESULT] Status Code: {response.status_code}")
        print(f"[RESULT] Response Length: {len(response.text)} bytes")
        print(f"[RESULT] Content-Type: {response.headers.get('Content-Type', 'N/A')}")

        if response.status_code in [200, 500]:
            print("[VERIFIED] Security gap confirmed - test reached backend logic")
        else:
            print(f"[FILTERED] Response indicates filtering at status {response.status_code}")

        return {
            "status_code": response.status_code,
            "response_length": len(response.text),
            "verified": response.status_code in [200, 500],
        }

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Request failed: {e}")
        return {"error": str(e)}

if __name__ == "__main__":
    print("=" * 60)
    print("CYBERSCOPE SCANNER - TECHNICAL EVIDENCE SCRIPT")
    print("=" * 60)
    result = run_verification()
    print("\\n" + "=" * 60)
    print(f"Verification completed at {datetime.now().isoformat()}")
    print(json.dumps(result, indent=2))
`;
}

export function generateCurlCommand(config: PocConfig): string {
  const token = config.auditToken || `CYBERSCOPE-${Date.now()}`;
  const headerFlags = [
    `-H "X-CyberScope-Token: ${token}"`,
    `-H "User-Agent: CyberScope-Scanner/5.0 (Authorized Security Audit)"`,
    ...Object.entries(config.headers || {}).map(([k, v]) => `-H "${k}: ${v}"`),
  ].join(" \\\n  ");

  return `# CyberScope Scanner - Technical Evidence (curl)
# Adaptation: ${config.adaptationName}
# Generated: ${new Date().toISOString()}

curl -X ${config.method} "${config.targetUrl}" \\
  ${headerFlags} \\
  -d '${config.payload.replace(/'/g, "'\\''")}' \\
  --max-time 10 \\
  -v 2>&1
`;
}
