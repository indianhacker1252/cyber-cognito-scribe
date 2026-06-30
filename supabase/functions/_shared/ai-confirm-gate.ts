// AI Confirmation Gate + Honeypot/Decoy Trap Detector.
// Every finding MUST pass this gate before being inserted into
// vulnerability_findings or pending_approvals. The gate combines:
//   1. Deterministic proof check (response code alone is NEVER enough)
//   2. Honeypot/decoy detection (trap responses that always say "vulnerable")
//   3. AI confirmation via Lovable AI (Gemini) with strict JSON tool-call output
//
// Returns { confirmed, confidence, reasoning, honeypot, proofType } so the
// caller can decide insert vs. drop.

const LOVABLE_API_KEY = Deno.env.get("LOVABLE_API_KEY");

// ─── Honeypot/Decoy Trap Signatures ──────────────────────────────────
// These patterns indicate a trap server / WAF that responds with fake
// "vulnerability" markers to trick scanners. Classic honeypots:
//   - Cowrie, Dionaea, Glastopf, T-Pot, OpenCanary fingerprints
//   - Identical 200 responses regardless of payload
//   - Static "you have been logged" messages
//   - Banner versions that don't match real software (e.g. SSH-2.0-Cowrie)
const HONEYPOT_SIGNATURES = [
  /cowrie/i,
  /dionaea/i,
  /glastopf/i,
  /opencanary/i,
  /honeyd/i,
  /honeypot/i,
  /thug-honeyclient/i,
  /SSH-2\.0-Cowrie/i,
  /HoneyDrive/i,
  /\bcanary[-_ ]?token\b/i,
  /you have been (logged|caught|trapped|recorded)/i,
  /this incident (has been|will be) reported/i,
  /<!-- canary -->/i,
  /x-honey(pot)?:/i,
];

// Telltales that a server is echoing payloads as a trap (always reflects)
const ALWAYS_REFLECT_MARKERS = ["<script>alert('xss')</script>", "' OR '1'='1", "<?php phpinfo();"];

export interface ProofBundle {
  vulnClass: string;
  payload: string;
  endpoint: string;
  parameter?: string;
  baseline?: { status: number; bodySnippet: string; length: number; headers?: Record<string, string> };
  mutated?: { status: number; bodySnippet: string; length: number; headers?: Record<string, string> };
  deterministicProof?: boolean;
  proofType?: string;
  cveIds?: string[];
}

export interface ConfirmResult {
  confirmed: boolean;
  confidence: number; // 0-100
  reasoning: string;
  honeypot: boolean;
  honeypotReason?: string;
  proofType: string; // e.g. "sql_error", "template_eval", "honeypot_trap", "no_proof"
  recommendedAction: "insert_finding" | "insert_approval" | "drop_false_positive" | "drop_honeypot";
}

// ─── Honeypot detector (heuristic, runs before AI to save tokens) ────
export function detectHoneypot(bundle: ProofBundle): { isHoneypot: boolean; reason?: string } {
  const allText = [
    bundle.baseline?.bodySnippet || "",
    bundle.mutated?.bodySnippet || "",
    JSON.stringify(bundle.baseline?.headers || {}),
    JSON.stringify(bundle.mutated?.headers || {}),
  ].join("\n");

  for (const rx of HONEYPOT_SIGNATURES) {
    const m = allText.match(rx);
    if (m) return { isHoneypot: true, reason: `honeypot signature matched: ${m[0].slice(0, 60)}` };
  }

  // Trap: responses are byte-identical regardless of payload but contain
  // "vulnerability-like" markers — classic Glastopf-style decoy.
  if (bundle.baseline && bundle.mutated) {
    const sameLen = Math.abs(bundle.baseline.length - bundle.mutated.length) < 8;
    const sameStatus = bundle.baseline.status === bundle.mutated.status;
    if (sameLen && sameStatus && bundle.deterministicProof) {
      // proof claimed but body unchanged from baseline → trap
      return { isHoneypot: true, reason: "claimed proof but baseline/mutated bodies are identical (decoy)" };
    }
  }

  // Trap: server reflects every payload (always echoes well-known XSS/SQLi strings)
  const mutatedBody = bundle.mutated?.bodySnippet || "";
  const reflectedCount = ALWAYS_REFLECT_MARKERS.filter((m) => mutatedBody.includes(m)).length;
  if (reflectedCount >= 2) {
    return { isHoneypot: true, reason: "server reflects multiple canonical attack strings — honeypot trap" };
  }

  return { isHoneypot: false };
}

// ─── AI confirmation via Lovable AI Gateway ──────────────────────────
async function aiConfirm(
  bundle: ProofBundle,
  honeypot: boolean,
): Promise<{ confidence: number; reasoning: string; proofType: string }> {
  if (!LOVABLE_API_KEY) {
    return { confidence: 0, reasoning: "AI gateway unavailable — defaulting to drop", proofType: "no_ai" };
  }

  const prompt = `You are a senior offensive-security engineer. Confirm whether this is a TRUE vulnerability or a FALSE POSITIVE.

DO NOT confirm based on response status codes alone. Require deterministic proof:
- SQL error strings, command output markers, template evaluation results, file leaks, reflected XSS sinks, or unique CVE artefacts.
- Compare baseline vs mutated. If both look the same, it's a false positive.
- If the response looks like a honeypot trap (generic "vulnerable" message, identical body for all payloads, suspicious banners), reject.

Finding:
- Vuln Class: ${bundle.vulnClass}
- Payload: ${bundle.payload?.slice(0, 200)}
- Endpoint: ${bundle.endpoint}
- Parameter: ${bundle.parameter || "n/a"}
- Heuristic proof claimed: ${bundle.deterministicProof ? "yes" : "no"} (type: ${bundle.proofType || "none"})
- Honeypot pre-flag: ${honeypot ? "YES — likely trap" : "no"}
- CVE refs: ${(bundle.cveIds || []).join(", ") || "none"}

Baseline (status ${bundle.baseline?.status}, ${bundle.baseline?.length}b): ${(bundle.baseline?.bodySnippet || "").slice(0, 600)}
Mutated  (status ${bundle.mutated?.status}, ${bundle.mutated?.length}b): ${(bundle.mutated?.bodySnippet || "").slice(0, 600)}

Return your verdict via the tool.`;

  try {
    const resp = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${LOVABLE_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "google/gemini-2.5-flash",
        messages: [
          {
            role: "system",
            content: "Strict bug-bounty triage. No guesses. Status-code-only signals = false positive.",
          },
          { role: "user", content: prompt },
        ],
        tools: [
          {
            type: "function",
            function: {
              name: "confirm_vuln",
              description: "Confirm or reject the vulnerability finding",
              parameters: {
                type: "object",
                properties: {
                  confidence: { type: "number", description: "0-100 confidence this is a real exploitable vuln" },
                  reasoning: { type: "string", description: "Specific reason — cite proof string or absence" },
                  proofType: {
                    type: "string",
                    description:
                      "e.g. sql_error, template_eval, command_output, file_leak, reflected_sink, honeypot_trap, no_proof",
                  },
                },
                required: ["confidence", "reasoning", "proofType"],
                additionalProperties: false,
              },
            },
          },
        ],
        tool_choice: { type: "function", function: { name: "confirm_vuln" } },
      }),
      signal: AbortSignal.timeout(15000),
    });

    if (!resp.ok) {
      return { confidence: 0, reasoning: `AI gateway returned ${resp.status}`, proofType: "ai_error" };
    }
    const data = await resp.json();
    const tool = data.choices?.[0]?.message?.tool_calls?.[0];
    if (!tool) return { confidence: 0, reasoning: "AI returned no tool-call", proofType: "ai_no_output" };
    const parsed = JSON.parse(tool.function.arguments);
    return {
      confidence: Number(parsed.confidence) || 0,
      reasoning: String(parsed.reasoning || ""),
      proofType: String(parsed.proofType || "unknown"),
    };
  } catch (e) {
    return {
      confidence: 0,
      reasoning: `AI confirm failed: ${e instanceof Error ? e.message : "err"}`,
      proofType: "ai_exception",
    };
  }
}

// ─── Public: confirm a finding before insert ─────────────────────────
export async function confirmFinding(bundle: ProofBundle): Promise<ConfirmResult> {
  // Step 1: Honeypot trap detection
  const hp = detectHoneypot(bundle);
  if (hp.isHoneypot) {
    return {
      confirmed: false,
      confidence: 0,
      reasoning: `Honeypot/decoy trap detected — ${hp.reason}. Finding suppressed.`,
      honeypot: true,
      honeypotReason: hp.reason,
      proofType: "honeypot_trap",
      recommendedAction: "drop_honeypot",
    };
  }

  // Step 2: Bare status-code findings without deterministic proof are dropped immediately.
  // (the user explicitly: "bugs should not be displayed only on basis of response code")
  if (!bundle.deterministicProof && (!bundle.proofType || bundle.proofType === "none")) {
    return {
      confirmed: false,
      confidence: 0,
      reasoning: "No deterministic proof — status-code-only signals are not accepted.",
      honeypot: false,
      proofType: "no_proof",
      recommendedAction: "drop_false_positive",
    };
  }

  // Step 3: AI confirmation
  const ai = await aiConfirm(bundle, false);

  // ── Deterministic-proof fallback ──────────────────────────────────
  // If the AI gateway is unavailable/exhausted/erroring, do NOT silently
  // drop a finding that already has strong heuristic/deterministic proof
  // (e.g. AWS IMDS leak, SQL error string, SSTI evaluation result — proof
  // types supplied by callers like zeroday-engine that already diffed
  // baseline vs mutated before calling this gate). Route it to manual
  // review instead of discarding it outright, so AI-credit exhaustion
  // (which happens mid-scan routinely) doesn't erase real signals.
  const aiUnavailable = ["no_ai", "ai_error", "ai_no_output", "ai_exception"].includes(ai.proofType);
  if (aiUnavailable && bundle.deterministicProof && bundle.proofType && bundle.proofType !== "none") {
    return {
      confirmed: false,
      confidence: 70,
      reasoning: `AI gateway unavailable (${ai.proofType}) — falling back to deterministic proof "${bundle.proofType}" supplied by caller. Routed to manual review, not auto-confirmed.`,
      honeypot: false,
      proofType: bundle.proofType,
      recommendedAction: "insert_approval",
    };
  }

  const confirmed = ai.confidence >= 85;
  let action: ConfirmResult["recommendedAction"];
  if (ai.confidence >= 90) action = "insert_finding";
  else if (ai.confidence >= 70) action = "insert_approval";
  else action = "drop_false_positive";

  return {
    confirmed,
    confidence: ai.confidence,
    reasoning: ai.reasoning,
    honeypot: false,
    proofType: ai.proofType,
    recommendedAction: action,
  };
}
