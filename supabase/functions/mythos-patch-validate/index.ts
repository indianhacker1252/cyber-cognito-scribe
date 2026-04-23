// Static checks on AI-generated patch diffs before saving.
// Heuristic syntax/lint scoring + risk threshold gate.
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

interface Validation {
  syntax_ok: boolean;
  lint_warnings: string[];
  risk_factors: string[];
  risk_score: number; // 0=safe, 100=dangerous
  notes: string;
}

function staticCheckDiff(diff: string, language: string): Validation {
  const warnings: string[] = [];
  const risks: string[] = [];
  let risk = 30;
  let syntaxOk = true;

  if (!diff || diff.trim().length < 10) {
    return { syntax_ok: false, lint_warnings: ["empty or trivially short patch"], risk_factors: ["no-content"], risk_score: 100, notes: "Patch is empty/trivial" };
  }

  // Balanced braces / parens (rough check)
  const bal = (open: string, close: string) => {
    const o = (diff.match(new RegExp("\\" + open, "g")) || []).length;
    const c = (diff.match(new RegExp("\\" + close, "g")) || []).length;
    return Math.abs(o - c);
  };
  const braceDiff = bal("{", "}");
  const parenDiff = bal("(", ")");
  const bracketDiff = bal("[", "]");
  if (braceDiff > 1) { warnings.push(`unbalanced braces (Δ=${braceDiff})`); syntaxOk = false; risk += 15; }
  if (parenDiff > 2) { warnings.push(`unbalanced parens (Δ=${parenDiff})`); syntaxOk = false; risk += 10; }
  if (bracketDiff > 1) { warnings.push(`unbalanced brackets (Δ=${bracketDiff})`); risk += 5; }

  // Dangerous patterns the patch should NOT introduce
  const dangerPatterns: { re: RegExp; label: string; weight: number }[] = [
    { re: /eval\s*\(/i, label: "introduces eval()", weight: 30 },
    { re: /exec\s*\(/i, label: "introduces exec()", weight: 25 },
    { re: /\bsystem\s*\(/i, label: "introduces system()", weight: 25 },
    { re: /child_process|spawn\s*\(/i, label: "spawns subprocess", weight: 20 },
    { re: /innerHTML\s*=/i, label: "uses innerHTML (XSS risk)", weight: 15 },
    { re: /document\.write/i, label: "uses document.write", weight: 15 },
    { re: /SELECT\s+\*\s+FROM.*\$\{|`.*\$\{.*`.*query|f["'].*SELECT.*\{/i, label: "string-interpolated SQL", weight: 30 },
    { re: /password\s*=\s*["'][^"']+["']/i, label: "hardcoded credential", weight: 20 },
    { re: /\.\.\//, label: "path traversal sequence", weight: 10 },
    { re: /TODO|FIXME|XXX/i, label: "incomplete code marker", weight: 5 },
  ];
  for (const p of dangerPatterns) {
    if (p.re.test(diff)) {
      risks.push(p.label);
      risk += p.weight;
    }
  }

  // Positive signals (lower risk)
  const goodPatterns: { re: RegExp; label: string; weight: number }[] = [
    { re: /parameteriz|prepar(e|ed)\s+statement|placeholder|\?\s*,\s*\?/i, label: "uses parameterized query", weight: -15 },
    { re: /escape|sanitiz|encodeURI|escapeHtml|DOMPurify/i, label: "applies sanitization", weight: -10 },
    { re: /validator|joi|zod|yup|express-validator/i, label: "uses input validator", weight: -10 },
    { re: /helmet|csp|content-security-policy/i, label: "adds security header", weight: -8 },
    { re: /try\s*\{[^}]*catch/, label: "wraps in try/catch", weight: -3 },
  ];
  for (const p of goodPatterns) {
    if (p.re.test(diff)) {
      warnings.push(`✓ ${p.label}`);
      risk += p.weight;
    }
  }

  // Language-specific quick checks
  if (language === "javascript" || language === "typescript") {
    if (/\bvar\s+/.test(diff)) warnings.push("uses var (prefer const/let)");
    if (/console\.log/.test(diff)) warnings.push("contains console.log");
  } else if (language === "python") {
    // basic indentation sanity
    const lines = diff.split("\n").filter(l => l.trim() && !l.startsWith("+++") && !l.startsWith("---"));
    const tabsAndSpaces = lines.some(l => /^\+?\t/.test(l)) && lines.some(l => /^\+?    /.test(l));
    if (tabsAndSpaces) { warnings.push("mixed tabs/spaces"); syntaxOk = false; risk += 10; }
  } else if (language === "php") {
    if (!/<\?php/.test(diff) && diff.length > 100) warnings.push("missing <?php opener (may be partial)");
  }

  // Diff format sanity
  if (!/^[+\-@ ]/m.test(diff) && diff.length < 4000) {
    warnings.push("not in unified-diff format (treated as snippet)");
  }

  risk = Math.max(0, Math.min(100, risk));
  const notes = `${risks.length} risk factor(s), ${warnings.length} warning(s). Risk=${risk}/100 (${risk < 40 ? "LOW" : risk < 70 ? "MEDIUM" : "HIGH"}).`;

  return { syntax_ok: syntaxOk, lint_warnings: warnings, risk_factors: risks, risk_score: risk, notes };
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
  try {
    const { patchDiff, language = "javascript", patchId, findingId, targetId, threshold = 70 } = await req.json();
    if (!patchDiff || !targetId) throw new Error("patchDiff and targetId required");

    const v = staticCheckDiff(patchDiff, language);
    const passed = v.syntax_ok && v.risk_score <= threshold;

    const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
    const { data: row } = await db.from("patch_validations").insert({
      patch_id: patchId ?? null,
      finding_id: findingId ?? null,
      target_id: targetId,
      syntax_ok: v.syntax_ok,
      lint_warnings: v.lint_warnings,
      risk_score: v.risk_score,
      risk_factors: v.risk_factors,
      passed_threshold: passed,
      threshold_used: threshold,
      validator_notes: v.notes,
    }).select().single();

    // If a patch_id was passed, update its validation status
    if (patchId) {
      await db.from("mythos_patches").update({
        validation_status: passed ? "passed" : "failed",
        validation_id: row?.id ?? null,
        risk_score: v.risk_score,
      } as any).eq("id", patchId);
    }

    await db.from("scan_logs").insert({
      target_id: targetId,
      log_type: passed ? "result" : "error",
      message: `🛡️ Patch validation: ${passed ? "PASSED" : "FAILED"} (risk ${v.risk_score}/${threshold})`,
      metadata: { phase: "patch-validate", patch_id: patchId, validation_id: row?.id, risk_factors: v.risk_factors },
    });

    return new Response(JSON.stringify({ validationId: row?.id, passed, ...v }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (e) {
    console.error("patch-validate error:", e);
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : String(e) }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
