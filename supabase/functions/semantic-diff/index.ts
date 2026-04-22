// Semantic differ — replaces byte-length heuristics with structural diffs.
// Compares two HTTP responses for: HTML DOM-shape diff, JSON-shape diff, error-class diff.
// Returns a confidence-weighted score 0-1 and human-readable reason.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

function db() {
  return createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
}

// ─── Shape extractors ────────────────────────────────────────────────────────
function htmlSkeleton(s: string): string {
  // Strip text + attribute values, keep tag tree
  return s.replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<(\w+)[^>]*>/g, "<$1>")
    .replace(/>[\s\S]*?</g, "><")
    .replace(/\s+/g, "")
    .slice(0, 8000);
}

function jsonShape(obj: unknown): string {
  if (obj === null) return "n";
  if (Array.isArray(obj)) return `[${obj.length > 0 ? jsonShape(obj[0]) : ""}]`;
  if (typeof obj === "object") {
    const keys = Object.keys(obj as object).sort();
    return `{${keys.map(k => `${k}:${jsonShape((obj as any)[k])}`).join(",")}}`;
  }
  return typeof obj === "string" ? "s" : typeof obj === "number" ? "#" : typeof obj === "boolean" ? "b" : "?";
}

const ERROR_CLASSES = {
  sql: [/SQL syntax/i, /SQLSTATE/i, /ORA-\d+/i, /pg_query/i, /unclosed quotation/i, /near ".*": syntax/i, /PDOException/i],
  template: [/jinja2\.exceptions/i, /freemarker\.core/i, /Twig\\Error/i, /Velocity.*Error/i],
  deserialization: [/ObjectInputStream/i, /unserialize\(\)/i, /pickle\.loads/i, /SerializationException/i],
  framework: [/Whitelabel Error/i, /Werkzeug Debugger/i, /Rails\.application/i, /\.NET Framework/i, /at System\./i],
  filesystem: [/ENOENT/i, /No such file or directory/i, /FileNotFoundException/i, /Permission denied/i],
  auth: [/JWT.*invalid/i, /401 Unauthorized/i, /Forbidden by ACL/i, /CSRF token/i],
};

function classifyErrors(s: string): string[] {
  const found: string[] = [];
  for (const [cls, patterns] of Object.entries(ERROR_CLASSES)) {
    if (patterns.some(p => p.test(s))) found.push(cls);
  }
  return found;
}

function levenshteinRatio(a: string, b: string): number {
  if (a === b) return 1;
  const maxLen = Math.max(a.length, b.length);
  if (maxLen === 0) return 1;
  // Sample-based for performance — compare 500 chars at midpoints
  const sample = (s: string) => s.length <= 500 ? s : s.slice(0, 250) + s.slice(-250);
  const sa = sample(a), sb = sample(b);
  const m: number[][] = Array(sa.length + 1).fill(0).map(() => Array(sb.length + 1).fill(0));
  for (let i = 0; i <= sa.length; i++) m[i][0] = i;
  for (let j = 0; j <= sb.length; j++) m[0][j] = j;
  for (let i = 1; i <= sa.length; i++) {
    for (let j = 1; j <= sb.length; j++) {
      m[i][j] = sa[i-1] === sb[j-1] ? m[i-1][j-1] : 1 + Math.min(m[i-1][j], m[i][j-1], m[i-1][j-1]);
    }
  }
  return 1 - m[sa.length][sb.length] / Math.max(sa.length, sb.length, 1);
}

function diff(controlBody: string, controlStatus: number, payloadBody: string, payloadStatus: number, contentType: string) {
  const reasons: string[] = [];
  let score = 0;

  // 1. Status divergence
  if (controlStatus !== payloadStatus) {
    score += 0.25;
    reasons.push(`status ${controlStatus}→${payloadStatus}`);
  }

  // 2. Error class divergence (high signal)
  const ctrlErrs = new Set(classifyErrors(controlBody));
  const payErrs = new Set(classifyErrors(payloadBody));
  const newErrs = [...payErrs].filter(e => !ctrlErrs.has(e));
  if (newErrs.length > 0) {
    score += 0.55;
    reasons.push(`new error class: ${newErrs.join(",")}`);
  }

  // 3. Structural diff
  const isJson = /json/i.test(contentType);
  if (isJson) {
    try {
      const cs = jsonShape(JSON.parse(controlBody));
      const ps = jsonShape(JSON.parse(payloadBody));
      if (cs !== ps) {
        score += 0.30;
        reasons.push(`JSON shape changed (${cs.length}b→${ps.length}b)`);
      }
    } catch {
      // One side isn't valid JSON when other is → big signal
      try { JSON.parse(controlBody); score += 0.40; reasons.push("response stopped being JSON"); } catch { /* both invalid */ }
    }
  } else {
    const cs = htmlSkeleton(controlBody);
    const ps = htmlSkeleton(payloadBody);
    const sim = levenshteinRatio(cs, ps);
    if (sim < 0.85) {
      score += 0.30 * (1 - sim);
      reasons.push(`DOM-skeleton similarity ${(sim*100).toFixed(0)}%`);
    }
  }

  // 4. Length sanity (low weight)
  const lenRatio = Math.abs(payloadBody.length - controlBody.length) / Math.max(controlBody.length, 1);
  if (lenRatio > 0.5) {
    score += 0.10;
    reasons.push(`body size ${(lenRatio*100).toFixed(0)}% delta`);
  }

  return { score: Math.min(score, 1), reasons, ctrlErrors: [...ctrlErrs], payErrors: [...payErrs] };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const { controlBody, controlStatus, controlContentType,
            payloadBody, payloadStatus, payloadContentType } = await req.json();
    const ct = payloadContentType || controlContentType || "text/html";
    const result = diff(
      String(controlBody || ""), Number(controlStatus) || 0,
      String(payloadBody || ""), Number(payloadStatus) || 0, ct
    );
    return new Response(JSON.stringify({
      ...result,
      verdict: result.score >= 0.6 ? "diverged" : result.score >= 0.3 ? "suspicious" : "equivalent",
    }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
  } catch (e) {
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : "err", score: 0, reasons: [] }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
