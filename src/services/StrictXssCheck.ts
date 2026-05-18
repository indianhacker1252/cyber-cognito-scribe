// Strict reflected-XSS check — shared by frontend triage + regression tests.
// Mirrors the logic in supabase/functions/_shared/waf-detect.ts so we can
// unit-test the rules that prevent benign `q=` reflections from being flagged
// as XSS findings.
export function isStrictXssReflection(body: string, payload: string): boolean {
  if (!body || !payload) return false;
  const escMap: Record<string, string> = { "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;", "&": "&amp;" };
  const escaped = payload.replace(/[<>'"&]/g, (c) => escMap[c]);
  const rawIdx = body.indexOf(payload);
  if (rawIdx === -1) return false;
  const escIdx = body.indexOf(escaped);
  if (escIdx !== -1 && body.split(payload).length - 1 === body.split(escaped).length - 1) return false;
  // Reflections inside a quoted attribute value with no quote-breaking chars → not exploitable
  if (/=\s*"[^"]*$/.test(body.slice(0, rawIdx)) && /^[^"]*"/.test(body.slice(rawIdx + payload.length))) {
    if (!/["><]/.test(payload)) return false;
  }
  // Payload must contain at least one HTML control char to actually fire
  return /[<>"']/.test(payload);
}
