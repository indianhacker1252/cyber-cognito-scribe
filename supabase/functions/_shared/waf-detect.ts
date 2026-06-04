// WAF detection + adaptive backoff + payload encoding variants.
// Used by template-runner and other scanners to behave "slow" once a WAF is
// detected, and to retry the same logical payload through several encodings.
import { safeFetch, readBodySafe } from "./safe-fetch.ts";

export interface WafSignal {
  detected: boolean;
  vendor: string | null;
  status: number;
  evidence: string[];
}

const WAF_HEADERS: Array<[string, string]> = [
  ["cf-ray", "Cloudflare"],
  ["x-sucuri-id", "Sucuri"],
  ["x-akamai-transformed", "Akamai"],
  ["x-aws-waf", "AWS WAF"],
  ["x-azure-ref", "Azure Front Door"],
  ["x-cdn", "CDN"],
  ["server", ""], // inspected below
];

const WAF_BODY_PATTERNS: Array<[RegExp, string]> = [
  [/cloudflare/i, "Cloudflare"],
  [/access denied.{0,40}akamai/i, "Akamai"],
  [/blocked by.{0,30}imperva/i, "Imperva"],
  [/incapsula/i, "Imperva Incapsula"],
  [/request blocked.{0,40}aws/i, "AWS WAF"],
  [/sucuri website firewall/i, "Sucuri"],
  [/mod_security|modsecurity/i, "ModSecurity"],
  [/F5 .{0,10}BIG-?IP/i, "F5 BIG-IP"],
  [/blocked by .* waf/i, "Generic WAF"],
];

export async function detectWaf(url: string): Promise<WafSignal> {
  const evidence: string[] = [];
  let vendor: string | null = null;
  let status = 0;
  try {
    const r = await safeFetch(url, { method: "GET" }, 6000);
    status = r.status;
    r.headers.forEach((v, k) => {
      for (const [h, name] of WAF_HEADERS) {
        if (k.toLowerCase() === h) {
          if (h === "server") {
            const lv = v.toLowerCase();
            if (lv.includes("cloudflare")) { vendor ??= "Cloudflare"; evidence.push(`server:${v}`); }
            else if (lv.includes("akamai")) { vendor ??= "Akamai"; evidence.push(`server:${v}`); }
            else if (lv.includes("bigip")) { vendor ??= "F5 BIG-IP"; evidence.push(`server:${v}`); }
          } else { vendor ??= name; evidence.push(`${h}:${v.slice(0, 60)}`); }
        }
      }
    });
    const body = await readBodySafe(r, 8192);
    for (const [re, name] of WAF_BODY_PATTERNS) {
      if (re.test(body)) { vendor ??= name; evidence.push(`body~${name}`); break; }
    }
    // Probe with an obviously malicious string and watch for 403/406/429/501
    const probeUrl = url + (url.includes("?") ? "&" : "?") + `q=${encodeURIComponent("<script>alert(1)</script>' OR 1=1--")}`;
    const pr = await safeFetch(probeUrl, { method: "GET" }, 6000);
    if ([403, 406, 419, 429, 451, 501].includes(pr.status)) {
      evidence.push(`probe_status:${pr.status}`);
      vendor ??= "Generic WAF";
    }
  } catch (e) {
    evidence.push(`err:${e instanceof Error ? e.message : "x"}`);
  }
  return { detected: !!vendor, vendor, status, evidence };
}

// Polite delay generator — once a WAF is detected the scanner should slow down.
export class AdaptiveThrottle {
  private base: number;
  private blocked = 0;
  constructor(wafDetected: boolean) {
    this.base = wafDetected ? 1500 : 200;
  }
  async wait() {
    const jitter = Math.floor(Math.random() * 300);
    const delay = this.base + jitter + this.blocked * 400;
    await new Promise((r) => setTimeout(r, Math.min(delay, 5000)));
  }
  noteBlock() { this.blocked = Math.min(this.blocked + 1, 6); }
  noteOk() { this.blocked = Math.max(0, this.blocked - 1); }
}

// Encoding variants for a payload. Returns up to N unique strings.
export function encodingVariants(payload: string, max = 12): string[] {
  const out = new Set<string>([payload]);
  out.add(encodeURIComponent(payload));
  out.add(payload.split("").map((c) => `%${c.charCodeAt(0).toString(16).padStart(2, "0")}`).join(""));
  out.add(payload.split("").map((c) => `%25${c.charCodeAt(0).toString(16).padStart(2, "0")}`).join("")); // double url
  out.add(payload.replace(/[<>'"]/g, (c) => `&#${c.charCodeAt(0)};`)); // html entity
  out.add(payload.split("").map((c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`).join("")); // unicode esc
  out.add(payload.replace(/\s+/g, "/**/")); // SQL comment whitespace
  // Mixed case
  out.add(payload.split("").map((c, i) => i % 2 ? c.toUpperCase() : c.toLowerCase()).join(""));
  return Array.from(out).slice(0, max);
}

// Strict reflected-XSS check used by tests + template runner.
// Rejects when the payload only appears HTML-entity-escaped or attribute-encoded.
export function isStrictXssReflection(body: string, payload: string): boolean {
  if (!body || !payload) return false;
  const escaped = payload.replace(/[<>'"&]/g, (c) =>
    ({ "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;", "&": "&amp;" }[c] as string));
  // If payload only appears in escaped form, NOT a reflection
  const rawIdx = body.indexOf(payload);
  if (rawIdx === -1) return false;
  const escIdx = body.indexOf(escaped);
  if (escIdx !== -1 && body.split(payload).length - 1 === body.split(escaped).length - 1) return false;
  // Reject reflections inside attribute value with quoted boundaries
  const ctxStart = Math.max(0, rawIdx - 8);
  const ctxEnd = Math.min(body.length, rawIdx + payload.length + 8);
  const ctx = body.slice(ctxStart, ctxEnd);
  if (/=\s*"[^"]*$/.test(body.slice(ctxStart, rawIdx)) && /^[^"]*"/.test(body.slice(rawIdx + payload.length, ctxEnd))) {
    // inside attribute and the payload has no unescaped quote → not exploitable
    if (!/["><]/.test(payload)) return false;
  }
  // Must contain at least one of the unescaped HTML control chars to actually fire
  return /[<>"']/.test(payload) && new RegExp(payload.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).test(ctx);
}
