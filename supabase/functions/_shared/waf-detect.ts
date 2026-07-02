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
            if (lv.includes("cloudflare")) {
              vendor ??= "Cloudflare";
              evidence.push(`server:${v}`);
            } else if (lv.includes("akamai")) {
              vendor ??= "Akamai";
              evidence.push(`server:${v}`);
            } else if (lv.includes("bigip")) {
              vendor ??= "F5 BIG-IP";
              evidence.push(`server:${v}`);
            }
          } else {
            vendor ??= name;
            evidence.push(`${h}:${v.slice(0, 60)}`);
          }
        }
      }
    });

    const body = await readBodySafe(r, 8192);
    for (const [re, name] of WAF_BODY_PATTERNS) {
      if (re.test(body)) {
        vendor ??= name;
        evidence.push(`body~${name}`);
        break;
      }
    }
    // ADD active WAF detection by sending a known-bad payload:
    export async function detectWafActive(url: string): Promise<WafSignal> {
      // First try passive
      const passive = await detectWaf(url);
      if (passive.detected) return passive;

      // Send a clearly malicious probe — WAF will block and reveal itself
      const probeUrl = `${url}${url.includes("?") ? "&" : "?"}waf_probe=<script>alert(1)</script>&id=1' OR '1'='1`;
      try {
        const r = await safeFetch(probeUrl, { method: "GET" }, 6000);
        const body = await readBodySafe(r, 8000);
        const evidence: string[] = [];
        let vendor: string | null = null;

        // Check headers on blocked response
        r.headers.forEach((v, k) => {
          if (k.toLowerCase() === "x-akamai-transformed") {
            vendor ??= "Akamai";
            evidence.push("x-akamai-transformed on block");
          }
          if (k.toLowerCase() === "server" && v.toLowerCase().includes("akamai")) {
            vendor ??= "Akamai";
            evidence.push(`server:${v}`);
          }
        });

        // Check body patterns on 403/406/429 responses
        if (r.status === 403 || r.status === 406 || r.status === 429) {
          for (const [pat, name] of WAF_BODY_PATTERNS) {
            if (pat.test(body)) {
              vendor ??= name;
              evidence.push(`body-pattern:${name}`);
            }
          }
          // Generic block page heuristics
          if (!vendor && /request.{0,20}blocked|access.{0,20}denied|security.{0,20}violation/i.test(body)) {
            vendor = "Generic WAF";
            evidence.push(`block-page:${r.status}`);
          }
          // Akamai reference number pattern
          if (/Reference\s+#\d+\.\d+\.\d+/.test(body)) {
            vendor = "Akamai";
            evidence.push("Akamai reference number in block page");
          }
        }

        if (vendor) return { detected: true, vendor, status: r.status, evidence };
      } catch {
        /* ignore */
      }

      return passive;
    }
    // Probe with an obviously malicious string and watch for 403/406/429/501
    const probeUrl =
      url + (url.includes("?") ? "&" : "?") + `q=${encodeURIComponent("<script>alert(1)</script>' OR 1=1--")}`;
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
  noteBlock() {
    this.blocked = Math.min(this.blocked + 1, 6);
  }
  noteOk() {
    this.blocked = Math.max(0, this.blocked - 1);
  }
}

// Encoding variants for a payload. Returns up to N unique strings.
export function encodingVariants(payload: string, max = 12): string[] {
  const out = new Set<string>([payload]);
  out.add(encodeURIComponent(payload));
  out.add(
    payload
      .split("")
      .map((c) => `%${c.charCodeAt(0).toString(16).padStart(2, "0")}`)
      .join(""),
  );
  out.add(
    payload
      .split("")
      .map((c) => `%25${c.charCodeAt(0).toString(16).padStart(2, "0")}`)
      .join(""),
  ); // double url
  out.add(payload.replace(/[<>'"]/g, (c) => `&#${c.charCodeAt(0)};`)); // html entity
  out.add(
    payload
      .split("")
      .map((c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`)
      .join(""),
  ); // unicode esc
  out.add(payload.replace(/\s+/g, "/**/")); // SQL comment whitespace
  // Mixed case
  out.add(
    payload
      .split("")
      .map((c, i) => (i % 2 ? c.toUpperCase() : c.toLowerCase()))
      .join(""),
  );
  return Array.from(out).slice(0, max);
}

// Strict reflected-XSS check used by tests + template runner.
// Rejects when the payload only appears HTML-entity-escaped or attribute-encoded.
export function isStrictXssReflection(body: string, payload: string): boolean {
  if (!body || !payload) return false;
  const escaped = payload.replace(
    /[<>'"&]/g,
    (c) => ({ "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;", "&": "&amp;" })[c] as string,
  );
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

// ───── WAF Feedback Loop (Part C) ─────
// Observe consecutive responses and decide how strongly the next payload must mutate.
export type WafTier = "none" | "soft-block" | "hard-403" | "challenge";
export interface WafObservation {
  tier: WafTier;
  consecutive: number;
  vendor?: string;
  promptSuffix: string;
}
export class WafFeedback {
  private consecutive = 0;
  private vendor: string;
  constructor(vendor?: string) {
    this.vendor = vendor || "Unknown";
  }
  observe(prevStatus: number, newStatus: number, prevLen: number, newLen: number, body?: string): WafObservation {
    let tier: WafTier = "none";
    if (newStatus === 403 || newStatus === 406 || newStatus === 451) tier = "hard-403";
    else if (newStatus === 429 || newStatus === 503) tier = "soft-block";
    else if (body && /captcha|just a moment|cloudflare|attention required|challenge/i.test(body)) tier = "challenge";
    else if (prevStatus === 200 && newStatus >= 400) tier = "soft-block";
    else if (prevLen > 0 && Math.abs(newLen - prevLen) / Math.max(prevLen, 1) < 0.02 && newStatus >= 400)
      tier = "soft-block";
    if (tier === "none") this.consecutive = 0;
    else this.consecutive++;
    return { tier, consecutive: this.consecutive, vendor: this.vendor, promptSuffix: this.buildSuffix(tier) };
  }
  reset() {
    this.consecutive = 0;
  }
  shouldSwitchToBypassCorpus() {
    return this.consecutive >= 2;
  }
  private buildSuffix(tier: WafTier): string {
    if (tier === "none") return "";
    return (
      `\n\n[WAF FEEDBACK] vendor=${this.vendor} tier=${tier} consecutive=${this.consecutive}.\n` +
      `The previous payload was blocked. For the next payload you MUST use one of: ` +
      `HTML-entity encoding, Unicode escape (\\u00XX), JS template literals, SVG event handlers ` +
      `(<svg/onload=...>, <math><mtext>), double-URL-encoding, comment splitting (/**/, <!---->), ` +
      `case-mixed keywords (ScRiPt), or chunked/fragmented body. ` +
      `DO NOT repeat literal <script>, onerror=, javascript:, OR 1=1. ` +
      `Generate a payload that defeats a ${this.vendor} WAF.`
    );
  }
}

// ── WAF Profile Loader ────────────────────────────────────────────────────
// Reads the bypass profile written by waf-evasion-engine into waf_profiles.
// Called by advanced-fuzzer, template-runner, and mythos-variant-gen BEFORE
// choosing payloads so they use proven bypass encodings instead of raw text
// that the WAF will silently block.
//
// Before this function existed, waf-evasion-engine correctly identified
// working bypass techniques and stored them in waf_profiles, but nothing
// ever read that table — every subsequent fuzzer still sent raw payloads
// into the same WAF that was blocking them.
export async function loadWafBypassProfile(
  supa: any,
  targetId: string,
): Promise<{ wafType: string; workingTechniques: string[]; hasProfile: boolean }> {
  try {
    const { data } = await supa
      .from("waf_profiles")
      .select("waf_type, working_techniques")
      .eq("target_id", targetId)
      .maybeSingle();
    if (!data) return { wafType: "none", workingTechniques: [], hasProfile: false };
    const working = (data.working_techniques || [])
      .map((t: any) => (typeof t === "string" ? t : t.technique || ""))
      .filter(Boolean);
    return { wafType: data.waf_type || "none", workingTechniques: working, hasProfile: working.length > 0 };
  } catch {
    return { wafType: "none", workingTechniques: [], hasProfile: false };
  }
}

// Apply a WAF bypass technique to a raw payload string.
// Returns the encoded variant, or the original if the technique is unknown.
export function applyWafBypass(payload: string, technique: string): string {
  switch (technique) {
    case "url_double_encode":
      return encodeURIComponent(encodeURIComponent(payload));
    case "url_single_encode":
      return encodeURIComponent(payload);
    case "mixed_case":
      return payload
        .split("")
        .map((c, i) => (i % 2 ? c.toUpperCase() : c.toLowerCase()))
        .join("");
    case "comment_break":
      return payload
        .replace(/select/gi, "sel/**/ect")
        .replace(/union/gi, "un/**/ion")
        .replace(/script/gi, "scr/**/ipt");
    case "tab_sep":
      return payload.replace(/ /g, "\t");
    case "newline_sep":
      return payload.replace(/ /g, "%0a");
    case "unicode_quote":
      return payload.replace(/'/g, "\u2018").replace(/"/g, "\u201c");
    case "null_byte":
      return payload + "%00";
    case "trailing_dot":
      return payload + ".";
    default:
      return payload;
  }
}
