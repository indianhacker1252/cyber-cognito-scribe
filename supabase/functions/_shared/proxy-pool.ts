// Proxy pool with Cloudflare/Akamai 403 auto-flip.
// Set PROXY_POOL secret as newline- or comma-separated list of
// http(s)://user:pass@host:port entries. Empty/missing = direct only.
import { safeFetch } from "./safe-fetch.ts";

const RAW = Deno.env.get("PROXY_POOL") || "";
const POOL: string[] = RAW.split(/[\s,]+/).map(s => s.trim()).filter(Boolean);

let cursor = 0;
function nextProxy(): string | null {
  if (!POOL.length) return null;
  const p = POOL[cursor % POOL.length];
  cursor++;
  return p;
}

const BLOCK_SIGNATURES = [
  /cloudflare/i, /just a moment/i, /attention required/i,
  /akamai/i, /access denied/i, /reference #\d+\.[a-f0-9]+/i,
];

function looksBlocked(status: number, body: string, headers: Headers): boolean {
  if (status === 403 || status === 429 || status === 503) {
    const server = (headers.get("server") || "") + " " + (headers.get("x-amz-cf-id") || "");
    if (/cloudflare|akamai|cloudfront/i.test(server)) return true;
    if (BLOCK_SIGNATURES.some(re => re.test(body.slice(0, 4096)))) return true;
  }
  if (status === 1020 as any) return true; // CF block code
  return false;
}

export interface SmartFetchOptions extends RequestInit {
  timeoutMs?: number;
  /** Force proxy use from first try */
  forceProxy?: boolean;
  /** Disable auto-flip (testing) */
  noFlip?: boolean;
}

export interface SmartFetchResult {
  response: Response;
  body: string;
  viaProxy: boolean;
  proxyUsed?: string;
  flipped: boolean;
}

/**
 * Fetch with WAF-aware proxy rotation. Direct first; on Cloudflare/Akamai
 * 403/429/503 signatures, retries through the next proxy in the pool.
 *
 * Deno's native fetch does not honor HTTP_PROXY, so we route the retry
 * through a configurable HTTP proxy gateway. For full SOCKS5/residential,
 * the user-supplied gateway must expose an HTTP CONNECT endpoint.
 */
export async function smartFetch(url: string, opts: SmartFetchOptions = {}): Promise<SmartFetchResult> {
  const timeoutMs = opts.timeoutMs ?? 8000;
  const noFlip = opts.noFlip ?? false;

  // First attempt: direct (or proxy if forced)
  let useProxy = opts.forceProxy && POOL.length > 0;
  let proxyUsed: string | undefined;
  let flipped = false;

  const doFetch = async (proxy: string | null): Promise<{ resp: Response; body: string }> => {
    if (!proxy) {
      const resp = await safeFetch(url, opts, timeoutMs);
      const body = await resp.clone().text().catch(() => "");
      return { resp, body };
    }
    // Route via proxy gateway. Expected gateway contract:
    //   POST {proxy}/fetch  { url, method, headers, body }
    //   -> { status, headers, body }
    try {
      const gwResp = await safeFetch(`${proxy.replace(/\/$/, "")}/fetch`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url,
          method: opts.method || "GET",
          headers: opts.headers || {},
          body: typeof opts.body === "string" ? opts.body : undefined,
        }),
      }, timeoutMs);
      const j = await gwResp.json().catch(() => ({ status: 502, headers: {}, body: "" }));
      const resp = new Response(j.body || "", {
        status: j.status || 502,
        headers: j.headers || {},
      });
      return { resp, body: j.body || "" };
    } catch (e) {
      const resp = new Response(String(e), { status: 599 });
      return { resp, body: "" };
    }
  };

  let proxy: string | null = useProxy ? (proxyUsed = nextProxy() || undefined) ?? null : null;
  let { resp, body } = await doFetch(proxy);

  if (!noFlip && !useProxy && POOL.length > 0 && looksBlocked(resp.status, body, resp.headers)) {
    flipped = true;
    proxyUsed = nextProxy() || undefined;
    ({ resp, body } = await doFetch(proxyUsed || null));
    useProxy = true;
  }

  return { response: resp, body, viaProxy: useProxy, proxyUsed, flipped };
}

export function proxyPoolStats() {
  return { configured: POOL.length, cursor };
}
