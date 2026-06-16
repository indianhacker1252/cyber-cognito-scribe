// Shared safeFetch + central httpClient. All edge functions MUST route outbound
// HTTP through here so WAF drops, rate-limits, and payload accounting are global.

type HostStat = { sent: number; blocked: number; throttled: number; errors: number; cooldownUntil: number };
const HOST_STATS = new Map<string, HostStat>();

function hostOf(u: string): string {
  try { return new URL(u).host; } catch { return "unknown"; }
}
function stat(host: string): HostStat {
  let s = HOST_STATS.get(host);
  if (!s) { s = { sent: 0, blocked: 0, throttled: 0, errors: 0, cooldownUntil: 0 }; HOST_STATS.set(host, s); }
  return s;
}

export function getHostStats(): Record<string, HostStat> {
  const out: Record<string, HostStat> = {};
  for (const [k, v] of HOST_STATS.entries()) out[k] = v;
  return out;
}

export class WafBlockedError extends Error {
  constructor(public host: string, public status: number) {
    super(`WAF block on ${host} (HTTP ${status})`);
    this.name = "WafBlockedError";
  }
}

export async function safeFetch(
  url: string,
  opts: RequestInit = {},
  timeoutMs = 8000,
): Promise<Response> {
  const host = hostOf(url);
  const s = stat(host);
  if (Date.now() < s.cooldownUntil) {
    // Honor cooldown: return a synthesized 429 instead of hammering.
    return new Response("local-cooldown", { status: 429, headers: { "x-cyberscope-cooldown": "1" } });
  }

  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    const r = await fetch(url, { redirect: "manual", ...opts, signal: ctl.signal });
    s.sent++;
    if (r.status === 429 || r.status === 503) {
      s.throttled++;
      // Exponential cooldown per host
      s.cooldownUntil = Date.now() + Math.min(30_000, 2000 * Math.pow(2, Math.min(4, s.throttled)));
    } else if (r.status === 403 || r.status === 406 || r.status === 419) {
      s.blocked++;
    }
    return r;
  } catch (e) {
    s.errors++;
    throw e;
  } finally {
    clearTimeout(t);
  }
}

/** Central client every module MUST use. Adds retry, WAF-aware backoff, UA. */
export async function httpClient(
  url: string,
  opts: RequestInit & { retries?: number; timeoutMs?: number; ua?: string } = {},
): Promise<Response> {
  const { retries = 1, timeoutMs = 8000, ua, ...rest } = opts;
  const headers = new Headers(rest.headers || {});
  if (!headers.has("User-Agent")) headers.set("User-Agent", ua || "CyberScope/1.0 (+scanner)");
  let last: Response | null = null;
  for (let i = 0; i <= retries; i++) {
    try {
      const r = await safeFetch(url, { ...rest, headers }, timeoutMs);
      last = r;
      if (r.status === 429 || r.status === 503) {
        await new Promise((res) => setTimeout(res, 500 * (i + 1)));
        continue;
      }
      return r;
    } catch (_e) {
      if (i === retries) throw _e;
      await new Promise((res) => setTimeout(res, 300 * (i + 1)));
    }
  }
  return last!;
}

export async function readBodySafe(resp: Response, maxBytes = 64 * 1024): Promise<string> {
  try {
    const text = await resp.text();
    return text.length > maxBytes ? text.slice(0, maxBytes) : text;
  } catch {
    return "";
  }
}

export function headersToObject(h: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  h.forEach((v, k) => { out[k] = v; });
  return out;
}
