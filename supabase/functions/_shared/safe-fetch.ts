// Shared safeFetch with timeout + abort. All new attack modules reuse this
// to respect the 50s edge-function budget.
export async function safeFetch(
  url: string,
  opts: RequestInit = {},
  timeoutMs = 8000,
): Promise<Response> {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), timeoutMs);
  try {
    // Honor caller's redirect choice; default to "manual" so callers comparing
    // response bodies don't accidentally follow cross-host redirects.
    return await fetch(url, { redirect: "manual", ...opts, signal: ctl.signal });
  } finally {
    clearTimeout(t);
  }
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
