// Session jar — persistent per-target session state shared across sandbox-exec
// runs and exploit-engine mutation attempts. Stores cookies, custom headers,
// CSRF tokens, and JWTs harvested from prior responses so the next attempt
// behaves like a continuation of the same browser session.
//
// All updates are best-effort; failures never break the calling flow.

const SETCOOKIE_RX = /(?:^|;\s*)([^=;\s]+)=([^;]*)/;
const CSRF_META_RX = /<meta[^>]+name=["'](?:csrf-token|_csrf|csrf|xsrf-token)["'][^>]+content=["']([^"']+)["']/i;
const CSRF_INPUT_RX = /<input[^>]+name=["'](?:_token|authenticity_token|csrf_token|_csrf|csrfmiddlewaretoken)["'][^>]+value=["']([^"']+)["']/i;
const JWT_RX = /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b/;

export interface SessionJar {
  cookies: Record<string, string>;
  headers: Record<string, string>;
  csrf_token: string | null;
  jwt: string | null;
  last_url: string | null;
  hit_count: number;
}

export function emptyJar(): SessionJar {
  return { cookies: {}, headers: {}, csrf_token: null, jwt: null, last_url: null, hit_count: 0 };
}

export async function loadJar(supa: any, targetId: string, profile = "default"): Promise<SessionJar> {
  if (!targetId) return emptyJar();
  try {
    const { data } = await supa
      .from("session_jars")
      .select("cookies,headers,csrf_token,jwt,last_url,hit_count")
      .eq("target_id", targetId)
      .eq("profile_name", profile)
      .maybeSingle();
    if (!data) return emptyJar();
    return {
      cookies: (data.cookies as Record<string, string>) || {},
      headers: (data.headers as Record<string, string>) || {},
      csrf_token: data.csrf_token ?? null,
      jwt: data.jwt ?? null,
      last_url: data.last_url ?? null,
      hit_count: data.hit_count ?? 0,
    };
  } catch {
    return emptyJar();
  }
}

export function cookieHeader(jar: SessionJar): string {
  return Object.entries(jar.cookies)
    .map(([k, v]) => `${k}=${v}`)
    .join("; ");
}

/**
 * Apply jar state to a request that is about to be sent. Adds Cookie,
 * Authorization (Bearer JWT), and any sticky custom headers when not already
 * present in the caller's headers.
 */
export function applyJar(jar: SessionJar, headers: Record<string, string>): Record<string, string> {
  const out = { ...headers };
  const lower = Object.fromEntries(Object.keys(out).map((k) => [k.toLowerCase(), k]));
  if (!lower["cookie"] && Object.keys(jar.cookies).length > 0) {
    out["Cookie"] = cookieHeader(jar);
  }
  if (!lower["authorization"] && jar.jwt) {
    out["Authorization"] = `Bearer ${jar.jwt}`;
  }
  for (const [k, v] of Object.entries(jar.headers)) {
    if (!lower[k.toLowerCase()]) out[k] = v;
  }
  if (jar.csrf_token) {
    if (!lower["x-csrf-token"]) out["X-CSRF-Token"] = jar.csrf_token;
  }
  return out;
}

/**
 * Harvest cookies + tokens from a response and merge them into the jar.
 * Persists the merged jar back to Supabase.
 */
export async function harvestAndPersist(
  supa: any,
  targetId: string,
  profile: string,
  jar: SessionJar,
  resp: { headers: Headers; bodyText: string; url?: string },
): Promise<SessionJar> {
  if (!targetId) return jar;
  const merged: SessionJar = {
    cookies: { ...jar.cookies },
    headers: { ...jar.headers },
    csrf_token: jar.csrf_token,
    jwt: jar.jwt,
    last_url: resp.url || jar.last_url,
    hit_count: (jar.hit_count || 0) + 1,
  };

  // Set-Cookie ─ Deno exposes multiple values via getSetCookie()
  try {
    // @ts-ignore — getSetCookie is standard on modern runtimes
    const setCookies: string[] = typeof resp.headers.getSetCookie === "function"
      ? resp.headers.getSetCookie()
      : [resp.headers.get("set-cookie") || ""].filter(Boolean);
    for (const raw of setCookies) {
      const m = raw.match(SETCOOKIE_RX);
      if (m && m[1] && !/^(expires|path|domain|secure|httponly|samesite|max-age)$/i.test(m[1])) {
        merged.cookies[m[1]] = m[2];
      }
    }
  } catch { /* ignore */ }

  // CSRF token from HTML
  const html = resp.bodyText || "";
  const csrf = html.match(CSRF_META_RX)?.[1] || html.match(CSRF_INPUT_RX)?.[1] || null;
  if (csrf) merged.csrf_token = csrf;

  // JWT from JSON body / response headers
  const authH = resp.headers.get("authorization") || "";
  const authMatch = authH.match(JWT_RX)?.[0] || html.match(JWT_RX)?.[0] || null;
  if (authMatch) merged.jwt = authMatch;

  try {
    await supa.from("session_jars").upsert({
      target_id: targetId,
      profile_name: profile,
      cookies: merged.cookies,
      headers: merged.headers,
      csrf_token: merged.csrf_token,
      jwt: merged.jwt,
      last_url: merged.last_url,
      hit_count: merged.hit_count,
      updated_at: new Date().toISOString(),
    }, { onConflict: "target_id,profile_name" });
  } catch { /* best effort */ }

  return merged;
}
