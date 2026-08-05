// P5: multi-context auth — simple per-process cookie jars + header sets per (target, context name).
// Persisted to public.agent_auth_contexts so the runtime can pick up saved contexts across sessions.

import { db } from "./db.js";

type Jar = Record<string, string>; // host -> "k=v; k2=v2"
type Headers = Record<string, string>;

export type AuthContext = {
  name: string;
  jar: Jar;
  headers: Headers;
  user_hint?: string | null;
};

const cache = new Map<string, Map<string, AuthContext>>(); // targetId -> name -> ctx

function ctxKey(targetId: string) {
  if (!cache.has(targetId)) cache.set(targetId, new Map());
  return cache.get(targetId)!;
}

export async function loadContexts(targetId: string) {
  const { data } = await db
    .from("agent_auth_contexts")
    .select("name, cookie_jar, headers, user_hint")
    .eq("target_id", targetId);
  const map = ctxKey(targetId);
  for (const row of data ?? []) {
    map.set(row.name, {
      name: row.name,
      jar: (row.cookie_jar as Jar) ?? {},
      headers: (row.headers as Headers) ?? {},
      user_hint: row.user_hint ?? null,
    });
  }
  if (!map.has("anon")) map.set("anon", { name: "anon", jar: {}, headers: {} });
  return map;
}

export function getContext(targetId: string, name = "anon"): AuthContext {
  const map = ctxKey(targetId);
  return map.get(name) ?? { name: "anon", jar: {}, headers: {} };
}

export function setContext(targetId: string, ctx: AuthContext) {
  ctxKey(targetId).set(ctx.name, ctx);
}

export async function persistContext(targetId: string, ctx: AuthContext) {
  setContext(targetId, ctx);
  await db.from("agent_auth_contexts").upsert(
    {
      target_id: targetId,
      name: ctx.name,
      cookie_jar: ctx.jar,
      headers: ctx.headers,
      user_hint: ctx.user_hint ?? null,
      updated_at: new Date().toISOString(),
    },
    { onConflict: "target_id,name" },
  );
}

export function mergeSetCookies(jar: Jar, url: string, setCookieHeader: string | string[] | undefined) {
  if (!setCookieHeader) return;
  const host = new URL(url).host;
  const arr = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];
  const existing = parseCookieString(jar[host] ?? "");
  for (const raw of arr) {
    const [pair] = raw.split(";");
    if (!pair) continue;
    const eq = pair.indexOf("=");
    if (eq <= 0) continue;
    const k = pair.slice(0, eq).trim();
    const v = pair.slice(eq + 1).trim();
    existing[k] = v;
  }
  jar[host] = Object.entries(existing).map(([k, v]) => `${k}=${v}`).join("; ");
}

function parseCookieString(s: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of s.split(";")) {
    const eq = part.indexOf("=");
    if (eq <= 0) continue;
    out[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
  }
  return out;
}

export function cookieHeaderFor(jar: Jar, url: string): string | undefined {
  try {
    const host = new URL(url).host;
    return jar[host] || undefined;
  } catch { return undefined; }
}
