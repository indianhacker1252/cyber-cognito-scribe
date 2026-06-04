// Authenticated session helper.
// Resolves an auth_profile for a target into a ready-to-use header bag {Cookie, Authorization}.
// For login_replay type, performs the login POST and extracts session token via regex.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

function db() { return createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!); }

export async function resolveAuthHeaders(targetId: string): Promise<Record<string, string>> {
  const { data: profile } = await db().from("auth_profiles")
    .select("*").eq("target_id", targetId).eq("is_valid", true).limit(1).maybeSingle();
  if (!profile) return {};

  if (profile.auth_type === "cookie" && profile.cookie_header) {
    return { Cookie: profile.cookie_header };
  }
  if (profile.auth_type === "bearer" && profile.bearer_token) {
    return { Authorization: `Bearer ${profile.bearer_token}` };
  }
  if (profile.auth_type === "login_replay" && profile.login_url) {
    try {
      const body = (profile.login_body_template || "username={U}&password={P}")
        .replace("{U}", encodeURIComponent(profile.login_username || ""))
        .replace("{P}", encodeURIComponent(profile.login_password || ""));
      const r = await fetch(profile.login_url, {
        method: profile.login_method || "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body, redirect: "manual",
        signal: AbortSignal.timeout(8000),
      });
      const setCookie = r.headers.get("set-cookie") || "";
      const text = await r.text();
      // 1) Try regex extraction (e.g. token in JSON body)
      if (profile.session_extract_regex) {
        const re = new RegExp(profile.session_extract_regex);
        const m = text.match(re);
        if (m && m[1]) return { Authorization: `Bearer ${m[1]}` };
      }
      // 2) Fall back to set-cookie
      if (setCookie) {
        const cookies = setCookie.split(/,(?=\s*\w+=)/).map(c => c.split(";")[0].trim()).join("; ");
        await db().from("auth_profiles").update({
          cookie_header: cookies, last_validated_at: new Date().toISOString(),
        }).eq("id", profile.id);
        return { Cookie: cookies };
      }
    } catch (e) {
      await db().from("auth_profiles").update({ is_valid: false }).eq("id", profile.id);
    }
  }
  return {};
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  try {
    const { targetId, testUrl } = await req.json();
    const headers = await resolveAuthHeaders(targetId);
    let validation: any = { hasAuth: Object.keys(headers).length > 0 };
    if (testUrl) {
      try {
        const r = await fetch(testUrl, { headers, redirect: "manual", signal: AbortSignal.timeout(12000) });
        validation = { ...validation, status: r.status, ok: r.status < 400 };
      } catch (e) {
        validation = { ...validation, error: e instanceof Error ? e.message : "err" };
      }
    }
    return new Response(JSON.stringify({ headers, validation }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (e) {
    return new Response(JSON.stringify({ error: e instanceof Error ? e.message : "err" }), {
      status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
