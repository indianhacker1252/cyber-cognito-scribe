import { tool } from "ai";
import { z } from "zod";
import { request } from "undici";
import { chromium, type Browser } from "playwright";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { db, mergeWorldModel, emit, recordExperience, similarExperiences, metric } from "../db.js";
import { runOracle } from "../oracles.js";
import {
  loadContexts, getContext, persistContext, mergeSetCookies, cookieHeaderFor,
  type AuthContext,
} from "../authctx.js";

const pexec = promisify(execFile);

let sharedBrowser: Browser | null = null;
async function getBrowser() {
  if (!sharedBrowser) sharedBrowser = await chromium.launch({ headless: true, args: ["--no-sandbox"] });
  return sharedBrowser;
}
export async function closeBrowser() {
  if (sharedBrowser) { await sharedBrowser.close(); sharedBrowser = null; }
}

const SHELL_ALLOWLIST = new Set([
  "curl", "dig", "whois", "nmap", "jq", "host", "nslookup",
  "subfinder", "httpx", "dnsx", "naabu", "katana", "nuclei",
  "assetfinder", "waybackurls", "gau", "ffuf", "feroxbuster",
  "arjun", "gobuster", "wafw00f", "whatweb", "sslscan", "testssl.sh",
  "sqlmap", "dalfox", "commix", "wpscan",
]);

const INTERACTSH_URL = process.env.INTERACTSH_URL || "";

// Shared request helper honoring an auth context (cookies + headers).
async function httpRequestAs(opts: {
  ctx: AuthContext;
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  timeout_ms?: number;
  update_jar?: boolean;
}) {
  const timeout = opts.timeout_ms ?? 10000;
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeout);
  const cookieHeader = cookieHeaderFor(opts.ctx.jar, opts.url);
  const mergedHeaders: Record<string, string> = {
    ...(opts.ctx.headers ?? {}),
    ...(opts.headers ?? {}),
  };
  if (cookieHeader) mergedHeaders["cookie"] = cookieHeader;
  try {
    const res = await request(opts.url, {
      method: (opts.method ?? "GET") as any,
      headers: mergedHeaders,
      body: opts.body,
      signal: ac.signal,
      maxRedirections: 0,
    });
    const buf = await res.body.text();
    if (opts.update_jar !== false) {
      mergeSetCookies(opts.ctx.jar, opts.url, res.headers["set-cookie"] as any);
    }
    return {
      status: res.statusCode,
      headers: res.headers,
      body: buf.slice(0, 8192),
      truncated: buf.length > 8192,
    };
  } catch (e: any) {
    return { error: String(e?.message ?? e) };
  } finally { clearTimeout(t); }
}

export function buildTools(ctx: { sessionId: string; targetId: string }) {
  // Warm-load auth contexts once per session.
  loadContexts(ctx.targetId).catch(() => {});

  return {
    "http.request": tool({
      description: "Send an HTTP request. Optional `as` selects a saved auth context (cookies + headers). Returns status, headers, and body (8KB).",
      inputSchema: z.object({
        url: z.string().url(),
        method: z.enum(["GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD"]).default("GET"),
        headers: z.record(z.string(), z.string()).optional(),
        body: z.string().optional(),
        timeout_ms: z.number().int().min(500).max(30000).default(10000),
        as: z.string().default("anon"),
        update_jar: z.boolean().default(true),
      }),
      execute: async (a) => httpRequestAs({ ctx: getContext(ctx.targetId, a.as), ...a }),
    }),

    "browser.visit": tool({
      description: "Open URL in headless Chromium under a given auth context. Returns title, final URL, DOM snapshot, and console logs.",
      inputSchema: z.object({
        url: z.string().url(),
        wait_ms: z.number().int().min(0).max(15000).default(2000),
        as: z.string().default("anon"),
      }),
      execute: async ({ url, wait_ms, as }) => {
        const browser = await getBrowser();
        const authCtx = getContext(ctx.targetId, as);
        const context = await browser.newContext({ extraHTTPHeaders: authCtx.headers ?? {} });
        // Seed cookies from jar for this URL host.
        try {
          const host = new URL(url).host;
          const raw = authCtx.jar[host];
          if (raw) {
            const cookies = raw.split(";").map(s => s.trim()).filter(Boolean).map(kv => {
              const eq = kv.indexOf("="); const name = kv.slice(0, eq); const value = kv.slice(eq + 1);
              return { name, value, domain: host, path: "/" };
            });
            await context.addCookies(cookies as any);
          }
        } catch {}
        const page = await context.newPage();
        const consoleLogs: string[] = [];
        page.on("console", (m) => consoleLogs.push(`[${m.type()}] ${m.text()}`.slice(0, 500)));
        try {
          await page.goto(url, { waitUntil: "domcontentloaded", timeout: 20000 });
          await page.waitForTimeout(wait_ms);
          const title = await page.title();
          const finalUrl = page.url();
          const html = (await page.content()).slice(0, 16384);
          // Sync cookies back to jar.
          try {
            const cks = await context.cookies();
            for (const c of cks) {
              mergeSetCookies(authCtx.jar, `https://${c.domain.replace(/^\./, "")}${c.path || "/"}`, `${c.name}=${c.value}`);
            }
          } catch {}
          return { title, finalUrl, html, console: consoleLogs.slice(0, 40) };
        } catch (e: any) {
          return { error: String(e?.message ?? e), console: consoleLogs.slice(0, 40) };
        } finally { await context.close(); }
      },
    }),

    "browser.exec_js": tool({
      description: "Load URL, execute a JS expression in-page, return its serialized result. Use for DOM XSS / proto pollution proofs.",
      inputSchema: z.object({ url: z.string().url(), expression: z.string().min(1).max(4096), as: z.string().default("anon") }),
      execute: async ({ url, expression, as }) => {
        const browser = await getBrowser();
        const authCtx = getContext(ctx.targetId, as);
        const context = await browser.newContext({ extraHTTPHeaders: authCtx.headers ?? {} });
        const page = await context.newPage();
        try {
          await page.goto(url, { waitUntil: "domcontentloaded", timeout: 20000 });
          const result = await page.evaluate(expression);
          return { ok: true, result };
        } catch (e: any) {
          return { ok: false, error: String(e?.message ?? e) };
        } finally { await context.close(); }
      },
    }),

    "shell.run": tool({
      description: "Run one allowlisted CLI (subfinder, httpx, nuclei, nmap, curl, ...). Returns stdout/stderr.",
      inputSchema: z.object({
        bin: z.string(),
        args: z.array(z.string()).max(30),
        timeout_ms: z.number().int().min(500).max(30000).default(10000),
      }),
      execute: async ({ bin, args, timeout_ms }) => {
        if (!SHELL_ALLOWLIST.has(bin)) return { error: `bin '${bin}' not allowlisted` };
        try {
          const { stdout, stderr } = await pexec(bin, args, { timeout: timeout_ms, maxBuffer: 1024 * 128 });
          return { stdout: stdout.slice(0, 8192), stderr: stderr.slice(0, 2048) };
        } catch (e: any) {
          return { error: String(e?.message ?? e), stdout: e?.stdout?.slice?.(0, 4096), stderr: e?.stderr?.slice?.(0, 2048) };
        }
      },
    }),

    "memory.write": tool({
      description: "Persist facts learned about the target into the world model (tech stack, endpoints, beliefs, attempts).",
      inputSchema: z.object({ patch: z.record(z.string(), z.any()) }),
      execute: async ({ patch }) => { await mergeWorldModel(ctx.targetId, patch); return { ok: true }; },
    }),

    // ---------------- P3: structured endpoint memory ----------------
    "endpoints.upsert": tool({
      description: "Insert or refresh one or many discovered endpoints (url, method, params, auth_required, tech_tags, source). Deduped on (target, method, url).",
      inputSchema: z.object({
        endpoints: z.array(z.object({
          url: z.string(),
          method: z.string().default("GET"),
          status: z.number().int().optional(),
          content_type: z.string().optional(),
          params: z.array(z.any()).default([]),
          auth_required: z.boolean().default(false),
          tech_tags: z.array(z.string()).default([]),
          source: z.string().default("agent"),
        })).min(1).max(200),
      }),
      execute: async ({ endpoints }) => {
        const rows = endpoints.map(e => ({
          target_id: ctx.targetId,
          url: e.url, method: e.method.toUpperCase(),
          status: e.status ?? null,
          content_type: e.content_type ?? null,
          params: e.params, auth_required: e.auth_required,
          tech_tags: e.tech_tags, source: e.source,
          last_seen_at: new Date().toISOString(),
        }));
        const { error, count } = await db.from("endpoint_catalog")
          .upsert(rows, { onConflict: "target_id,method,url", count: "exact" });
        return error ? { ok: false, error: error.message } : { ok: true, count: count ?? rows.length };
      },
    }),

    "endpoints.list": tool({
      description: "List catalogued endpoints for the target. Filter by method/tech/auth. Use to pick the next attack surface.",
      inputSchema: z.object({
        method: z.string().optional(),
        auth_required: z.boolean().optional(),
        contains: z.string().optional(),
        limit: z.number().int().min(1).max(200).default(50),
      }),
      execute: async ({ method, auth_required, contains, limit }) => {
        let q = db.from("endpoint_catalog").select("url,method,status,params,auth_required,tech_tags,source,last_seen_at").eq("target_id", ctx.targetId);
        if (method) q = q.eq("method", method.toUpperCase());
        if (typeof auth_required === "boolean") q = q.eq("auth_required", auth_required);
        if (contains) q = q.ilike("url", `%${contains}%`);
        const { data, error } = await q.order("last_seen_at", { ascending: false }).limit(limit);
        return error ? { ok: false, error: error.message } : { ok: true, count: data?.length ?? 0, endpoints: data ?? [] };
      },
    }),

    "notes.write": tool({
      description: "Persist a durable note (hypothesis, dead-end, gotcha, credential hint) so future sessions inherit context.",
      inputSchema: z.object({
        topic: z.string(),
        body: z.string(),
        tags: z.array(z.string()).default([]),
        importance: z.number().int().min(1).max(5).default(2),
      }),
      execute: async (n) => {
        const { error } = await db.from("agent_notes").insert({
          target_id: ctx.targetId, session_id: ctx.sessionId,
          topic: n.topic, body: n.body, tags: n.tags, importance: n.importance,
        });
        return error ? { ok: false, error: error.message } : { ok: true };
      },
    }),

    "notes.search": tool({
      description: "Search agent notes by topic keyword. Use at session start to load prior hypotheses.",
      inputSchema: z.object({ query: z.string().default(""), limit: z.number().int().min(1).max(50).default(20) }),
      execute: async ({ query, limit }) => {
        let q = db.from("agent_notes").select("topic,body,tags,importance,created_at").eq("target_id", ctx.targetId);
        if (query) q = q.or(`topic.ilike.%${query}%,body.ilike.%${query}%`);
        const { data, error } = await q.order("importance", { ascending: false }).order("created_at", { ascending: false }).limit(limit);
        return error ? { ok: false, error: error.message } : { ok: true, notes: data ?? [] };
      },
    }),

    // ---------------- P5: multi-context auth ----------------
    "auth.login_form": tool({
      description: "Log in via an HTML form and save cookies/headers as a named auth context. Use for user/admin roles in IDOR/BAC tests.",
      inputSchema: z.object({
        context_name: z.string(),
        login_url: z.string().url(),
        username_selector: z.string().default('input[name="username"], input[name="email"], input[type="email"]'),
        password_selector: z.string().default('input[name="password"], input[type="password"]'),
        submit_selector: z.string().default('button[type="submit"], input[type="submit"]'),
        username: z.string(),
        password: z.string(),
        user_hint: z.string().optional(),
      }),
      execute: async (a) => {
        const browser = await getBrowser();
        const bctx = await browser.newContext();
        const page = await bctx.newPage();
        try {
          await page.goto(a.login_url, { waitUntil: "domcontentloaded", timeout: 20000 });
          await page.fill(a.username_selector, a.username);
          await page.fill(a.password_selector, a.password);
          await Promise.all([
            page.waitForLoadState("domcontentloaded").catch(() => {}),
            page.click(a.submit_selector),
          ]);
          await page.waitForTimeout(1500);
          const cookies = await bctx.cookies();
          const jar: Record<string, string> = {};
          for (const c of cookies) {
            const host = c.domain.replace(/^\./, "");
            const existing = jar[host] ? jar[host] + "; " : "";
            jar[host] = `${existing}${c.name}=${c.value}`;
          }
          const authCtx = { name: a.context_name, jar, headers: {}, user_hint: a.user_hint ?? a.username };
          await persistContext(ctx.targetId, authCtx);
          return { ok: true, context: a.context_name, cookies: cookies.length, final_url: page.url() };
        } catch (e: any) {
          return { ok: false, error: String(e?.message ?? e) };
        } finally { await bctx.close(); }
      },
    }),

    "auth.set_bearer": tool({
      description: "Store a bearer token / API key as a named auth context (Authorization: Bearer ...).",
      inputSchema: z.object({
        context_name: z.string(),
        token: z.string(),
        header_name: z.string().default("authorization"),
        header_prefix: z.string().default("Bearer "),
        user_hint: z.string().optional(),
      }),
      execute: async (a) => {
        const headers: Record<string, string> = {};
        headers[a.header_name.toLowerCase()] = `${a.header_prefix}${a.token}`;
        await persistContext(ctx.targetId, { name: a.context_name, jar: {}, headers, user_hint: a.user_hint ?? null });
        return { ok: true, context: a.context_name };
      },
    }),

    "auth.list_contexts": tool({
      description: "List saved auth contexts for this target with cookie/header counts. Use before IDOR/BAC testing.",
      inputSchema: z.object({}),
      execute: async () => {
        const map = await loadContexts(ctx.targetId);
        return {
          contexts: Array.from(map.values()).map(c => ({
            name: c.name,
            hosts: Object.keys(c.jar).length,
            headers: Object.keys(c.headers ?? {}).length,
            user_hint: c.user_hint ?? null,
          })),
        };
      },
    }),

    "auth.compare": tool({
      description: "Send the same request under two auth contexts (e.g. 'anon' vs 'user' vs 'admin') and diff status/length/body-hash. Core primitive for IDOR / broken-access-control proofs. Returns diff summary + both responses (truncated).",
      inputSchema: z.object({
        url: z.string().url(),
        method: z.enum(["GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD"]).default("GET"),
        headers: z.record(z.string(), z.string()).optional(),
        body: z.string().optional(),
        as_a: z.string().default("anon"),
        as_b: z.string(),
        timeout_ms: z.number().int().min(500).max(30000).default(10000),
      }),
      execute: async (a) => {
        const ctxA = getContext(ctx.targetId, a.as_a);
        const ctxB = getContext(ctx.targetId, a.as_b);
        const common = { url: a.url, method: a.method, headers: a.headers, body: a.body, timeout_ms: a.timeout_ms, update_jar: false };
        const [rA, rB] = await Promise.all([
          httpRequestAs({ ctx: ctxA, ...common }),
          httpRequestAs({ ctx: ctxB, ...common }),
        ]);
        if ("error" in rA || "error" in rB) {
          return { ok: false, error: (rA as any).error ?? (rB as any).error, a: rA, b: rB };
        }
        const bodyA = (rA as any).body ?? ""; const bodyB = (rB as any).body ?? "";
        const lenA = bodyA.length; const lenB = bodyB.length;
        const sameStatus = (rA as any).status === (rB as any).status;
        const sameLen = lenA === lenB;
        const sameBody = bodyA === bodyB;
        // Heuristic access-control signals.
        const authLikeStatusesA = [401, 403].includes((rA as any).status);
        const authLikeStatusesB = [401, 403].includes((rB as any).status);
        const suspectIdor = (rA as any).status === 200 && (rB as any).status === 200 && !sameBody && Math.abs(lenA - lenB) > 40;
        const suspectBac = authLikeStatusesA !== authLikeStatusesB;
        return {
          ok: true,
          same_status: sameStatus, same_length: sameLen, same_body: sameBody,
          suspect_idor: suspectIdor, suspect_bac: suspectBac,
          a: { context: a.as_a, status: (rA as any).status, length: lenA, body: bodyA.slice(0, 2048) },
          b: { context: a.as_b, status: (rB as any).status, length: lenB, body: bodyB.slice(0, 2048) },
        };
      },
    }),

    // ---------------- P4: in-runtime chain executor ----------------
    "chain.run": tool({
      description: "Execute an ordered exploit chain in-process. Steps share a cookie jar via `as`. Each step can (1) send an HTTP request, (2) capture a value from the response via JSONPath-ish or regex, (3) reference captures in later steps as ${var}. Returns per-step outcomes + confirmation of chain success.",
      inputSchema: z.object({
        as: z.string().default("anon"),
        stop_on_fail: z.boolean().default(true),
        steps: z.array(z.object({
          name: z.string(),
          method: z.enum(["GET","POST","PUT","PATCH","DELETE"]).default("GET"),
          url: z.string(),
          headers: z.record(z.string(), z.string()).optional(),
          body: z.string().optional(),
          expect_status: z.array(z.number().int()).optional(),
          expect_body_contains: z.string().optional(),
          capture: z.array(z.object({
            var: z.string(),
            from: z.enum(["body_regex","header","set_cookie","status"]),
            expr: z.string().optional(),
            header: z.string().optional(),
          })).default([]),
        })).min(1).max(15),
      }),
      execute: async ({ as, stop_on_fail, steps }) => {
        const authCtx = getContext(ctx.targetId, as);
        const vars: Record<string, string> = {};
        const results: any[] = [];
        const interp = (s: string | undefined) => !s ? s : s.replace(/\$\{(\w+)\}/g, (_, k) => vars[k] ?? "");

        for (const step of steps) {
          const url = interp(step.url)!;
          const body = interp(step.body);
          const headers: Record<string, string> = {};
          for (const [k, v] of Object.entries(step.headers ?? {})) headers[k] = interp(v)!;
          const res = await httpRequestAs({ ctx: authCtx, url, method: step.method, headers, body, timeout_ms: 15000 });
          const stepOut: any = { name: step.name, url, method: step.method };
          if ("error" in res) { stepOut.error = res.error; results.push(stepOut); if (stop_on_fail) break; else continue; }
          stepOut.status = res.status;

          // Assertions
          let ok = true;
          if (step.expect_status && !step.expect_status.includes(res.status!)) { ok = false; stepOut.fail = `status ${res.status} not in ${step.expect_status}`; }
          if (ok && step.expect_body_contains && !(res.body ?? "").includes(interp(step.expect_body_contains)!)) { ok = false; stepOut.fail = `body missing "${step.expect_body_contains}"`; }
          stepOut.ok = ok;

          // Captures
          for (const cap of step.capture) {
            try {
              if (cap.from === "body_regex" && cap.expr) {
                const m = new RegExp(cap.expr).exec(res.body ?? "");
                if (m) vars[cap.var] = m[1] ?? m[0];
              } else if (cap.from === "header" && cap.header) {
                const v = res.headers?.[cap.header.toLowerCase()];
                if (v) vars[cap.var] = Array.isArray(v) ? v[0] : String(v);
              } else if (cap.from === "set_cookie" && cap.expr) {
                const sc = res.headers?.["set-cookie"];
                const list = Array.isArray(sc) ? sc : sc ? [sc as string] : [];
                for (const c of list) {
                  const m = new RegExp(`${cap.expr}=([^;]+)`).exec(c);
                  if (m) { vars[cap.var] = m[1]; break; }
                }
              } else if (cap.from === "status") {
                vars[cap.var] = String(res.status);
              }
            } catch (e: any) { stepOut.capture_err = String(e?.message ?? e); }
          }
          stepOut.captured = { ...vars };
          results.push(stepOut);
          if (!ok && stop_on_fail) break;
        }

        // Persist updated jar (session may have picked up cookies).
        await persistContext(ctx.targetId, authCtx);

        const success = results.every(r => r.ok !== false && !r.error);
        return { ok: success, steps: results, vars };
      },
    }),

    "findings.record": tool({
      description: "Record a confirmed vulnerability finding. ONLY call after concrete proof (oracle hit, DOM alert, OOB callback, or successful chain.run). Runtime re-verifies deterministically and rejects unproven findings — a rejection is auto-logged as a 'dead_end' experience.",
      inputSchema: z.object({
        title: z.string(),
        vuln_class: z.string(),
        severity: z.enum(["critical","high","medium","low","info"]),
        affected_url: z.string(),
        proof_tier: z.enum(["exploited","confirmed","suspected"]).default("confirmed"),
        request_raw: z.string().optional(),
        response_raw: z.string().optional(),
        description: z.string(),
        technique: z.string().optional(),
        tech_tags: z.array(z.string()).default([]),
        evidence: z.record(z.string(), z.any()).optional(),
      }),
      execute: async (f) => {
        await metric(ctx.sessionId, ctx.targetId, "oracle_calls", 1, { vuln_class: f.vuln_class });
        const oracle = await runOracle(f.vuln_class, f.affected_url, f.evidence ?? {});
        await emit(ctx.sessionId, ctx.targetId, "critique", {
          stage: "proof_oracle", vuln_class: f.vuln_class, affected_url: f.affected_url,
          ok: oracle.ok, reason: oracle.reason, details: oracle.details,
        });
        let endpointPattern: string | null = null;
        try { const u = new URL(f.affected_url); endpointPattern = `${u.host}${u.pathname}`; } catch {}
        if (!oracle.ok) {
          await metric(ctx.sessionId, ctx.targetId, "findings_rejected_by_oracle", 1, { vuln_class: f.vuln_class });
          await recordExperience({
            target_id: ctx.targetId, session_id: ctx.sessionId,
            vuln_class: f.vuln_class, technique: f.technique ?? null, endpoint_pattern: endpointPattern,
            tech_tags: f.tech_tags, outcome: "dead_end", confidence: 0.2,
            notes: `oracle rejected: ${oracle.reason}`,
          });
          return { ok: false, rejected: true, reason: `proof oracle failed: ${oracle.reason}` };
        }
        const proofTier = oracle.details ? "confirmed" : (f.proof_tier ?? "suspected");
        const { data, error } = await db.from("vulnerability_findings").insert({
          target_id: ctx.targetId, finding_type: f.vuln_class, vuln_class: f.vuln_class,
          source: "agent-runtime", title: f.title, severity: f.severity, affected_url: f.affected_url,
          proof_tier: proofTier, description: f.description,
          request_raw: f.request_raw, response_raw: f.response_raw,
          evidence: { ...(f.evidence ?? {}), session_id: ctx.sessionId, oracle: { reason: oracle.reason, details: oracle.details } },
          hard_evidence: { ...(f.evidence ?? {}), oracle_reason: oracle.reason },
        }).select("id").maybeSingle();
        if (error) return { ok: false, error: error.message };
        await metric(ctx.sessionId, ctx.targetId, "findings_confirmed", 1, { vuln_class: f.vuln_class, severity: f.severity });
        await recordExperience({
          target_id: ctx.targetId, session_id: ctx.sessionId,
          vuln_class: f.vuln_class, technique: f.technique ?? null, endpoint_pattern: endpointPattern,
          tech_tags: f.tech_tags, outcome: "confirmed", confidence: 0.9,
          proof_snippet: oracle.reason, notes: f.title,
        });
        return { ok: true, finding_id: data?.id, proof: oracle.reason };
      },
    }),

    // -------- Mythos L2/L5: experience replay (agent memory) --------
    "experiences.similar": tool({
      description: "Query prior experiences for this target (and cross-target by tech tags) to learn which vuln classes/techniques worked before. Call at start of each new sub-goal.",
      inputSchema: z.object({
        tech_tags: z.array(z.string()).default([]),
        limit: z.number().int().min(1).max(50).default(20),
      }),
      execute: async ({ tech_tags, limit }) => {
        const rows = await similarExperiences(ctx.targetId, tech_tags, limit);
        return { count: rows.length, experiences: rows };
      },
    }),

    "experiences.record": tool({
      description: "Log a hypothesis outcome (partial/dead_end) so future sessions skip dead paths. `confirmed` outcomes are auto-recorded by findings.record — do NOT double-log.",
      inputSchema: z.object({
        vuln_class: z.string(),
        technique: z.string().optional(),
        endpoint_pattern: z.string().optional(),
        tech_tags: z.array(z.string()).default([]),
        outcome: z.enum(["rejected","partial","dead_end"]),
        confidence: z.number().min(0).max(1).default(0.3),
        notes: z.string().optional(),
      }),
      execute: async (e) => {
        await recordExperience({
          target_id: ctx.targetId, session_id: ctx.sessionId,
          vuln_class: e.vuln_class, technique: e.technique ?? null,
          endpoint_pattern: e.endpoint_pattern ?? null, tech_tags: e.tech_tags,
          outcome: e.outcome, confidence: e.confidence, notes: e.notes ?? null,
        });
        return { ok: true };
      },
    }),

    // -------- Mythos L3: metrics --------
    "metrics.inc": tool({
      description: "Increment a session metric counter (e.g. 'endpoints_discovered', 'chain_success'). Use sparingly for signals not otherwise captured.",
      inputSchema: z.object({
        metric: z.string(),
        value: z.number().default(1),
        tags: z.record(z.string(), z.any()).default({}),
      }),
      execute: async ({ metric: m, value, tags }) => {
        await metric(ctx.sessionId, ctx.targetId, m, value, tags);
        return { ok: true };
      },
    }),


    "recon.subfinder": tool({
      description: "Passive+active subdomain enumeration via subfinder. Returns unique subdomains.",
      inputSchema: z.object({ domain: z.string(), timeout_ms: z.number().int().min(1000).max(120000).default(60000) }),
      execute: async ({ domain, timeout_ms }) => {
        try {
          const { stdout } = await pexec("subfinder", ["-silent", "-d", domain], { timeout: timeout_ms, maxBuffer: 1024 * 512 });
          const subs = stdout.split("\n").map(s => s.trim()).filter(Boolean);
          return { count: subs.length, subdomains: subs.slice(0, 500) };
        } catch (e: any) { return { error: String(e?.message ?? e) }; }
      },
    }),

    "recon.httpx": tool({
      description: "Probe hosts with httpx. Returns status/title/tech per live host.",
      inputSchema: z.object({ hosts: z.array(z.string()).min(1).max(500), timeout_ms: z.number().int().min(1000).max(120000).default(60000) }),
      execute: async ({ hosts, timeout_ms }) => {
        try {
          const { stdout } = await pexec("httpx", ["-silent","-json","-title","-tech-detect","-status-code","-l","/dev/stdin"], { timeout: timeout_ms, maxBuffer: 1024 * 512, input: hosts.join("\n") } as any);
          const rows = stdout.split("\n").filter(Boolean).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
          return { count: rows.length, hosts: rows.slice(0, 200) };
        } catch (e: any) { return { error: String(e?.message ?? e) }; }
      },
    }),

    "recon.katana": tool({
      description: "Crawl a URL with katana (headless) to discover endpoints + JS routes.",
      inputSchema: z.object({ url: z.string().url(), depth: z.number().int().min(1).max(5).default(2), timeout_ms: z.number().int().min(5000).max(120000).default(45000) }),
      execute: async ({ url, depth, timeout_ms }) => {
        try {
          const { stdout } = await pexec("katana", ["-silent","-jc","-d",String(depth),"-u",url], { timeout: timeout_ms, maxBuffer: 1024 * 512 });
          const urls = stdout.split("\n").map(s => s.trim()).filter(Boolean);
          return { count: urls.length, urls: urls.slice(0, 300) };
        } catch (e: any) { return { error: String(e?.message ?? e) }; }
      },
    }),

    "vuln.nuclei": tool({
      description: "Run nuclei templates against a target. Filter by severity.",
      inputSchema: z.object({
        url: z.string().url(),
        severity: z.array(z.enum(["info","low","medium","high","critical"])).default(["medium","high","critical"]),
        tags: z.array(z.string()).optional(),
        timeout_ms: z.number().int().min(10000).max(180000).default(90000),
      }),
      execute: async ({ url, severity, tags, timeout_ms }) => {
        const args = ["-silent","-jsonl","-u",url,"-severity",severity.join(",")];
        if (tags?.length) args.push("-tags", tags.join(","));
        try {
          const { stdout } = await pexec("nuclei", args, { timeout: timeout_ms, maxBuffer: 1024 * 1024 });
          const hits = stdout.split("\n").filter(Boolean).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
          return { count: hits.length, findings: hits.slice(0, 50) };
        } catch (e: any) { return { error: String(e?.message ?? e) }; }
      },
    }),

    "oob.register": tool({
      description: "Get a fresh OOB callback URL from the local interactsh server.",
      inputSchema: z.object({}),
      execute: async () => {
        if (!INTERACTSH_URL) return { error: "INTERACTSH_URL not set; start interactsh via installer" };
        const id = Math.random().toString(36).slice(2, 10);
        const host = new URL(INTERACTSH_URL).host;
        return { callback_url: `http://${id}.${host}`, correlation_id: id };
      },
    }),

    "oob.poll": tool({
      description: "Poll interactsh for callbacks matching a correlation_id.",
      inputSchema: z.object({ correlation_id: z.string() }),
      execute: async ({ correlation_id }) => {
        if (!INTERACTSH_URL) return { error: "INTERACTSH_URL not set" };
        try {
          const r = await request(`${INTERACTSH_URL}/poll?id=${correlation_id}`, { headersTimeout: 5000 });
          const body = await r.body.text();
          return { status: r.statusCode, body: body.slice(0, 4096) };
        } catch (e: any) { return { error: String(e?.message ?? e) }; }
      },
    }),

    "proxy.replay": tool({
      description: "Replay a captured request with tampered headers/body via the mitmproxy sidecar.",
      inputSchema: z.object({
        url: z.string().url(),
        method: z.enum(["GET","POST","PUT","PATCH","DELETE"]).default("GET"),
        headers: z.record(z.string(), z.string()).optional(),
        body: z.string().optional(),
        via_proxy: z.boolean().default(true),
      }),
      execute: async ({ url, method, headers, body }) => {
        try {
          const r = await request(url, { method, headers, body, headersTimeout: 10000, maxRedirections: 0 });
          const buf = await r.body.text();
          return { status: r.statusCode, headers: r.headers, body: buf.slice(0, 4096) };
        } catch (e: any) { return { error: String(e?.message ?? e) }; }
      },
    }),

    "finish": tool({
      description: "End the session. Call when the goal is met or budget is nearly exhausted.",
      inputSchema: z.object({ reason: z.string() }),
      execute: async ({ reason }) => ({ done: true, reason }),
    }),
  };
}

export type ToolBundle = ReturnType<typeof buildTools>;
