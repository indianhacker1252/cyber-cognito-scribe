import { tool } from "ai";
import { z } from "zod";
import { request } from "undici";
import { chromium, type Browser } from "playwright";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { db, mergeWorldModel } from "../db.js";

const pexec = promisify(execFile);

let sharedBrowser: Browser | null = null;
async function getBrowser() {
  if (!sharedBrowser) sharedBrowser = await chromium.launch({ headless: true, args: ["--no-sandbox"] });
  return sharedBrowser;
}
export async function closeBrowser() {
  if (sharedBrowser) { await sharedBrowser.close(); sharedBrowser = null; }
}

const SHELL_ALLOWLIST = new Set(["curl", "dig", "whois", "nmap", "jq", "host", "nslookup"]);

export function buildTools(ctx: { sessionId: string; targetId: string }) {
  return {
    "http.request": tool({
      description: "Send an HTTP request. Returns status, headers, and body (truncated to 8KB).",
      inputSchema: z.object({
        url: z.string().url(),
        method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]).default("GET"),
        headers: z.record(z.string(), z.string()).optional(),
        body: z.string().optional(),
        timeout_ms: z.number().int().min(500).max(30000).default(10000),
      }),
      execute: async ({ url, method, headers, body, timeout_ms }) => {
        const ac = new AbortController();
        const t = setTimeout(() => ac.abort(), timeout_ms);
        try {
          const res = await request(url, { method, headers, body, signal: ac.signal, maxRedirections: 0 });
          const buf = await res.body.text();
          return {
            status: res.statusCode,
            headers: res.headers,
            body: buf.slice(0, 8192),
            truncated: buf.length > 8192,
          };
        } catch (e: any) {
          return { error: String(e?.message ?? e) };
        } finally { clearTimeout(t); }
      },
    }),

    "browser.visit": tool({
      description: "Open URL in headless Chromium. Returns title, final URL, DOM snapshot, and console logs.",
      inputSchema: z.object({
        url: z.string().url(),
        wait_ms: z.number().int().min(0).max(15000).default(2000),
      }),
      execute: async ({ url, wait_ms }) => {
        const browser = await getBrowser();
        const context = await browser.newContext();
        const page = await context.newPage();
        const consoleLogs: string[] = [];
        page.on("console", (m) => consoleLogs.push(`[${m.type()}] ${m.text()}`.slice(0, 500)));
        try {
          await page.goto(url, { waitUntil: "domcontentloaded", timeout: 20000 });
          await page.waitForTimeout(wait_ms);
          const title = await page.title();
          const finalUrl = page.url();
          const html = (await page.content()).slice(0, 16384);
          return { title, finalUrl, html, console: consoleLogs.slice(0, 40) };
        } catch (e: any) {
          return { error: String(e?.message ?? e), console: consoleLogs.slice(0, 40) };
        } finally { await context.close(); }
      },
    }),

    "browser.exec_js": tool({
      description: "Load URL, execute a JS expression in-page, return its serialized result. Use for DOM XSS / proto pollution proofs.",
      inputSchema: z.object({ url: z.string().url(), expression: z.string().min(1).max(4096) }),
      execute: async ({ url, expression }) => {
        const browser = await getBrowser();
        const context = await browser.newContext();
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
      description: "Run one allowlisted CLI (curl, dig, whois, nmap, jq, host, nslookup). Returns stdout/stderr.",
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
      description: "Persist facts learned about the target (tech stack, endpoints, beliefs, attempts) into the world model.",
      inputSchema: z.object({ patch: z.record(z.string(), z.any()) }),
      execute: async ({ patch }) => {
        await mergeWorldModel(ctx.targetId, patch);
        return { ok: true };
      },
    }),

    "findings.record": tool({
      description: "Record a confirmed vulnerability finding. ONLY call after concrete proof (oracle hit, DOM alert, OOB callback).",
      inputSchema: z.object({
        title: z.string(),
        vuln_class: z.string(),
        severity: z.enum(["critical", "high", "medium", "low", "info"]),
        affected_url: z.string(),
        proof_tier: z.enum(["exploited", "confirmed", "suspected"]).default("confirmed"),
        request_raw: z.string().optional(),
        response_raw: z.string().optional(),
        description: z.string(),
        evidence: z.record(z.string(), z.any()).optional(),
      }),
      execute: async (f) => {
        const { data, error } = await db.from("vulnerability_findings").insert({
          target_id: ctx.targetId,
          finding_type: f.vuln_class,
          vuln_class: f.vuln_class,
          source: "agent-runtime",
          title: f.title,
          severity: f.severity,
          affected_url: f.affected_url,
          proof_tier: f.proof_tier,
          description: f.description,
          request_raw: f.request_raw,
          response_raw: f.response_raw,
          evidence: { ...(f.evidence ?? {}), session_id: ctx.sessionId },
          hard_evidence: f.evidence ?? {},
        }).select("id").maybeSingle();
        if (error) return { ok: false, error: error.message };
        return { ok: true, finding_id: data?.id };
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
