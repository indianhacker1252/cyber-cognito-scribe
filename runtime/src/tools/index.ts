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

const SHELL_ALLOWLIST = new Set([
  "curl", "dig", "whois", "nmap", "jq", "host", "nslookup",
  // ProjectDiscovery + fuzzers
  "subfinder", "httpx", "dnsx", "naabu", "katana", "nuclei",
  "assetfinder", "waybackurls", "gau", "ffuf", "feroxbuster",
  "arjun", "gobuster", "wafw00f", "whatweb", "sslscan", "testssl.sh",
  // exploit CLIs (still gated by target_is_exploit_authorized in operator prompt)
  "sqlmap", "dalfox", "commix", "wpscan",
]);

const INTERACTSH_URL = process.env.INTERACTSH_URL || "";

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
          const { stdout } = await pexec("httpx", ["-silent", "-json", "-title", "-tech-detect", "-status-code", "-l", "/dev/stdin"], { timeout: timeout_ms, maxBuffer: 1024 * 512, input: hosts.join("\n") } as any);
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
          const { stdout } = await pexec("katana", ["-silent", "-jc", "-d", String(depth), "-u", url], { timeout: timeout_ms, maxBuffer: 1024 * 512 });
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
        const args = ["-silent", "-jsonl", "-u", url, "-severity", severity.join(",")];
        if (tags?.length) args.push("-tags", tags.join(","));
        try {
          const { stdout } = await pexec("nuclei", args, { timeout: timeout_ms, maxBuffer: 1024 * 1024 });
          const hits = stdout.split("\n").filter(Boolean).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
          return { count: hits.length, findings: hits.slice(0, 50) };
        } catch (e: any) { return { error: String(e?.message ?? e) }; }
      },
    }),

    "oob.register": tool({
      description: "Get a fresh OOB callback URL from the local interactsh server. Use in SSRF/blind-RCE/blind-SQLi payloads, then poll oob.poll to confirm.",
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
      description: "Replay a captured request with tampered headers/body via the mitmproxy sidecar. Use for Intruder/Repeater-style probing.",
      inputSchema: z.object({
        url: z.string().url(),
        method: z.enum(["GET","POST","PUT","PATCH","DELETE"]).default("GET"),
        headers: z.record(z.string(), z.string()).optional(),
        body: z.string().optional(),
        via_proxy: z.boolean().default(true),
      }),
      execute: async ({ url, method, headers, body, via_proxy }) => {
        try {
          const opts: any = { method, headers, body, headersTimeout: 10000, maxRedirections: 0 };
          if (via_proxy && process.env.MITM_PROXY_URL) opts.dispatcher = undefined; // undici honors HTTP_PROXY env if set
          const r = await request(url, opts);
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
