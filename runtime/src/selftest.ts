// CyberScope agent runtime selftest — pings the runtime gateway, LLM, browser, OOB.
import { chromium } from "playwright";
import { request } from "undici";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { streamText } from "ai";
import { pickProvider } from "./llm.js";

const pexec = promisify(execFile);

type Row = { name: string; ok: boolean; detail: string };
const rows: Row[] = [];

async function check(name: string, fn: () => Promise<string>) {
  try { rows.push({ name, ok: true, detail: await fn() }); }
  catch (e: any) { rows.push({ name, ok: false, detail: String(e?.message ?? e) }); }
}

await check("env: SUPABASE_URL", async () => {
  if (!process.env.SUPABASE_URL) throw new Error("missing");
  return process.env.SUPABASE_URL;
});
await check("env: RUNTIME_SECRET", async () => {
  if (!process.env.RUNTIME_SECRET) throw new Error("missing"); return "set";
});
await check("env: cloud AI access", async () => {
  if (!process.env.SUPABASE_URL || !process.env.RUNTIME_SECRET) throw new Error("cloud URL and shared secret required");
  return "uses cloud-managed AI key";
});

await check("runtime-gateway reachable", async () => {
  const r = await request(`${process.env.SUPABASE_URL}/functions/v1/runtime-gateway`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-runtime-secret": process.env.RUNTIME_SECRET ?? "",
    },
    body: JSON.stringify({ op: "query", table: "agent_sessions", select: "id", limit: 1 }),
    headersTimeout: 8000,
  });
  const body = await r.body.text();
  const payload = JSON.parse(body);
  if (payload.error) throw new Error(String(payload.error));
  if (r.statusCode === 401) throw new Error("unauthorized — RUNTIME_SECRET mismatch");
  if (r.statusCode >= 500) throw new Error(`status ${r.statusCode}: ${body.slice(0, 120)}`);
  return `HTTP ${r.statusCode}`;
});

await check("cloud AI inference", async () => {
  const result = streamText({
    model: pickProvider("lovable", process.env.RUNTIME_AI_MODEL || "google/gemini-2.5-flash"),
    prompt: "Reply with OK only.", maxRetries: 0,
  });
  for await (const chunk of result.fullStream) {
    if (chunk.type === "error") throw chunk.error;
  }
  if (!(await result.text).trim()) throw new Error("AI returned no text");
  return "authenticated streaming response received";
});

await check("playwright chromium", async () => {
  const b = await chromium.launch({ headless: true, args: ["--no-sandbox"] });
  const p = await (await b.newContext()).newPage();
  await p.goto("about:blank"); await b.close();
  return "launched + navigated";
});

await check("ollama (optional)", async () => {
  const url = process.env.OLLAMA_URL || "http://host.docker.internal:11434";
  const r = await request(`${url}/api/tags`, { headersTimeout: 3000 });
  return `HTTP ${r.statusCode}`;
});

await check("interactsh (optional)", async () => {
  const url = process.env.INTERACTSH_URL || "http://host.docker.internal:8443";
  const r = await request(url, { headersTimeout: 3000 });
  return `HTTP ${r.statusCode}`;
});

for (const bin of ["subfinder", "httpx", "katana", "nuclei", "nmap", "ffuf", "sqlmap"]) {
  await check(`shell: ${bin}`, async () => {
    const { stdout } = await pexec(bin, ["-version"]).catch(async () => pexec(bin, ["--version"]));
    return (stdout || "").split("\n")[0].slice(0, 60) || "present";
  });
}

const w = 32;
console.log("\nCyberScope runtime selftest\n" + "-".repeat(w + 12));
for (const r of rows) {
  const mark = r.ok ? "\x1b[32m✓\x1b[0m" : "\x1b[31m✗\x1b[0m";
  console.log(`${mark} ${r.name.padEnd(w)} ${r.detail}`);
}
console.log("-".repeat(w + 12));
const failed = rows.filter(r => !r.ok).length;
console.log(`${rows.length - failed}/${rows.length} checks passed`);
process.exit(failed > 0 ? 1 : 0);
