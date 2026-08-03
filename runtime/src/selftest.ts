// CyberScope agent runtime selftest — pings Supabase, LLM, browser, OOB.
import { chromium } from "playwright";
import { request } from "undici";

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
await check("env: SUPABASE_SERVICE_ROLE_KEY", async () => {
  if (!process.env.SUPABASE_SERVICE_ROLE_KEY) throw new Error("missing"); return "set";
});
await check("env: LLM key (any)", async () => {
  const k = process.env.LOVABLE_API_KEY || process.env.OPENAI_API_KEY || process.env.GEMINI_API_KEY;
  if (!k) throw new Error("no LLM key set"); return "ok";
});

await check("supabase reachable", async () => {
  const r = await request(`${process.env.SUPABASE_URL}/rest/v1/`, {
    headers: { apikey: process.env.SUPABASE_SERVICE_ROLE_KEY ?? "" },
  });
  if (r.statusCode >= 500) throw new Error(`status ${r.statusCode}`);
  return `HTTP ${r.statusCode}`;
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

const w = 32;
console.log("\nCyberScope runtime selftest\n" + "-".repeat(w + 12));
for (const r of rows) {
  const mark = r.ok ? "\x1b[32m✓\x1b[0m" : "\x1b[31m✗\x1b[0m";
  console.log(`${mark} ${r.name.padEnd(w)} ${r.detail}`);
}
const failed = rows.filter(r => !r.ok).length;
console.log("-".repeat(w + 12));
console.log(`${rows.length - failed}/${rows.length} checks passed`);
process.exit(failed > 0 ? 1 : 0);
