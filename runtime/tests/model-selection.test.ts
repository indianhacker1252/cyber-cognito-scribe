import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";

const read = (path: string) => readFileSync(new URL(`../../${path}`, import.meta.url), "utf8");

describe("approved Gateway model selection", () => {
  for (const path of [
    "supabase/functions/_shared/llm.ts",
    "supabase/functions/agent-start/index.ts",
    "src/components/AgentSessionStarter.tsx",
    "runtime/src/selftest.ts",
    ...["advanced-fuzzer", "ai-tutor-distill", "app-package-scan", "chain-finder", "deep-signal-triage", "exploit-engine", "generate-poc", "mythos-chainer", "mythos-debate", "mythos-patcher", "mythos-variant-gen", "report-rewrite", "triage-brain", "validate-finding"].map(name => `supabase/functions/${name}/index.ts`),
  ]) {
    it(`${path} selects the active Flash model`, () => {
      const source = read(path);
      expect(source).toContain('"google/gemini-3.8-flash"');
      expect(source).not.toMatch(/google\/gemini-(?:2\.5-flash|3\.6-flash)/);
    });
  }
  for (const name of ["vuln-scanner", "intel-sync", "mythos-debate"]) {
    it(`${name} retains lightweight routing with active Flash Lite`, () => {
      expect(read(`supabase/functions/${name}/index.ts`)).toContain('"google/gemini-3.1-flash-lite"');
    });
  }
  it("preserves direct-provider selections and optional runtime override", () => {
    const ui = read("src/components/AgentSessionStarter.tsx");
    expect(ui).toContain('openai: "gpt-4.1-mini"');
    expect(ui).toContain('gemini: "gemini-2.0-flash-exp"');
    expect(read("runtime/src/selftest.ts")).toContain('process.env.RUNTIME_AI_MODEL || "google/gemini-3.8-flash"');
    expect(read("supabase/functions/_shared/llm.ts")).toContain("models/gemini-2.5-flash:generateContent");
  });
});