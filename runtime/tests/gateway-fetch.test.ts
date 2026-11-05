import { describe, it, expect } from "bun:test";
import { createRuntimeAIFetch } from "../src/gateway-fetch.js";
import { proxyRuntimeAI } from "../../supabase/functions/runtime-gateway/ai-proxy.ts";

describe("runtime AI cloud boundary", () => {
  it("keeps the managed key in cloud and streams tool deltas unchanged", async () => {
    const sse = 'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1"}]}}]}\n\ndata: [DONE]\n\n';
    const transport = createRuntimeAIFetch("https://cloud.example", "shared-test", async (url, init) => {
      expect(String(url)).toBe("https://cloud.example/functions/v1/runtime-gateway?ai=chat/completions");
      expect(new Headers(init?.headers).get("Lovable-API-Key")).toBeNull();
      expect(new Headers(init?.headers).get("x-runtime-secret")).toBe("shared-test");
      return proxyRuntimeAI(new Request(String(url), init), "cloud-only-test", {}, async (destination, request) => {
        expect(String(destination)).toBe("https://ai.gateway.lovable.dev/v1/chat/completions");
        expect(new Headers(request?.headers).get("Lovable-API-Key")).toBe("cloud-only-test");
        return new Response(sse, { headers: { "Content-Type": "text/event-stream", "X-Lovable-AIG-Run-ID": "upstream-run" } });
      });
    });
    const response = await transport("https://ignored.example", { method: "POST", body: JSON.stringify({ model: "existing-model", messages: [], stream: true }) });
    expect(await response.text()).toBe(sse);
  });

  for (const status of [401, 402, 403, 429, 503]) {
    it(`restores upstream ${status} for terminal/retry handling`, async () => {
      const transport = createRuntimeAIFetch("https://cloud.example", "shared-test", async (url, init) => {
        const cloudResponse = await proxyRuntimeAI(new Request(String(url), init), "cloud-only-test", {}, async () =>
          new Response(JSON.stringify({ message: "safe failure" }), { status, headers: { "Content-Type": "application/json" } }));
        expect(cloudResponse.status).toBe(200);
        return cloudResponse;
      });
      const response = await transport("https://ignored.example", { method: "POST", body: JSON.stringify({ model: "existing-model", messages: [] }) });
      expect(response.status).toBe(status);
      expect((await response.json()).error.message).toBe("safe failure");
    });
  }

  it("reuses only the upstream-issued run ID on follow-up calls", async () => {
    let calls = 0;
    const transport = createRuntimeAIFetch("https://cloud.example", "shared-test", async (_url, init) => {
      expect(new Headers(init?.headers).get("X-Lovable-AIG-Run-ID")).toBe(calls++ ? "issued-run" : null);
      return new Response("data: [DONE]\n\n", { headers: { "Content-Type": "text/event-stream", "X-Lovable-AIG-Run-ID": "issued-run" } });
    });
    await transport("https://ignored.example");
    await transport("https://ignored.example");
    expect(calls).toBe(2);
  });
});