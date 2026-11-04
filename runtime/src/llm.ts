import { createOpenAICompatible } from "@ai-sdk/openai-compatible";
import { createGoogleGenerativeAI } from "@ai-sdk/google";
import { createRuntimeAIFetch } from "./gateway-fetch.js";

export function pickProvider(provider: string, model: string) {
  if (provider === "openai") {
    const key = process.env.OPENAI_API_KEY;
    if (!key) throw new Error("OPENAI_API_KEY not set");
    const p = createOpenAICompatible({
      name: "openai",
      baseURL: "https://api.openai.com/v1",
      headers: { Authorization: `Bearer ${key}` },
      supportsStructuredOutputs: true,
    });
    return p(model.replace(/^openai\//, ""));
  }
  if (provider === "gemini") {
    const key = process.env.GEMINI_API_KEY;
    if (!key) throw new Error("GEMINI_API_KEY not set");
    // Use native Google provider — the OpenAI-compat endpoint omits `index`
    // on tool_call deltas which breaks AI SDK 5 stream parsing.
    const google = createGoogleGenerativeAI({ apiKey: key });
    return google(model.replace(/^google\//, ""));
  }
  // default: lovable gateway
  const baseURL = process.env.SUPABASE_URL;
  const secret = process.env.RUNTIME_SECRET;
  if (!baseURL || !secret) throw new Error("SUPABASE_URL and RUNTIME_SECRET are required for cloud AI");
  const p = createOpenAICompatible({
    name: "lovable",
    baseURL: "https://ai.gateway.lovable.dev/v1",
    fetch: createRuntimeAIFetch(baseURL, secret),
  });
  return p(model);
}
