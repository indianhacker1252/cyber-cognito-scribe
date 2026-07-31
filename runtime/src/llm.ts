import { createOpenAICompatible } from "@ai-sdk/openai-compatible";

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
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { createGoogleGenerativeAI } = require("@ai-sdk/google");
    const google = createGoogleGenerativeAI({ apiKey: key });
    return google(model.replace(/^google\//, ""));
  }
  // default: lovable gateway
  const key = process.env.LOVABLE_API_KEY;
  if (!key) throw new Error("LOVABLE_API_KEY not set");
  const p = createOpenAICompatible({
    name: "lovable",
    baseURL: "https://ai.gateway.lovable.dev/v1",
    headers: { "Lovable-API-Key": key, "X-Lovable-AIG-SDK": "vercel-ai-sdk" },
  });
  return p(model);
}
