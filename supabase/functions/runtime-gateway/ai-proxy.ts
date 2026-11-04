// Only the authenticated runtime-gateway handler may call this helper.
export async function proxyRuntimeAI(
  req: Request,
  key: string | undefined,
  headers: HeadersInit,
  upstreamFetch: typeof fetch,
): Promise<Response> {
  const error = (message: string, upstreamStatus: number) => new Response(
    JSON.stringify({ error: message, upstream_status: upstreamStatus }),
    { status: 200, headers: { ...Object.fromEntries(new Headers(headers)), "Content-Type": "application/json" } },
  );
  if (!key) return error("Cloud AI access is not configured", 401);
  if (req.method !== "POST") return error("POST required", 405);
  const body = await req.json();
  if (!body || typeof body.model !== "string" || !Array.isArray(body.messages)) {
    return error("model and messages are required", 400);
  }
  // Fixed destination: the runtime cannot turn this into an arbitrary proxy.
  const upstreamHeaders = new Headers({
    "Content-Type": "application/json",
    "Lovable-API-Key": key,
    "X-Lovable-AIG-SDK": "vercel-ai-sdk",
  });
  const runId = req.headers.get("X-Lovable-AIG-Run-ID");
  if (runId) upstreamHeaders.set("X-Lovable-AIG-Run-ID", runId);
  const upstream = await upstreamFetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
    method: "POST", headers: upstreamHeaders, body: JSON.stringify(body), signal: req.signal,
  });
  const responseHeaders = new Headers(headers);
  upstream.headers.forEach((value, name) => {
    if (name.toLowerCase().startsWith("x-lovable-aig-")) responseHeaders.set(name, value);
  });
  if (!upstream.ok) {
    const payload = await upstream.json().catch(() => ({}));
    const message = payload.message ?? payload.error?.message ?? payload.title ?? `AI request failed (${upstream.status})`;
    const failed = error(String(message), upstream.status);
    responseHeaders.forEach((value, name) => failed.headers.set(name, value));
    if (upstream.headers.has("Retry-After")) failed.headers.set("Retry-After", upstream.headers.get("Retry-After") ?? "");
    return failed;
  }
  responseHeaders.set("Content-Type", upstream.headers.get("Content-Type") ?? "text/event-stream");
  return new Response(upstream.body, { status: 200, headers: responseHeaders });
}