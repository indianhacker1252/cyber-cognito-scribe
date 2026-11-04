// Request-local correlation state; never place the managed AI key on the VPS.
export function createRuntimeAIFetch(baseURL: string, secret: string, fetcher: typeof fetch = fetch): typeof fetch {
  let runId: string | undefined;
  return async (_input, init) => {
    const headers = new Headers({ "Content-Type": "application/json", "x-runtime-secret": secret });
    if (runId) headers.set("X-Lovable-AIG-Run-ID", runId);
    const response = await fetcher(`${baseURL.replace(/\/+$/, "")}/functions/v1/runtime-gateway?ai=chat/completions`, {
      ...init, headers,
    });
    runId ??= response.headers.get("X-Lovable-AIG-Run-ID")?.trim() || undefined;
    if (response.ok && response.headers.get("Content-Type")?.includes("application/json")) {
      const payload = await response.clone().json().catch(() => ({}));
      if (payload.error) {
        const status = Number(payload.upstream_status ?? 500);
        return new Response(JSON.stringify({ error: { message: payload.error } }), {
          status: status >= 400 && status <= 599 ? status : 500,
          headers: response.headers,
        });
      }
    }
    return response;
  };
}