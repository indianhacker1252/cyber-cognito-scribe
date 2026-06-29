// dedup-key.ts — normalize a finding into a single canonical key so we
// reject duplicate findings at the DB level (unique index on dedup_key).
//
// Key inputs that matter: host, method, path-without-ids, param name, vuln class.
// Status code / payload values are intentionally ignored — same bug fired with
// 10 payloads on the same param is still one finding.

function normalizePath(path: string): string {
  if (!path) return "/";
  // Strip numeric and uuid id segments so /user/123 and /user/456 collapse.
  return path
    .replace(/\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, "/:uuid")
    .replace(/\/\d+(?=\/|$)/g, "/:id")
    .replace(/\/+$/g, "") || "/";
}

export interface DedupInput {
  url?: string;
  method?: string;
  param?: string;
  vulnClass?: string;
  source?: string;
}

export function buildDedupKey(input: DedupInput): string {
  let host = "", path = "/";
  try {
    if (input.url) {
      const u = new URL(input.url);
      host = u.host.toLowerCase();
      path = normalizePath(u.pathname);
    }
  } catch { /* ignore */ }
  const method = (input.method || "GET").toUpperCase();
  const param = (input.param || "").toLowerCase();
  const cls = (input.vulnClass || input.source || "generic").toLowerCase();
  return [host, method, path, param, cls].join("|");
}

// Pull param name from evidence/request if not explicitly provided.
export function inferParam(req?: { url?: string; body?: string }, evidence?: Record<string, unknown>): string {
  if (evidence?.param && typeof evidence.param === "string") return evidence.param;
  if (req?.url) {
    try {
      const u = new URL(req.url);
      const keys = [...u.searchParams.keys()];
      if (keys.length) return keys[0];
    } catch { /* ignore */ }
  }
  return "";
}
