const MAX_BODY_CHARS = 12000;

export type ProofRequest = {
  method?: string;
  url?: string;
  headers?: Record<string, unknown>;
  body?: unknown;
  payload?: string;
  parameter?: string;
};

export type ProofResponse = {
  status?: number;
  headers?: Record<string, unknown>;
  body?: unknown;
  bodySnippet?: string;
  length?: number;
};

function safeStringify(value: unknown): string {
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value ?? "");
  }
}

export function trimBody(value: unknown, maxChars = MAX_BODY_CHARS): string {
  const text = safeStringify(value);
  if (text.length <= maxChars) return text;
  return `${text.slice(0, maxChars)}\n\n[truncated ${text.length - maxChars} chars]`;
}

function normalizeHeaders(headers?: Record<string, unknown>): Record<string, string> {
  if (!headers) return {};
  return Object.fromEntries(
    Object.entries(headers).map(([key, value]) => [key, typeof value === "string" ? value : safeStringify(value)]),
  );
}

export function buildCurlPocScript(request: ProofRequest): string {
  const method = (request.method || "GET").toUpperCase();
  const headerFlags = Object.entries(normalizeHeaders(request.headers))
    .filter(([key]) => key.toLowerCase() !== "content-length")
    .map(([key, value]) => `-H ${JSON.stringify(`${key}: ${value}`)}`)
    .join(" ");
  const bodyFlag = request.body == null
    ? ""
    : ` --data-raw ${JSON.stringify(typeof request.body === "string" ? request.body : safeStringify(request.body))}`;

  return `curl -i -sS -X ${method} ${headerFlags}${bodyFlag} ${JSON.stringify(request.url || "")}`.trim();
}

export function buildProofMarkdown(input: {
  title: string;
  proofSummary: string;
  remediation?: string;
  request: ProofRequest;
  baselineResponse?: ProofResponse | null;
  mutatedResponse?: ProofResponse | null;
  cveIds?: string[];
}) {
  const request = input.request;
  const baseline = input.baselineResponse;
  const mutated = input.mutatedResponse;
  const cveLine = input.cveIds && input.cveIds.length ? `\n- CVE mapping: ${input.cveIds.join(", ")}` : "";

  return [
    `# ${input.title}`,
    "",
    "## Summary",
    `- Proof: ${input.proofSummary}${cveLine}`,
    `- Payload: ${request.payload || "n/a"}`,
    `- Parameter: ${request.parameter || "n/a"}`,
    `- URL: ${request.url || "n/a"}`,
    "",
    "## Reproduction",
    "```bash",
    buildCurlPocScript(request),
    "```",
    "",
    "## Request",
    "```json",
    safeStringify({
      method: request.method || "GET",
      url: request.url,
      headers: normalizeHeaders(request.headers),
      body: request.body ?? null,
    }),
    "```",
    "",
    baseline ? "## Baseline Response" : null,
    baseline ? "```json" : null,
    baseline ? safeStringify({
      status: baseline.status ?? 0,
      headers: normalizeHeaders(baseline.headers),
      length: baseline.length ?? trimBody(baseline.body ?? baseline.bodySnippet).length,
      body: trimBody(baseline.body ?? baseline.bodySnippet),
    }) : null,
    baseline ? "```" : null,
    baseline ? "" : null,
    mutated ? "## Mutated Response" : null,
    mutated ? "```json" : null,
    mutated ? safeStringify({
      status: mutated.status ?? 0,
      headers: normalizeHeaders(mutated.headers),
      length: mutated.length ?? trimBody(mutated.body ?? mutated.bodySnippet).length,
      body: trimBody(mutated.body ?? mutated.bodySnippet),
    }) : null,
    mutated ? "```" : null,
    "",
    "## Remediation",
    input.remediation || "Validate input, enforce context-aware escaping, and require deterministic re-test before reporting.",
  ].filter(Boolean).join("\n");
}

export async function createEvidencePackage(
  db: any,
  input: {
    targetId: string;
    findingId?: string | null;
    approvalId?: string | null;
    title: string;
    proofSummary: string;
    remediation?: string;
    request: ProofRequest;
    baselineResponse?: ProofResponse | null;
    mutatedResponse?: ProofResponse | null;
    validationStatus?: string;
    pocScript?: string;
    scriptLanguage?: string;
    cvssScore?: number | null;
    cvssVector?: string | null;
    cveIds?: string[];
  },
): Promise<string | null> {
  const reportMarkdown = buildProofMarkdown({
    title: input.title,
    proofSummary: input.proofSummary,
    remediation: input.remediation,
    request: input.request,
    baselineResponse: input.baselineResponse,
    mutatedResponse: input.mutatedResponse,
    cveIds: input.cveIds,
  });

  const { data, error } = await db.from("evidence_packages").insert({
    target_id: input.targetId,
    finding_id: input.findingId || null,
    approval_id: input.approvalId || null,
    validation_status: input.validationStatus || "verified",
    script_language: input.scriptLanguage || "bash",
    poc_script: input.pocScript || buildCurlPocScript(input.request),
    http_request_data: {
      method: input.request.method || "GET",
      url: input.request.url || "",
      headers: normalizeHeaders(input.request.headers),
      body: input.request.body ?? null,
      payload: input.request.payload || null,
      parameter: input.request.parameter || null,
      curl: buildCurlPocScript(input.request),
    },
    http_response_data: {
      baseline: input.baselineResponse ? {
        status: input.baselineResponse.status ?? 0,
        headers: normalizeHeaders(input.baselineResponse.headers),
        length: input.baselineResponse.length ?? trimBody(input.baselineResponse.body ?? input.baselineResponse.bodySnippet).length,
        body: trimBody(input.baselineResponse.body ?? input.baselineResponse.bodySnippet),
      } : null,
      mutated: input.mutatedResponse ? {
        status: input.mutatedResponse.status ?? 0,
        headers: normalizeHeaders(input.mutatedResponse.headers),
        length: input.mutatedResponse.length ?? trimBody(input.mutatedResponse.body ?? input.mutatedResponse.bodySnippet).length,
        body: trimBody(input.mutatedResponse.body ?? input.mutatedResponse.bodySnippet),
      } : null,
      proof_summary: input.proofSummary,
      cve_ids: input.cveIds || [],
    },
    report_markdown: reportMarkdown,
    cvss_score: input.cvssScore ?? null,
    cvss_vector: input.cvssVector ?? null,
  }).select("id").single();

  if (error) {
    console.error("evidence package insert failed", error);
    return null;
  }

  return data?.id || null;
}