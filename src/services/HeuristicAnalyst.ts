/**
 * HeuristicAnalyst - Filter Analysis Engine
 * Evaluates HTTP response patterns to classify why a verification test was filtered.
 */

export type FilterClassification =
  | "string_matching"
  | "character_sanitization"
  | "rate_limiting"
  | "ip_blocking"
  | "method_restriction"
  | "content_type_rejection"
  | "unknown";

export interface FilterAnalysis {
  classification: FilterClassification;
  confidence: number;
  indicators: string[];
  statusCode: number;
  responseSnippet: string;
}

const WAF_SIGNATURES = [
  { pattern: /cloudflare/i, provider: "Cloudflare" },
  { pattern: /akamai/i, provider: "Akamai" },
  { pattern: /mod_security/i, provider: "ModSecurity" },
  { pattern: /aws\s?waf/i, provider: "AWS WAF" },
  { pattern: /imperva/i, provider: "Imperva" },
];

export function classifyFilter(statusCode: number, responseBody: string, headers?: Record<string, string>): FilterAnalysis {
  const indicators: string[] = [];
  let classification: FilterClassification = "unknown";
  let confidence = 0.5;

  // Detect WAF provider
  for (const sig of WAF_SIGNATURES) {
    if (sig.pattern.test(responseBody) || (headers && Object.values(headers).some(v => sig.pattern.test(v)))) {
      indicators.push(`WAF detected: ${sig.provider}`);
    }
  }

  // Classify based on status code and body patterns
  if (statusCode === 429 || /rate.?limit|too many requests|throttl/i.test(responseBody)) {
    classification = "rate_limiting";
    confidence = 0.9;
    indicators.push("Rate limiting response detected");
  } else if (statusCode === 403) {
    if (/forbidden.*character|invalid.*char|illegal.*input|sanitiz/i.test(responseBody)) {
      classification = "character_sanitization";
      confidence = 0.85;
      indicators.push("Character-level filtering detected in 403 response");
    } else if (/signature|pattern|rule.*match|blocked.*request/i.test(responseBody)) {
      classification = "string_matching";
      confidence = 0.85;
      indicators.push("Signature-based string matching detected");
    } else {
      classification = "string_matching";
      confidence = 0.6;
      indicators.push("Generic 403 Forbidden — likely signature match");
    }
  } else if (statusCode === 406) {
    classification = "content_type_rejection";
    confidence = 0.8;
    indicators.push("406 Not Acceptable — content type or encoding rejected");
  } else if (statusCode === 405) {
    classification = "method_restriction";
    confidence = 0.9;
    indicators.push("405 Method Not Allowed");
  } else if (statusCode === 400 && /bad.*request|malformed|invalid/i.test(responseBody)) {
    classification = "character_sanitization";
    confidence = 0.7;
    indicators.push("400 Bad Request with sanitization indicators");
  }

  return {
    classification,
    confidence,
    indicators,
    statusCode,
    responseSnippet: responseBody.slice(0, 500),
  };
}

export function isFiltered(statusCode: number): boolean {
  return [403, 406, 429, 405, 400, 401, 418].includes(statusCode);
}

export function isVerificationSuccess(statusCode: number, prevLength: number, newLength: number): boolean {
  // A change to 200 or 500 from a blocked status, or significant response length change
  if (statusCode === 200 || statusCode === 500) return true;
  if (Math.abs(newLength - prevLength) > 100) return true;
  return false;
}
