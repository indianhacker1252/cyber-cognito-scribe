/**
 * AdaptiveStrategy - Dynamic Heuristic Adaptation
 * Provides transformation functions to adapt verification tests
 * based on filter classifications.
 */

import type { FilterClassification } from "./HeuristicAnalyst";

export type AdaptationType = "encoding" | "structural" | "protocol";

export interface AdaptationStep {
  type: AdaptationType;
  name: string;
  description: string;
  transform: (input: string) => string;
}

// Encoding adaptations
const urlEncode = (s: string): string =>
  s.replace(/[^a-zA-Z0-9_.~-]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

const doubleHexEncode = (s: string): string =>
  s.replace(/[^a-zA-Z0-9]/g, (c) => `%25${c.charCodeAt(0).toString(16).toUpperCase()}`);

const unicodeEscape = (s: string): string =>
  s.replace(/['"<>&]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);

// Structural adaptations
const whitespaceVariation = (s: string): string =>
  s.replace(/ /g, "  ").replace(/\t/g, "    ");

const alternativeOperators = (s: string): string =>
  s.replace(/\bOR\b/gi, "||").replace(/\bAND\b/gi, "&&").replace(/\bNOT\b/gi, "!");

const jsonWrapper = (s: string): string =>
  JSON.stringify({ data: s, format: "text" });

const xmlWrapper = (s: string): string =>
  `<?xml version="1.0"?><request><data><![CDATA[${s}]]></data></request>`;

// Protocol adaptations
const chunkedPayload = (s: string): string => {
  const chunks: string[] = [];
  for (let i = 0; i < s.length; i += 10) {
    chunks.push(s.slice(i, i + 10));
  }
  return chunks.join("\r\n");
};

const headerManipulation = (s: string): string =>
  s; // Identity — the actual header changes happen at request level

const ADAPTATION_LIBRARY: Record<FilterClassification, AdaptationStep[]> = {
  string_matching: [
    { type: "encoding", name: "URL Encoding", description: "Apply URL percent-encoding to special characters", transform: urlEncode },
    { type: "encoding", name: "Double Hex Encoding", description: "Apply double hex encoding to evade single-pass decoders", transform: doubleHexEncode },
    { type: "structural", name: "JSON Wrapping", description: "Wrap payload in valid JSON structure", transform: jsonWrapper },
  ],
  character_sanitization: [
    { type: "encoding", name: "Unicode Escape", description: "Replace filtered characters with Unicode escape sequences", transform: unicodeEscape },
    { type: "structural", name: "Whitespace Variation", description: "Vary whitespace to avoid exact pattern matches", transform: whitespaceVariation },
    { type: "encoding", name: "URL Encoding", description: "Apply URL percent-encoding", transform: urlEncode },
  ],
  rate_limiting: [
    { type: "protocol", name: "Chunked Payload", description: "Split payload into smaller chunks", transform: chunkedPayload },
    { type: "structural", name: "Alternative Operators", description: "Use alternative logical operator syntax", transform: alternativeOperators },
    { type: "protocol", name: "Header Manipulation", description: "Adjust request headers for rate-limit mitigation", transform: headerManipulation },
  ],
  ip_blocking: [
    { type: "protocol", name: "Header Manipulation", description: "Add forwarded-for headers", transform: headerManipulation },
    { type: "encoding", name: "URL Encoding", description: "Apply URL encoding", transform: urlEncode },
    { type: "structural", name: "JSON Wrapping", description: "Wrap in JSON structure", transform: jsonWrapper },
  ],
  method_restriction: [
    { type: "protocol", name: "Header Manipulation", description: "Use X-HTTP-Method-Override header", transform: headerManipulation },
    { type: "structural", name: "XML Wrapping", description: "Wrap payload in XML structure", transform: xmlWrapper },
    { type: "encoding", name: "URL Encoding", description: "Apply URL encoding", transform: urlEncode },
  ],
  content_type_rejection: [
    { type: "structural", name: "JSON Wrapping", description: "Present payload as valid JSON", transform: jsonWrapper },
    { type: "structural", name: "XML Wrapping", description: "Present payload as valid XML", transform: xmlWrapper },
    { type: "encoding", name: "Unicode Escape", description: "Use Unicode escape sequences", transform: unicodeEscape },
  ],
  unknown: [
    { type: "encoding", name: "URL Encoding", description: "Apply URL encoding as generic adaptation", transform: urlEncode },
    { type: "structural", name: "Whitespace Variation", description: "Vary whitespace patterns", transform: whitespaceVariation },
    { type: "structural", name: "JSON Wrapping", description: "Wrap in JSON structure", transform: jsonWrapper },
  ],
};

export function getAdaptationStrategies(classification: FilterClassification): AdaptationStep[] {
  return ADAPTATION_LIBRARY[classification] || ADAPTATION_LIBRARY.unknown;
}

export function applyAdaptation(input: string, step: AdaptationStep): string {
  return step.transform(input);
}
