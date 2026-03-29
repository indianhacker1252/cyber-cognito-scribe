/**
 * EvolutionaryFuzzer.ts — Dynamic Payload Mutation Genetic Algorithm
 * Evolves payloads through mutation/crossover when a payload is "close"
 * to working (e.g., 500 instead of 403).
 */

export interface PayloadOrganism {
  payload: string;
  fitness: number; // 0-100
  generation: number;
  parentPayload?: string;
  mutationApplied?: string;
}

/**
 * Fitness function: scores how "close" a response was to confirming a vuln.
 */
export function calculateFitness(
  responseStatus: number,
  baselineStatus: number,
  responseLength: number,
  baselineLength: number,
  hasEvidence: boolean
): number {
  let fitness = 0;

  // Direct evidence = maximum fitness
  if (hasEvidence) return 95;

  // Status-based scoring
  if (responseStatus === 200 && baselineStatus === 200) {
    const lengthDiff = Math.abs(responseLength - baselineLength) / Math.max(baselineLength, 1);
    fitness += Math.min(lengthDiff * 100, 50);
  } else if (responseStatus === 500) {
    fitness += 60; // Server error = close to exploitation
  } else if (responseStatus === 200 && baselineStatus !== 200) {
    fitness += 70; // Bypassed something
  } else if (responseStatus === 403 || responseStatus === 406) {
    fitness += 20; // Blocked but detected
  } else if (responseStatus === 429) {
    fitness += 10; // Rate limited
  } else if (responseStatus === 404) {
    fitness += 5; // Not found
  }

  return Math.min(fitness, 100);
}

// ─── Mutation Operators ───────────────────────────────────

const MUTATIONS: Array<{
  name: string;
  mutate: (payload: string) => string;
}> = [
  {
    name: "url_encode_special",
    mutate: (p) => p.replace(/[<>"'&;|`]/g, (c) =>
      `%${c.charCodeAt(0).toString(16).toUpperCase()}`
    ),
  },
  {
    name: "double_url_encode",
    mutate: (p) => p.replace(/[<>"'&;|`]/g, (c) =>
      `%25${c.charCodeAt(0).toString(16).toUpperCase()}`
    ),
  },
  {
    name: "unicode_escape",
    mutate: (p) => p.replace(/[<>"']/g, (c) =>
      `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`
    ),
  },
  {
    name: "html_entity",
    mutate: (p) => p.replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"),
  },
  {
    name: "case_swap",
    mutate: (p) => p.split("").map((c, i) =>
      i % 2 === 0 ? c.toUpperCase() : c.toLowerCase()
    ).join(""),
  },
  {
    name: "whitespace_injection",
    mutate: (p) => p.replace(/ /g, "/**/"),
  },
  {
    name: "null_byte_prefix",
    mutate: (p) => `%00${p}`,
  },
  {
    name: "tab_injection",
    mutate: (p) => p.replace(/ /g, "\t"),
  },
  {
    name: "newline_break",
    mutate: (p) => p.replace(/ /g, "%0a"),
  },
  {
    name: "concat_split",
    mutate: (p) => {
      if (p.includes("SELECT")) return p.replace("SELECT", "SEL"+"ECT");
      if (p.includes("script")) return p.replace("script", "scr"+"ipt");
      return p + "/**/";
    },
  },
];

/**
 * Evolve a payload population using genetic algorithm principles.
 * Takes a parent payload and produces mutated offspring.
 */
export function evolvePayload(
  parentPayload: string,
  parentFitness: number,
  generation: number,
  count = 5
): PayloadOrganism[] {
  const offspring: PayloadOrganism[] = [];

  // Select mutations proportional to how close we are
  const mutationsToApply = parentFitness >= 50
    ? MUTATIONS.slice(0, Math.min(count, MUTATIONS.length)) // Subtle mutations for close hits
    : MUTATIONS; // Try everything for low fitness

  for (let i = 0; i < Math.min(count, mutationsToApply.length); i++) {
    const mutation = mutationsToApply[i];
    const mutated = mutation.mutate(parentPayload);

    // Avoid identical offspring
    if (mutated !== parentPayload) {
      offspring.push({
        payload: mutated,
        fitness: 0, // Will be scored after testing
        generation: generation + 1,
        parentPayload,
        mutationApplied: mutation.name,
      });
    }
  }

  // Crossover: combine two mutation strategies
  if (parentFitness >= 30 && MUTATIONS.length >= 2) {
    const m1 = MUTATIONS[0];
    const m2 = MUTATIONS[5] || MUTATIONS[1];
    const crossed = m2.mutate(m1.mutate(parentPayload));
    if (crossed !== parentPayload) {
      offspring.push({
        payload: crossed,
        fitness: 0,
        generation: generation + 1,
        parentPayload,
        mutationApplied: `crossover(${m1.name}+${m2.name})`,
      });
    }
  }

  return offspring;
}

/**
 * Run a full evolutionary cycle: evolve → test → select fittest → repeat.
 * Returns the best-performing payloads across all generations.
 */
export function selectFittest(
  population: PayloadOrganism[],
  topN = 3
): PayloadOrganism[] {
  return [...population]
    .sort((a, b) => b.fitness - a.fitness)
    .slice(0, topN);
}

/**
 * Determine if a response warrants mutation retry.
 */
export function shouldEvolve(responseStatus: number, baselineStatus: number): boolean {
  // 500 = close to exploitation, 403/406 = WAF blocking
  return (
    responseStatus === 500 ||
    responseStatus === 403 ||
    responseStatus === 406 ||
    (responseStatus === 200 && baselineStatus === 200) // Need deeper differential
  );
}
