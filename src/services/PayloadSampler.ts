/**
 * PayloadSampler.ts — Smart Sample Generator
 * Implements Smart Sampling: Quick Scan (Top 20), Deep Scan (Top 500), Full Fuzz.
 * Uses reputation scoring to prioritize the most effective payloads.
 */

export type ScanMode = "quick" | "deep" | "full";

export interface SamplingConfig {
  mode: ScanMode;
  maxPayloads: number;
  label: string;
  description: string;
}

export const SCAN_MODES: Record<ScanMode, SamplingConfig> = {
  quick: {
    mode: "quick",
    maxPayloads: 20,
    label: "Quick Scan",
    description: "Top 20 highest-rated payloads for fast verification",
  },
  deep: {
    mode: "deep",
    maxPayloads: 500,
    label: "Deep Scan",
    description: "Top 500 payloads with mutation variants for thorough testing",
  },
  full: {
    mode: "full",
    maxPayloads: Infinity,
    label: "Full Fuzz",
    description: "All available payloads — comprehensive but slow",
  },
};

export interface RankedPayload {
  payload: string;
  score: number; // 0-100 reputation score
  source: string;
}

/**
 * Sample payloads from a list based on scan mode.
 * Uses stratified sampling to ensure diversity.
 */
export function samplePayloads(
  payloads: string[],
  mode: ScanMode,
  reputationScores?: Map<string, number>
): RankedPayload[] {
  const config = SCAN_MODES[mode];

  // Score each payload
  const ranked: RankedPayload[] = payloads.map((p) => ({
    payload: p,
    score: reputationScores?.get(p) ?? estimatePayloadScore(p),
    source: "seclists",
  }));

  // Sort by score descending
  ranked.sort((a, b) => b.score - a.score);

  // For full mode, return everything
  if (mode === "full") return ranked;

  // For quick/deep, take top N with diversity guarantee
  const selected: RankedPayload[] = [];
  const seenPrefixes = new Set<string>();

  for (const item of ranked) {
    if (selected.length >= config.maxPayloads) break;

    // Ensure diversity: don't pick too many payloads with same prefix
    const prefix = item.payload.slice(0, 10).toLowerCase();
    const prefixCount = [...seenPrefixes].filter((p) => p === prefix).length;
    if (prefixCount >= 3 && mode === "quick") continue;

    selected.push(item);
    seenPrefixes.add(prefix);
  }

  return selected;
}

/**
 * Estimate a payload's effectiveness score based on heuristics.
 * Used when no historical reputation data is available.
 */
function estimatePayloadScore(payload: string): number {
  let score = 50; // baseline

  // Shorter payloads tend to bypass filters better
  if (payload.length < 30) score += 10;
  if (payload.length < 15) score += 5;

  // Encoded payloads may bypass WAFs
  if (payload.includes("%") || payload.includes("\\u")) score += 8;

  // Common effective patterns
  if (/UNION\s+SELECT/i.test(payload)) score += 12;
  if (/OR\s+1\s*=\s*1/i.test(payload)) score += 10;
  if (/<script/i.test(payload)) score += 8;
  if (/\.\.\//.test(payload)) score += 8;
  if (/\$\{/.test(payload) || /\{\{/.test(payload)) score += 10;
  if (/onerror|onload|onfocus/i.test(payload)) score += 10;

  // Penalize overly long or complex payloads
  if (payload.length > 200) score -= 10;
  if (payload.length > 500) score -= 15;

  return Math.max(0, Math.min(100, score));
}

/**
 * Merge payloads from multiple sources, deduplicate, and rank.
 */
export function mergeAndRank(
  secListsPayloads: string[],
  experienceVaultPayloads: string[],
  customPayloads: string[],
  mode: ScanMode,
  reputationScores?: Map<string, number>
): RankedPayload[] {
  // Experience vault payloads get a bonus
  const allPayloads = new Map<string, number>();

  for (const p of customPayloads) {
    allPayloads.set(p, (reputationScores?.get(p) ?? 80) + 15);
  }
  for (const p of experienceVaultPayloads) {
    if (!allPayloads.has(p)) {
      allPayloads.set(p, (reputationScores?.get(p) ?? 70) + 10);
    }
  }
  for (const p of secListsPayloads) {
    if (!allPayloads.has(p)) {
      allPayloads.set(p, reputationScores?.get(p) ?? estimatePayloadScore(p));
    }
  }

  const ranked: RankedPayload[] = [...allPayloads.entries()].map(([payload, score]) => ({
    payload,
    score,
    source: customPayloads.includes(payload) ? "custom"
      : experienceVaultPayloads.includes(payload) ? "experience_vault"
      : "seclists",
  }));

  ranked.sort((a, b) => b.score - a.score);

  const config = SCAN_MODES[mode];
  return mode === "full" ? ranked : ranked.slice(0, config.maxPayloads);
}
