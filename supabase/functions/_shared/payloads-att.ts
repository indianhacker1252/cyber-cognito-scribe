// PayloadsAllTheThings integration — fetches curated payload lists from
// swisskyrepo/PayloadsAllTheThings on-demand, caches in memory per Edge
// Function warm instance, and exposes a normalized API by vuln class.
//
// This does NOT replace AI mutation — it seeds the AI with real-world
// operator payloads (WAF-tested, tool-vetted) that the LLM then mutates
// contextually. See ai-mutator.ts for the mutation loop.

const RAW_BASE = "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master";

// Vuln class -> list of raw file paths (curated, small, high-signal).
// Kept small on purpose: bulk lists hurt more than help because they
// blow out request budgets and generate false positives.
const CLASS_MAP: Record<string, string[]> = {
  xss: [
    "/XSS%20Injection/Intruders/BRUTELOGIC-XSS.txt",
    "/XSS%20Injection/Intruders/xss-polyglots.txt",
  ],
  sqli: [
    "/SQL%20Injection/Intruder/Auth_Bypass.txt",
    "/SQL%20Injection/Intruder/payloads-sql-blind-MSSQL-INSERT-boolean.txt",
    "/SQL%20Injection/Intruder/payloads-sql-blind-MySQL-INSERT-boolean.txt",
  ],
  ssti: ["/Server%20Side%20Template%20Injection/Intruder/ssti.fuzz"],
  ssrf: ["/Server%20Side%20Request%20Forgery/Intruder/SSRF-URLs.txt"],
  cmdi: [
    "/Command%20Injection/Intruder/command_exec.txt",
    "/Command%20Injection/Intruder/command_exec_extension.txt",
  ],
  lfi: ["/File%20Inclusion/Intruders/JHADDIX_LFI.txt"],
  xxe: ["/XXE%20Injection/Intruders/XXE_Fuzzing.txt"],
  nosql: ["/NoSQL%20Injection/Intruder/NoSQL.txt"],
  openredirect: ["/Open%20Redirect/Intruder/Open-Redirect-payloads.txt"],
  ldap: ["/LDAP%20Injection/Intruder/LDAP_FUZZ.txt"],
  crlf: ["/CRLF%20Injection/Intruder/CRLF-injection.txt"],
};

// In-memory cache per warm instance (Edge Functions are killed after ~a few
// minutes idle, so this is effectively a soft TTL).
const cache = new Map<string, { at: number; lines: string[] }>();
const TTL_MS = 15 * 60_000;

async function fetchOne(path: string, signal?: AbortSignal): Promise<string[]> {
  const cached = cache.get(path);
  if (cached && Date.now() - cached.at < TTL_MS) return cached.lines;
  try {
    const r = await fetch(RAW_BASE + path, { signal });
    if (!r.ok) return [];
    const text = await r.text();
    const lines = text
      .split(/\r?\n/)
      .map((l) => l.replace(/^\s+|\s+$/g, ""))
      .filter((l) => l.length > 0 && !l.startsWith("#"))
      .slice(0, 200); // cap per file
    cache.set(path, { at: Date.now(), lines });
    return lines;
  } catch {
    return [];
  }
}

/**
 * Return curated seed payloads for a vuln class. Result is capped at `max`
 * and shuffled so different fuzzer runs pull different subsets.
 */
export async function getSeedPayloads(vulnClass: string, max = 40, timeoutMs = 5000): Promise<string[]> {
  const key = vulnClass.toLowerCase().replace(/[^a-z]/g, "");
  const paths = CLASS_MAP[key] || [];
  if (!paths.length) return [];
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const all = (await Promise.all(paths.map((p) => fetchOne(p, controller.signal)))).flat();
    // Shuffle
    for (let i = all.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [all[i], all[j]] = [all[j], all[i]];
    }
    return all.slice(0, max);
  } finally {
    clearTimeout(t);
  }
}

export function supportedClasses(): string[] {
  return Object.keys(CLASS_MAP);
}
