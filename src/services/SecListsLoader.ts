/**
 * SecListsLoader.ts — SecLists Asset Manager
 * Maps vulnerability classes to specific SecLists directories and provides
 * curated payload sets from the SecLists repository via GitHub raw content.
 */

const SECLISTS_BASE = "https://raw.githubusercontent.com/danielmiessler/SecLists/master";

// Mapping of vulnerability classes to SecLists file paths
export const SECLISTS_MAP: Record<string, string[]> = {
  sqli: [
    "Fuzzing/SQLi/Generic-SQLi.txt",
    "Fuzzing/SQLi/quick-SQLi.txt",
    "Fuzzing/SQLi/Intruder/FUZZDB_SQLi_quick.txt",
  ],
  "sqli-mysql": [
    "Fuzzing/SQLi/Generic-SQLi.txt",
    "Fuzzing/Databases/MySQL-SQLi-Login-Bypass.fuzzdb.txt",
    "Fuzzing/Databases/MySQL.fuzzdb.txt",
  ],
  "sqli-mssql": [
    "Fuzzing/SQLi/Generic-SQLi.txt",
    "Fuzzing/Databases/MSSQL-Enumeration.fuzzdb.txt",
    "Fuzzing/Databases/MSSQL.fuzzdb.txt",
  ],
  "sqli-postgres": [
    "Fuzzing/SQLi/Generic-SQLi.txt",
    "Fuzzing/Databases/Postgres-Enumeration.fuzzdb.txt",
  ],
  "sqli-mongodb": [
    "Fuzzing/Databases/MongoDB.fuzzdb.txt",
    "Fuzzing/NoSQL-Injection/NoSQLi.txt",
  ],
  nosqli: [
    "Fuzzing/NoSQL-Injection/NoSQLi.txt",
  ],
  rxss: [
    "Fuzzing/XSS/XSS-Bypass-Strings-BruteLogic.txt",
    "Fuzzing/XSS/XSS-Cheat-Sheet-PortSwigger.txt",
    "Fuzzing/XSS/xss-without-parentheses-semi-colons.txt",
  ],
  "stored-xss": [
    "Fuzzing/XSS/XSS-Bypass-Strings-BruteLogic.txt",
    "Fuzzing/XSS/XSS-Cheat-Sheet-PortSwigger.txt",
  ],
  cmdi: [
    "Fuzzing/command-injection-commix.txt",
    "Fuzzing/LDAP-Injection.txt",
  ],
  "path-traversal": [
    "Fuzzing/LFI/LFI-Jhaddix.txt",
    "Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt",
  ],
  lfi: [
    "Fuzzing/LFI/LFI-Jhaddix.txt",
    "Fuzzing/LFI/LFI-gracefulsecurity-linux.txt",
    "Fuzzing/LFI/LFI-gracefulsecurity-windows.txt",
  ],
  ssti: [
    "Fuzzing/SSI-Injection/SSI-Injection.txt",
    "Fuzzing/template-engines-special-vars.txt",
  ],
  xxe: [
    "Fuzzing/XXE-Fuzzing.txt",
  ],
  ssrf: [
    "Fuzzing/SSRF/SSRF.txt",
  ],
  "open-redirect": [
    "Fuzzing/open-redirect-payloads.txt",
  ],
  "auth-bypass": [
    "Fuzzing/SQLi/quick-SQLi.txt",
    "Passwords/Default-Credentials/default-passwords.csv",
  ],
  discovery: [
    "Discovery/Web-Content/common.txt",
    "Discovery/Web-Content/directory-list-2.3-small.txt",
    "Discovery/Web-Content/raft-small-words.txt",
  ],
};

// In-memory cache for fetched payloads
const payloadCache = new Map<string, string[]>();

/**
 * Fetch a SecLists file from GitHub and return lines as an array.
 * Results are cached in memory for the session.
 */
export async function fetchSecListFile(filePath: string): Promise<string[]> {
  if (payloadCache.has(filePath)) {
    return payloadCache.get(filePath)!;
  }

  try {
    const url = `${SECLISTS_BASE}/${filePath}`;
    const resp = await fetch(url, {
      headers: { "User-Agent": "CyberScope-Scanner/1.0" },
    });

    if (!resp.ok) {
      console.warn(`SecLists fetch failed for ${filePath}: ${resp.status}`);
      return [];
    }

    const text = await resp.text();
    const lines = text
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l.length > 0 && !l.startsWith("#"));

    payloadCache.set(filePath, lines);
    return lines;
  } catch (err) {
    console.error(`SecLists fetch error for ${filePath}:`, err);
    return [];
  }
}

/**
 * Get all SecLists file paths for a given vulnerability class.
 */
export function getSecListPaths(vulnClass: string): string[] {
  return SECLISTS_MAP[vulnClass] || SECLISTS_MAP["sqli"] || [];
}

/**
 * Load all payloads for a vulnerability class (merged from all mapped files).
 */
export async function loadPayloadsForClass(vulnClass: string): Promise<string[]> {
  const paths = getSecListPaths(vulnClass);
  const allPayloads: string[] = [];

  for (const path of paths) {
    const lines = await fetchSecListFile(path);
    allPayloads.push(...lines);
  }

  // Deduplicate
  return [...new Set(allPayloads)];
}

/**
 * Clear the in-memory cache.
 */
export function clearCache(): void {
  payloadCache.clear();
}
