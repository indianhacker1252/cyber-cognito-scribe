/**
 * ContextSelector.ts — Context-Aware Payload Selector
 * Selects payloads strictly based on the Tech-Stack discovered during recon.
 * E.g., MySQL payloads for MySQL targets, MongoDB for MongoDB, etc.
 */

import { SECLISTS_MAP } from "./SecListsLoader";

export interface TechContext {
  server?: string;
  framework?: string;
  poweredBy?: string;
  os?: string;
  database?: string;
  language?: string;
  cms?: string;
  waf?: string;
}

export interface PayloadSelection {
  vulnClass: string;
  secListsPaths: string[];
  reason: string;
  priority: number; // 1-10, higher = more relevant
}

// Technology fingerprint → database type mapping
const DB_FINGERPRINTS: Record<string, string> = {
  mysql: "mysql", mariadb: "mysql",
  postgresql: "postgres", postgres: "postgres",
  mssql: "mssql", "sql server": "mssql", sqlserver: "mssql",
  mongodb: "mongodb", mongo: "mongodb",
  oracle: "oracle",
  sqlite: "sqlite",
  redis: "redis",
  couchdb: "couchdb",
};

// Framework → likely vuln class mapping
const FRAMEWORK_VULNS: Record<string, string[]> = {
  django: ["ssti", "sqli-postgres", "path-traversal"],
  flask: ["ssti", "sqli", "cmdi"],
  express: ["nosqli", "rxss", "ssrf"],
  rails: ["sqli-postgres", "ssti", "deserialization"],
  laravel: ["sqli-mysql", "ssti", "path-traversal"],
  spring: ["sqli", "ssti", "deserialization", "xxe"],
  aspnet: ["sqli-mssql", "xxe", "deserialization"],
  wordpress: ["sqli-mysql", "rxss", "path-traversal", "auth-bypass"],
  drupal: ["sqli-mysql", "rxss", "deserialization"],
  joomla: ["sqli-mysql", "rxss", "path-traversal"],
  tomcat: ["path-traversal", "xxe", "deserialization"],
  nginx: ["path-traversal", "ssrf"],
  apache: ["path-traversal", "ssrf"],
  iis: ["path-traversal", "sqli-mssql"],
  php: ["sqli-mysql", "rxss", "lfi", "cmdi", "ssti"],
  node: ["nosqli", "ssrf", "rxss", "ssti"],
  python: ["ssti", "cmdi", "sqli-postgres"],
  java: ["sqli", "xxe", "deserialization", "ssti"],
  ruby: ["sqli-postgres", "ssti", "cmdi"],
};

// WAF-specific bypass file preferences
const WAF_ADAPTATIONS: Record<string, string[]> = {
  cloudflare: ["Fuzzing/XSS/XSS-Bypass-Strings-BruteLogic.txt"],
  akamai: ["Fuzzing/XSS/XSS-Bypass-Strings-BruteLogic.txt"],
  modsecurity: ["Fuzzing/SQLi/Intruder/FUZZDB_SQLi_quick.txt"],
  imperva: ["Fuzzing/XSS/XSS-Cheat-Sheet-PortSwigger.txt"],
};

/**
 * Detect database type from tech stack fingerprint.
 */
function detectDatabase(techStack: TechContext): string | null {
  const allText = [
    techStack.server, techStack.framework, techStack.poweredBy,
    techStack.database, techStack.language,
  ].filter(Boolean).join(" ").toLowerCase();

  for (const [keyword, dbType] of Object.entries(DB_FINGERPRINTS)) {
    if (allText.includes(keyword)) return dbType;
  }
  return null;
}

/**
 * Select the most relevant payloads based on tech stack context.
 */
export function selectPayloads(
  vulnClass: string,
  techStack: TechContext
): PayloadSelection {
  const dbType = detectDatabase(techStack);
  const allText = Object.values(techStack).filter(Boolean).join(" ").toLowerCase();

  // For SQL injection, select DB-specific payloads
  if (vulnClass === "sqli") {
    if (dbType === "mysql") {
      return {
        vulnClass: "sqli-mysql",
        secListsPaths: SECLISTS_MAP["sqli-mysql"] || SECLISTS_MAP["sqli"],
        reason: `MySQL detected — using MySQL-specific SQLi payloads`,
        priority: 9,
      };
    }
    if (dbType === "mssql") {
      return {
        vulnClass: "sqli-mssql",
        secListsPaths: SECLISTS_MAP["sqli-mssql"] || SECLISTS_MAP["sqli"],
        reason: `MSSQL detected — using MSSQL-specific payloads`,
        priority: 9,
      };
    }
    if (dbType === "postgres") {
      return {
        vulnClass: "sqli-postgres",
        secListsPaths: SECLISTS_MAP["sqli-postgres"] || SECLISTS_MAP["sqli"],
        reason: `PostgreSQL detected — using Postgres-specific payloads`,
        priority: 9,
      };
    }
    if (dbType === "mongodb") {
      return {
        vulnClass: "sqli-mongodb",
        secListsPaths: SECLISTS_MAP["sqli-mongodb"] || SECLISTS_MAP["nosqli"],
        reason: `MongoDB detected — switching to NoSQLi payloads`,
        priority: 9,
      };
    }
  }

  // For NoSQLi, check if it's actually a SQL DB
  if (vulnClass === "nosqli" && dbType && !["mongodb", "couchdb", "redis"].includes(dbType)) {
    return {
      vulnClass: "sqli",
      secListsPaths: SECLISTS_MAP["sqli"],
      reason: `Relational DB (${dbType}) detected — using SQLi instead of NoSQLi`,
      priority: 7,
    };
  }

  // WAF-aware payload selection
  const wafName = techStack.waf?.toLowerCase() || "";
  const wafPaths = Object.entries(WAF_ADAPTATIONS).find(([k]) => wafName.includes(k))?.[1] || [];

  // Default: use standard SecLists for the vuln class
  const basePaths = SECLISTS_MAP[vulnClass] || [];
  return {
    vulnClass,
    secListsPaths: [...basePaths, ...wafPaths],
    reason: dbType
      ? `Using ${vulnClass} payloads (detected: ${dbType})`
      : `Using standard ${vulnClass} payloads`,
    priority: 5,
  };
}

/**
 * Get recommended vuln classes to test based on tech stack.
 */
export function getRecommendedVulnClasses(techStack: TechContext): string[] {
  const recommended = new Set<string>();
  const allText = Object.values(techStack).filter(Boolean).join(" ").toLowerCase();

  for (const [tech, classes] of Object.entries(FRAMEWORK_VULNS)) {
    if (allText.includes(tech)) {
      classes.forEach((c) => recommended.add(c));
    }
  }

  // Always include generic classes
  recommended.add("rxss");
  recommended.add("sqli");
  recommended.add("path-traversal");

  return [...recommended];
}
