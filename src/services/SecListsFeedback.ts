/**
 * SecListsFeedback.ts — Error-Based Recognition
 * Listens for "Technology Leak" error messages in scan responses
 * and re-runs scans using exact version-specific SecLists files.
 */

export interface TechLeak {
  technology: string;
  version?: string;
  leakSource: string;
  errorPattern: string;
  recommendedSecLists: string[];
}

// Error patterns that leak technology information
const TECH_LEAK_PATTERNS: Array<{
  pattern: RegExp;
  technology: string;
  extractVersion?: (match: RegExpMatchArray) => string | undefined;
  secListsPaths: string[];
}> = [
  // Database errors
  {
    pattern: /MySQL.*?(\d+\.\d+(?:\.\d+)?)/i,
    technology: "MySQL",
    extractVersion: (m) => m[1],
    secListsPaths: ["Fuzzing/Databases/MySQL.fuzzdb.txt", "Fuzzing/Databases/MySQL-SQLi-Login-Bypass.fuzzdb.txt"],
  },
  {
    pattern: /PostgreSQL.*?(\d+\.\d+)/i,
    technology: "PostgreSQL",
    extractVersion: (m) => m[1],
    secListsPaths: ["Fuzzing/Databases/Postgres-Enumeration.fuzzdb.txt"],
  },
  {
    pattern: /Microsoft SQL Server.*?(\d+\.\d+)/i,
    technology: "MSSQL",
    extractVersion: (m) => m[1],
    secListsPaths: ["Fuzzing/Databases/MSSQL.fuzzdb.txt", "Fuzzing/Databases/MSSQL-Enumeration.fuzzdb.txt"],
  },
  {
    pattern: /ORA-\d{4,5}/i,
    technology: "Oracle",
    secListsPaths: ["Fuzzing/Databases/Oracle.fuzzdb.txt"],
  },
  {
    pattern: /MongoDB.*?(\d+\.\d+)/i,
    technology: "MongoDB",
    extractVersion: (m) => m[1],
    secListsPaths: ["Fuzzing/Databases/MongoDB.fuzzdb.txt", "Fuzzing/NoSQL-Injection/NoSQLi.txt"],
  },

  // Web server errors
  {
    pattern: /Apache\/(\d+\.\d+(?:\.\d+)?)/i,
    technology: "Apache",
    extractVersion: (m) => m[1],
    secListsPaths: ["Fuzzing/LFI/LFI-Jhaddix.txt"],
  },
  {
    pattern: /nginx\/(\d+\.\d+(?:\.\d+)?)/i,
    technology: "Nginx",
    extractVersion: (m) => m[1],
    secListsPaths: ["Fuzzing/LFI/LFI-Jhaddix.txt"],
  },
  {
    pattern: /Microsoft-IIS\/(\d+\.\d+)/i,
    technology: "IIS",
    extractVersion: (m) => m[1],
    secListsPaths: ["Fuzzing/LFI/LFI-gracefulsecurity-windows.txt"],
  },

  // Framework errors
  {
    pattern: /PHP\/(\d+\.\d+(?:\.\d+)?)/i,
    technology: "PHP",
    extractVersion: (m) => m[1],
    secListsPaths: ["Fuzzing/LFI/LFI-gracefulsecurity-linux.txt"],
  },
  {
    pattern: /ASP\.NET|System\.Web/i,
    technology: "ASP.NET",
    secListsPaths: ["Fuzzing/LFI/LFI-gracefulsecurity-windows.txt"],
  },
  {
    pattern: /Django|DjangoTemplates/i,
    technology: "Django",
    secListsPaths: ["Fuzzing/SSI-Injection/SSI-Injection.txt"],
  },
  {
    pattern: /Rails|ActionController/i,
    technology: "Ruby on Rails",
    secListsPaths: ["Fuzzing/SSI-Injection/SSI-Injection.txt"],
  },
  {
    pattern: /Express|node_modules/i,
    technology: "Node.js/Express",
    secListsPaths: ["Fuzzing/NoSQL-Injection/NoSQLi.txt"],
  },

  // Java/Tomcat errors
  {
    pattern: /java\.lang\.|javax\.|org\.apache\.catalina/i,
    technology: "Java/Tomcat",
    secListsPaths: ["Fuzzing/LFI/LFI-Jhaddix.txt"],
  },
  {
    pattern: /Struts|OGNL/i,
    technology: "Apache Struts",
    secListsPaths: ["Fuzzing/SSI-Injection/SSI-Injection.txt"],
  },

  // Stack trace leaks
  {
    pattern: /stack\s*trace|Traceback\s*\(most recent/i,
    technology: "Debug Mode",
    secListsPaths: [],
  },
  {
    pattern: /SQLSTATE\[(\w+)\]/i,
    technology: "PDO/PHP",
    secListsPaths: ["Fuzzing/SQLi/Generic-SQLi.txt"],
  },
];

/**
 * Analyze a response body for technology leak patterns.
 * Returns detected leaks with recommended SecLists files.
 */
export function detectTechLeaks(responseBody: string, responseHeaders?: Record<string, string>): TechLeak[] {
  const leaks: TechLeak[] = [];
  const textToScan = responseBody + " " + Object.values(responseHeaders || {}).join(" ");

  for (const entry of TECH_LEAK_PATTERNS) {
    const match = textToScan.match(entry.pattern);
    if (match) {
      leaks.push({
        technology: entry.technology,
        version: entry.extractVersion?.(match),
        leakSource: match[0].slice(0, 100),
        errorPattern: entry.pattern.source,
        recommendedSecLists: entry.secListsPaths,
      });
    }
  }

  return leaks;
}

/**
 * Determine if a tech leak warrants a targeted rescan.
 */
export function shouldRescanWithSpecificPayloads(leaks: TechLeak[]): boolean {
  return leaks.some((l) => l.recommendedSecLists.length > 0 && l.version);
}

/**
 * Get the most specific SecLists paths based on detected leaks.
 */
export function getLeakBasedPaths(leaks: TechLeak[]): string[] {
  const paths = new Set<string>();
  for (const leak of leaks) {
    for (const path of leak.recommendedSecLists) {
      paths.add(path);
    }
  }
  return [...paths];
}
