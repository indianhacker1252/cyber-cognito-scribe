/**
 * DomWatcher.ts — Headless Browser Harness
 * Monitors DOM modifications and JS events via edge function
 * to catch vulnerabilities that static scanners miss.
 */

import { supabase } from "@/integrations/supabase/client";

export interface DomWatchResult {
  domModifications: DomModification[];
  consoleMessages: string[];
  networkRequests: string[];
  eventListeners: EventListenerInfo[];
  xssTriggered: boolean;
  postMessageHandlers: number;
  dangerousEvals: number;
}

export interface DomModification {
  type: "innerHTML" | "script_inject" | "attribute_change" | "form_action";
  element: string;
  detail: string;
  dangerous: boolean;
}

export interface EventListenerInfo {
  type: string;
  target: string;
  hasDangerousHandler: boolean;
}

/**
 * Request headless browser analysis of a URL via edge function.
 */
export async function watchDom(
  targetUrl: string,
  payload?: string
): Promise<DomWatchResult> {
  try {
    const { data, error } = await supabase.functions.invoke("validate-finding", {
      body: {
        action: "dom-watch",
        targetUrl,
        payload: payload || "",
      },
    });

    if (error) throw error;

    return {
      domModifications: data?.domModifications || [],
      consoleMessages: data?.consoleMessages || [],
      networkRequests: data?.networkRequests || [],
      eventListeners: data?.eventListeners || [],
      xssTriggered: data?.xssTriggered || false,
      postMessageHandlers: data?.postMessageHandlers || 0,
      dangerousEvals: data?.dangerousEvals || 0,
    };
  } catch {
    return {
      domModifications: [],
      consoleMessages: [],
      networkRequests: [],
      eventListeners: [],
      xssTriggered: false,
      postMessageHandlers: 0,
      dangerousEvals: 0,
    };
  }
}

/**
 * Static DOM analysis: check response HTML for dangerous patterns.
 * Used as a lightweight alternative when headless browser isn't available.
 */
export function staticDomAnalysis(html: string): {
  dangerousPatterns: Array<{ pattern: string; context: string }>;
  riskScore: number;
} {
  const patterns: Array<{ regex: RegExp; name: string; risk: number }> = [
    { regex: /innerHTML\s*=\s*[^;]+/gi, name: "innerHTML assignment", risk: 8 },
    { regex: /document\.write\s*\(/gi, name: "document.write", risk: 9 },
    { regex: /eval\s*\(/gi, name: "eval() call", risk: 10 },
    { regex: /setTimeout\s*\(\s*['"`]/gi, name: "setTimeout with string", risk: 7 },
    { regex: /setInterval\s*\(\s*['"`]/gi, name: "setInterval with string", risk: 7 },
    { regex: /on\w+\s*=\s*['"][^'"]*['"](?=[^a-z])/gi, name: "inline event handler", risk: 6 },
    { regex: /window\.addEventListener\s*\(\s*['"]message['"]/gi, name: "postMessage listener", risk: 7 },
    { regex: /\.src\s*=\s*[^;]+(?:location|document|window)/gi, name: "dynamic src assignment", risk: 8 },
    { regex: /new\s+Function\s*\(/gi, name: "Function constructor", risk: 9 },
    { regex: /javascript\s*:/gi, name: "javascript: URI", risk: 8 },
  ];

  const found: Array<{ pattern: string; context: string }> = [];
  let totalRisk = 0;

  for (const { regex, name, risk } of patterns) {
    const matches = html.match(regex);
    if (matches) {
      for (const match of matches.slice(0, 3)) {
        const idx = html.indexOf(match);
        const context = html.substring(Math.max(0, idx - 30), idx + match.length + 30);
        found.push({ pattern: name, context: context.replace(/\n/g, " ").trim() });
      }
      totalRisk += risk * matches.length;
    }
  }

  return {
    dangerousPatterns: found,
    riskScore: Math.min(100, totalRisk),
  };
}
