/**
 * IntelScraper.ts — Disclosure Harvester
 * Pulls disclosed reports from HackerOne Hacktivity, Bugcrowd,
 * and security RSS feeds. Only processes publicly disclosed, resolved reports.
 */

import { supabase } from "@/integrations/supabase/client";

export interface DisclosedReport {
  source: "hackerone" | "bugcrowd" | "cve-feed" | "exploit-db" | "github-advisory";
  reportId: string;
  title: string;
  summary: string;
  severity: string;
  url: string;
  disclosedAt: string;
  techStack?: string[];
  vulnClass?: string;
}

/**
 * Fetch publicly disclosed reports from HackerOne Hacktivity API.
 * Respects rate limits and only retrieves resolved/disclosed reports.
 */
export async function fetchHackerOneHacktivity(limit = 25): Promise<DisclosedReport[]> {
  const reports: DisclosedReport[] = [];
  
  try {
    // HackerOne public Hacktivity API (disclosed reports only)
    const resp = await fetch(
      `https://hackerone.com/hacktivity/overview?queryString=disclosed%3Atrue&sortField=latest_disclosable_activity_at&sortDirection=DESC&pageIndex=0&limit=${limit}`,
      {
        headers: {
          "Accept": "application/json",
          "User-Agent": "CyberScope-Scanner/1.0 (security-research-tool)",
        },
      }
    );

    if (resp.status === 429) {
      console.warn("HackerOne rate limited — backing off");
      return [];
    }

    if (resp.ok) {
      const data = await resp.json();
      const items = data?.data || data?.hacktivity_items || [];
      
      for (const item of items) {
        const report = item?.node || item;
        if (!report) continue;
        
        reports.push({
          source: "hackerone",
          reportId: report.id || report.databaseId || `h1-${Date.now()}`,
          title: report.title || report.report?.title || "Untitled",
          summary: report.report?.substate || report.severity_rating || "",
          severity: mapH1Severity(report.severity_rating || report.report?.severity_rating),
          url: report.url || `https://hackerone.com/reports/${report.databaseId || report.id}`,
          disclosedAt: report.latest_disclosable_activity_at || report.disclosed_at || new Date().toISOString(),
          vulnClass: report.report?.weakness?.name,
        });
      }
    }
  } catch (e) {
    console.error("HackerOne fetch error:", e);
  }

  return reports;
}

/**
 * Fetch recent CVE advisories from GitHub Advisory Database API.
 */
export async function fetchGitHubAdvisories(limit = 20): Promise<DisclosedReport[]> {
  const reports: DisclosedReport[] = [];

  try {
    const resp = await fetch(
      `https://api.github.com/advisories?type=reviewed&per_page=${limit}`,
      {
        headers: {
          "Accept": "application/vnd.github+json",
          "User-Agent": "CyberScope-Scanner/1.0",
          "X-GitHub-Api-Version": "2022-11-28",
        },
      }
    );

    if (resp.ok) {
      const advisories = await resp.json();
      for (const adv of advisories) {
        const techStack = (adv.vulnerabilities || []).map(
          (v: any) => v.package?.name
        ).filter(Boolean);

        reports.push({
          source: "github-advisory",
          reportId: adv.ghsa_id || adv.cve_id || `gh-${Date.now()}`,
          title: adv.summary || "Untitled Advisory",
          summary: adv.description?.slice(0, 500) || "",
          severity: adv.severity || "medium",
          url: adv.html_url || "",
          disclosedAt: adv.published_at || new Date().toISOString(),
          techStack,
          vulnClass: adv.cwe_ids?.[0],
        });
      }
    }
  } catch (e) {
    console.error("GitHub Advisory fetch error:", e);
  }

  return reports;
}

/**
 * Fetch from Exploit-DB RSS feed for latest exploits.
 */
export async function fetchExploitDB(limit = 15): Promise<DisclosedReport[]> {
  const reports: DisclosedReport[] = [];

  try {
    const resp = await fetch("https://www.exploit-db.com/rss.xml", {
      headers: { "User-Agent": "CyberScope-Scanner/1.0" },
    });

    if (resp.ok) {
      const xml = await resp.text();
      // Simple XML parsing for RSS items
      const items = xml.match(/<item>[\s\S]*?<\/item>/g) || [];
      
      for (const item of items.slice(0, limit)) {
        const title = item.match(/<title>(.*?)<\/title>/)?.[1] || "Untitled";
        const link = item.match(/<link>(.*?)<\/link>/)?.[1] || "";
        const desc = item.match(/<description>(.*?)<\/description>/)?.[1] || "";
        const pubDate = item.match(/<pubDate>(.*?)<\/pubDate>/)?.[1] || "";

        reports.push({
          source: "exploit-db",
          reportId: `edb-${link.split("/").pop() || Date.now()}`,
          title: decodeXmlEntities(title),
          summary: decodeXmlEntities(desc).slice(0, 500),
          severity: "high",
          url: link,
          disclosedAt: pubDate || new Date().toISOString(),
        });
      }
    }
  } catch (e) {
    console.error("ExploitDB fetch error:", e);
  }

  return reports;
}

/**
 * Run full ingestion pipeline from all sources.
 */
export async function ingestAllSources(): Promise<{
  total: number;
  bySource: Record<string, number>;
  newReports: DisclosedReport[];
}> {
  const [h1Reports, ghReports, edbReports] = await Promise.all([
    fetchHackerOneHacktivity(20),
    fetchGitHubAdvisories(15),
    fetchExploitDB(10),
  ]);

  const allReports = [...h1Reports, ...ghReports, ...edbReports];

  // Deduplicate by reportId
  const seen = new Set<string>();
  const newReports = allReports.filter((r) => {
    if (seen.has(r.reportId)) return false;
    seen.add(r.reportId);
    return true;
  });

  return {
    total: newReports.length,
    bySource: {
      hackerone: h1Reports.length,
      "github-advisory": ghReports.length,
      "exploit-db": edbReports.length,
    },
    newReports,
  };
}

// ─── Helpers ───
function mapH1Severity(rating?: string): string {
  const map: Record<string, string> = {
    critical: "critical", high: "high", medium: "medium", low: "low", none: "info",
  };
  return map[(rating || "").toLowerCase()] || "medium";
}

function decodeXmlEntities(str: string): string {
  return str
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/<!\[CDATA\[(.*?)\]\]>/g, "$1");
}
