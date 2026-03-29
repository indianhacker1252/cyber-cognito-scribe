/**
 * MethodExpansion.ts — Autonomous Method Discovery
 * Experiments with alternative HTTP methods and non-standard headers
 * to discover unexpected server behaviors.
 */

import { supabase } from "@/integrations/supabase/client";

export interface MethodDiscovery {
  id: string;
  endpoint_url: string;
  http_method: string;
  custom_headers: Record<string, string>;
  response_status: number | null;
  response_diff_pct: number;
  is_interesting: boolean;
  notes: string | null;
  created_at: string;
}

const METHODS_TO_TRY = ["PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "HEAD", "CONNECT"];

const HEADER_EXPERIMENTS = [
  { "X-Forwarded-For": "127.0.0.1" },
  { "X-Original-URL": "/admin" },
  { "X-Rewrite-URL": "/admin" },
  { "X-Custom-IP-Authorization": "127.0.0.1" },
  { "X-Forwarded-Host": "localhost" },
  { "Content-Type": "application/xml" },
  { "Accept": "application/json" },
  { "X-HTTP-Method-Override": "PUT" },
];

/**
 * Probe an endpoint with alternative HTTP methods.
 * Returns interesting discoveries where the response differs from GET.
 */
export async function probeAlternativeMethods(
  endpointUrl: string,
  baselineStatus: number,
  baselineLength: number,
  targetId?: string
): Promise<MethodDiscovery[]> {
  const discoveries: MethodDiscovery[] = [];

  for (const method of METHODS_TO_TRY) {
    try {
      const resp = await fetch(endpointUrl, {
        method,
        headers: { "User-Agent": "CyberScope-Scanner/1.0" },
        redirect: "manual",
      });
      const body = await resp.text();
      const diffPct = Math.abs(body.length - baselineLength) / Math.max(baselineLength, 1) * 100;

      const isInteresting =
        (resp.status === 200 && method !== "GET" && method !== "HEAD" && method !== "OPTIONS") ||
        (resp.status !== baselineStatus && resp.status !== 405 && resp.status !== 501) ||
        diffPct > 30;

      if (isInteresting || method === "OPTIONS" || method === "TRACE") {
        const record = {
          target_id: targetId || null,
          endpoint_url: endpointUrl,
          http_method: method,
          custom_headers: {},
          response_status: resp.status,
          response_diff_pct: Math.round(diffPct * 100) / 100,
          is_interesting: isInteresting,
          notes: isInteresting
            ? `${method} returned ${resp.status} (baseline GET: ${baselineStatus}), body diff ${diffPct.toFixed(1)}%`
            : `${method} returned expected ${resp.status}`,
        };

        const { data } = await supabase
          .from("method_discoveries" as any)
          .insert(record as any)
          .select("*")
          .single();

        if (data) discoveries.push(data as unknown as MethodDiscovery);
      }

      await new Promise((r) => setTimeout(r, 200));
    } catch {
      // Skip unreachable methods
    }
  }

  return discoveries;
}

/**
 * Probe an endpoint with non-standard headers to find access bypasses.
 */
export async function probeCustomHeaders(
  endpointUrl: string,
  baselineStatus: number,
  targetId?: string
): Promise<MethodDiscovery[]> {
  const discoveries: MethodDiscovery[] = [];

  for (const headerSet of HEADER_EXPERIMENTS) {
    try {
      const resp = await fetch(endpointUrl, {
        method: "GET",
        headers: {
          "User-Agent": "CyberScope-Scanner/1.0",
          ...headerSet,
        },
        redirect: "manual",
      });

      const isInteresting =
        resp.status !== baselineStatus &&
        resp.status !== 404 &&
        resp.status !== 405;

      if (isInteresting) {
        const record = {
          target_id: targetId || null,
          endpoint_url: endpointUrl,
          http_method: "GET",
          custom_headers: headerSet,
          response_status: resp.status,
          response_diff_pct: 0,
          is_interesting: true,
          notes: `Header ${JSON.stringify(headerSet)} changed response from ${baselineStatus} to ${resp.status}`,
        };

        const { data } = await supabase
          .from("method_discoveries" as any)
          .insert(record as any)
          .select("*")
          .single();

        if (data) discoveries.push(data as unknown as MethodDiscovery);
      }

      await new Promise((r) => setTimeout(r, 150));
    } catch {
      // Skip
    }
  }

  return discoveries;
}

/**
 * Get all interesting method discoveries for a target.
 */
export async function getInterestingDiscoveries(
  targetId: string
): Promise<MethodDiscovery[]> {
  const { data } = await supabase
    .from("method_discoveries" as any)
    .select("*")
    .eq("target_id", targetId)
    .eq("is_interesting", true)
    .order("created_at", { ascending: false });

  return (data || []) as unknown as MethodDiscovery[];
}
