/**
 * SyncCron.ts — Daily Sync Scheduler
 * Implements a 24-hour synchronization cycle. Every morning, CyberScope
 * ingests the last 24 hours of global security research and updates
 * the Memory Vault (Phase 8 Experience Vault).
 */

import { supabase } from "@/integrations/supabase/client";

export interface SyncRunStatus {
  id: string;
  startedAt: string;
  completedAt: string | null;
  reportsFetched: number;
  reportsProcessed: number;
  templatesGenerated: number;
  rescansTriggered: number;
  status: "running" | "completed" | "failed";
  errorMessage: string | null;
}

/**
 * Trigger a manual sync run via the edge function.
 */
export async function triggerManualSync(): Promise<{ syncRunId: string; success: boolean; error?: string }> {
  try {
    const { data, error } = await supabase.functions.invoke("intel-sync", {
      body: { action: "full-sync" },
    });

    if (error) throw error;

    return {
      syncRunId: data?.syncRunId || "",
      success: true,
    };
  } catch (e) {
    return {
      syncRunId: "",
      success: false,
      error: e instanceof Error ? e.message : "Unknown error",
    };
  }
}

/**
 * Get the latest sync run status.
 */
export async function getLatestSyncStatus(): Promise<SyncRunStatus | null> {
  const { data } = await supabase
    .from("intel_sync_runs")
    .select("*")
    .order("started_at", { ascending: false })
    .limit(1)
    .single();

  if (!data) return null;

  return {
    id: data.id,
    startedAt: data.started_at,
    completedAt: data.completed_at,
    reportsFetched: data.reports_fetched || 0,
    reportsProcessed: data.reports_processed || 0,
    templatesGenerated: data.templates_generated || 0,
    rescansTriggered: data.rescans_triggered || 0,
    status: data.status as SyncRunStatus["status"],
    errorMessage: data.error_message,
  };
}

/**
 * Get sync run history.
 */
export async function getSyncHistory(limit = 10): Promise<SyncRunStatus[]> {
  const { data } = await supabase
    .from("intel_sync_runs")
    .select("*")
    .order("started_at", { ascending: false })
    .limit(limit);

  if (!data) return [];

  return data.map((d: any) => ({
    id: d.id,
    startedAt: d.started_at,
    completedAt: d.completed_at,
    reportsFetched: d.reports_fetched || 0,
    reportsProcessed: d.reports_processed || 0,
    templatesGenerated: d.templates_generated || 0,
    rescansTriggered: d.rescans_triggered || 0,
    status: d.status,
    errorMessage: d.error_message,
  }));
}

/**
 * Get all intel feed entries.
 */
export async function getIntelFeeds(params?: {
  status?: string;
  signalStrength?: string;
  limit?: number;
}): Promise<any[]> {
  let query = supabase
    .from("intel_feeds")
    .select("*")
    .order("ingested_at", { ascending: false });

  if (params?.status) query = query.eq("status", params.status);
  if (params?.signalStrength) query = query.eq("signal_strength", params.signalStrength);
  if (params?.limit) query = query.limit(params.limit);

  const { data } = await query;
  return data || [];
}

/**
 * Delete old sync runs older than N days.
 */
export async function cleanupOldSyncRuns(olderThanDays = 30): Promise<number> {
  const cutoff = new Date();
  cutoff.setDate(cutoff.getDate() - olderThanDays);

  const { data } = await supabase
    .from("intel_sync_runs")
    .delete()
    .lt("started_at", cutoff.toISOString())
    .select("id");

  return data?.length || 0;
}
