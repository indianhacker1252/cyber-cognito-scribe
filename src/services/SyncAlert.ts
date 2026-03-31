/**
 * SyncAlert.ts — Intelligence-Driven Notification System
 * Creates dashboard notifications when new disclosures match targets
 * and updates the Evidence Vault with original research links.
 */

import { supabase } from "@/integrations/supabase/client";

export interface IntelNotification {
  id: string;
  intelFeedId: string;
  targetId: string | null;
  type: "new_disclosure" | "rescan_initiated" | "match_found" | "template_ready";
  title: string;
  message: string;
  isRead: boolean;
  actionUrl?: string;
  createdAt: string;
}

/**
 * Create a notification for a new disclosure that matches a target.
 */
export async function notifyDisclosureMatch(params: {
  intelFeedId: string;
  targetId: string;
  targetName: string;
  reportTitle: string;
  reportUrl: string;
  vulnClass: string;
  signalStrength: string;
}): Promise<void> {
  const emoji = params.signalStrength === "high" ? "🔴" : params.signalStrength === "medium" ? "🟡" : "🟢";

  await supabase.from("intel_notifications").insert({
    intel_feed_id: params.intelFeedId,
    target_id: params.targetId,
    notification_type: "match_found",
    title: `${emoji} New ${params.vulnClass.toUpperCase()} disclosure matches ${params.targetName}`,
    message: `"${params.reportTitle}" may affect ${params.targetName}. Re-verification initiated.`,
    action_url: params.reportUrl,
  });
}

/**
 * Create a notification for a rescan being triggered.
 */
export async function notifyRescanInitiated(params: {
  intelFeedId: string;
  targetId: string;
  targetName: string;
  vulnClass: string;
}): Promise<void> {
  await supabase.from("intel_notifications").insert({
    intel_feed_id: params.intelFeedId,
    target_id: params.targetId,
    notification_type: "rescan_initiated",
    title: `🔄 Delta scan initiated on ${params.targetName}`,
    message: `New ${params.vulnClass} intelligence triggered a re-scan of ${params.targetName}.`,
  });
}

/**
 * Create a notification when a new template is generated.
 */
export async function notifyTemplateReady(params: {
  intelFeedId: string;
  templateName: string;
  vulnClass: string;
  payloadCount: number;
}): Promise<void> {
  await supabase.from("intel_notifications").insert({
    intel_feed_id: params.intelFeedId,
    notification_type: "template_ready",
    title: `📋 New test template: ${params.templateName}`,
    message: `${params.payloadCount} payloads for ${params.vulnClass} extracted from disclosure. Template ready for deployment.`,
  });
}

/**
 * Fetch unread notifications for the dashboard.
 */
export async function fetchUnreadNotifications(limit = 20): Promise<IntelNotification[]> {
  const { data, error } = await supabase
    .from("intel_notifications")
    .select("*")
    .eq("is_read", false)
    .order("created_at", { ascending: false })
    .limit(limit);

  if (error || !data) return [];

  return data.map((n: any) => ({
    id: n.id,
    intelFeedId: n.intel_feed_id,
    targetId: n.target_id,
    type: n.notification_type,
    title: n.title,
    message: n.message,
    isRead: n.is_read,
    actionUrl: n.action_url,
    createdAt: n.created_at,
  }));
}

/**
 * Mark notifications as read.
 */
export async function markNotificationsRead(ids: string[]): Promise<void> {
  await supabase
    .from("intel_notifications")
    .update({ is_read: true })
    .in("id", ids);
}

/**
 * Mark all notifications as read.
 */
export async function markAllRead(): Promise<void> {
  await supabase
    .from("intel_notifications")
    .update({ is_read: true })
    .eq("is_read", false);
}

/**
 * Update a finding's evidence with the original research link.
 */
export async function linkResearchToFinding(params: {
  findingId: string;
  reportUrl: string;
  reportTitle: string;
  source: string;
}): Promise<void> {
  const { data: finding } = await supabase
    .from("vulnerability_findings")
    .select("description, triage_reasoning")
    .eq("id", params.findingId)
    .single();

  if (finding) {
    const updatedDesc = `${finding.description || ""}\n\n📚 **Related Research:** [${params.reportTitle}](${params.reportUrl}) (Source: ${params.source})`;
    const updatedReasoning = `${finding.triage_reasoning || ""} | Intel-correlated: ${params.source}`;

    await supabase
      .from("vulnerability_findings")
      .update({
        description: updatedDesc,
        triage_reasoning: updatedReasoning,
      })
      .eq("id", params.findingId);
  }
}
