/**
 * AuditReportService - Professional Compliance Reporter
 * Generates high-quality Security Audit Reports in Markdown,
 * including technical summary, CVSS scoring, validation methodology,
 * PoC scripts, and impact analysis.
 */

import { supabase } from "@/integrations/supabase/client";

export interface ReportContext {
  title: string;
  severity: string;
  description: string;
  cvssScore: number | null;
  targetDomain: string;
  filterClassification: string;
  adaptationSteps: Array<{
    iteration: number;
    adaptationName: string;
    description: string;
    success: boolean;
    reasoning: string;
  }>;
  pocScript: string;
  verificationStatus: string;
}

export async function generateAuditReport(
  context: ReportContext,
  chainId: string
): Promise<string> {
  const { data, error } = await supabase.functions.invoke("adaptive-validate", {
    body: {
      action: "report",
      chainId,
      context: {
        title: context.title,
        severity: context.severity,
        description: context.description,
        cvssScore: context.cvssScore,
        targetDomain: context.targetDomain,
        filterClassification: context.filterClassification,
        adaptationSteps: context.adaptationSteps,
        pocScript: context.pocScript?.slice(0, 3000),
        verificationStatus: context.verificationStatus,
      },
    },
  });

  if (error) throw error;
  if (data?.error) throw new Error(data.error);

  return data.report;
}
