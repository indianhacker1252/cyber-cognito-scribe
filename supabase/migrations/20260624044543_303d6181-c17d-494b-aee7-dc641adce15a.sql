CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_jobs_unique_active_phase
ON public.scan_jobs (target_id, job_type, (payload->>'runId'), (payload->>'nextPhase'))
WHERE status IN ('queued', 'running')
  AND job_type = 'mythos_step'
  AND payload->>'runId' IS NOT NULL
  AND payload->>'nextPhase' IS NOT NULL;

CREATE TABLE IF NOT EXISTS public.nvd_intel (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  cve_id TEXT UNIQUE NOT NULL,
  title TEXT,
  description TEXT,
  cvss_score NUMERIC(4,1),
  severity TEXT CHECK (severity IN ('critical','high','medium','low','info')),
  published TIMESTAMPTZ,
  "references" JSONB DEFAULT '[]',
  affected_products JSONB DEFAULT '[]',
  synced_at TIMESTAMPTZ DEFAULT NOW(),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

GRANT SELECT ON public.nvd_intel TO authenticated;
GRANT ALL ON public.nvd_intel TO service_role;

ALTER TABLE public.nvd_intel ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "nvd_intel auth read" ON public.nvd_intel;
CREATE POLICY "nvd_intel auth read" ON public.nvd_intel
  FOR SELECT TO authenticated USING (true);

DROP POLICY IF EXISTS "nvd_intel admin write" ON public.nvd_intel;
CREATE POLICY "nvd_intel admin write" ON public.nvd_intel
  FOR ALL TO authenticated
  USING (public.has_role(auth.uid(), 'admin'))
  WITH CHECK (public.has_role(auth.uid(), 'admin'));

CREATE INDEX IF NOT EXISTS idx_nvd_intel_severity ON public.nvd_intel(severity);
CREATE INDEX IF NOT EXISTS idx_nvd_intel_cvss ON public.nvd_intel(cvss_score DESC);
CREATE INDEX IF NOT EXISTS idx_nvd_intel_synced ON public.nvd_intel(synced_at DESC);

ALTER TABLE public.target_workspaces
  ADD COLUMN IF NOT EXISTS resolved_protocol TEXT DEFAULT 'https';

CREATE INDEX IF NOT EXISTS idx_exploit_runs_target_created
  ON public.exploit_runs(target_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_logs_target_type_created
  ON public.scan_logs(target_id, log_type, created_at DESC);