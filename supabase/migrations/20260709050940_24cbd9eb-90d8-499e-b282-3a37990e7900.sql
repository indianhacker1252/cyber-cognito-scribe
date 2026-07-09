
-- 1) SECURITY: restrict intel + waf profile reads to admins only
DROP POLICY IF EXISTS "nvd_intel auth read" ON public.nvd_intel;
CREATE POLICY "Admins read nvd_intel"
  ON public.nvd_intel FOR SELECT
  TO authenticated
  USING (public.has_role(auth.uid(), 'admin'::app_role));

DROP POLICY IF EXISTS "Authenticated read waf profiles" ON public.waf_profiles;
CREATE POLICY "Admins read waf_profiles"
  ON public.waf_profiles FOR SELECT
  TO authenticated
  USING (public.has_role(auth.uid(), 'admin'::app_role));

-- 2) LOOP KILL: idempotency key on scan_jobs
ALTER TABLE public.scan_jobs
  ADD COLUMN IF NOT EXISTS idempotency_key TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS scan_jobs_active_idempotency_uidx
  ON public.scan_jobs (idempotency_key)
  WHERE idempotency_key IS NOT NULL
    AND status IN ('queued', 'running');

-- 3) PHASE ORDERING: sequenced phases so subdomain-enum can't run mid-fuzz
ALTER TABLE public.scan_phase_state
  ADD COLUMN IF NOT EXISTS phase_order INT,
  ADD COLUMN IF NOT EXISTS expected_modules TEXT[] DEFAULT ARRAY[]::TEXT[];

-- Seed phase_order for known phase names (idempotent)
UPDATE public.scan_phase_state SET phase_order = CASE phase
  WHEN 'recon' THEN 1
  WHEN 'discovery' THEN 2
  WHEN 'fingerprint' THEN 3
  WHEN 'fuzz' THEN 4
  WHEN 'exploit' THEN 5
  WHEN 'chain' THEN 6
  WHEN 'report' THEN 7
  ELSE phase_order
END
WHERE phase_order IS NULL;

-- 4) SIBLING FINDINGS: parent link for auto-replay results
ALTER TABLE public.vulnerability_findings
  ADD COLUMN IF NOT EXISTS parent_finding_id UUID
    REFERENCES public.vulnerability_findings(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS vf_parent_finding_idx
  ON public.vulnerability_findings(parent_finding_id)
  WHERE parent_finding_id IS NOT NULL;
