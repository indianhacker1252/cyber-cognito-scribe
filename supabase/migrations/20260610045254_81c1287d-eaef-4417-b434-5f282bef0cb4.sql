
-- Findings raw req/resp + source + WAF profile + lock down read access
ALTER TABLE public.vulnerability_findings
  ADD COLUMN IF NOT EXISTS request_raw text,
  ADD COLUMN IF NOT EXISTS response_raw text,
  ADD COLUMN IF NOT EXISTS response_diff jsonb DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS source text;

CREATE INDEX IF NOT EXISTS idx_vf_target_source_created
  ON public.vulnerability_findings(target_id, source, created_at DESC);

ALTER TABLE public.target_workspaces
  ADD COLUMN IF NOT EXISTS waf_profile jsonb NOT NULL DEFAULT '{}'::jsonb;

-- Security fix: restrict reads of sensitive tables to admins only
DROP POLICY IF EXISTS vulnerability_findings_auth_read ON public.vulnerability_findings;
CREATE POLICY vulnerability_findings_admin_read ON public.vulnerability_findings
  FOR SELECT TO authenticated
  USING (public.has_role(auth.uid(), 'admin'));

DROP POLICY IF EXISTS pending_approvals_auth_read ON public.pending_approvals;
-- pending_approvals_admin_all already covers admin SELECT
