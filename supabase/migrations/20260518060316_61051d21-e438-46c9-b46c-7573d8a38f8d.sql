
-- OWASP coverage tracking + template-runner results
CREATE TABLE IF NOT EXISTS public.owasp_coverage (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id uuid NOT NULL,
  scan_run_id uuid,
  owasp_category text NOT NULL,
  checks_run integer NOT NULL DEFAULT 0,
  payloads_sent integer NOT NULL DEFAULT 0,
  findings_count integer NOT NULL DEFAULT 0,
  waf_blocked integer NOT NULL DEFAULT 0,
  last_run_at timestamptz NOT NULL DEFAULT now(),
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_owasp_coverage_target ON public.owasp_coverage(target_id);
CREATE INDEX IF NOT EXISTS idx_owasp_coverage_cat ON public.owasp_coverage(owasp_category);

ALTER TABLE public.owasp_coverage ENABLE ROW LEVEL SECURITY;

CREATE POLICY owasp_coverage_auth_read ON public.owasp_coverage
  FOR SELECT TO authenticated USING (true);
CREATE POLICY owasp_coverage_admin_write ON public.owasp_coverage
  FOR ALL TO authenticated
  USING (public.has_role(auth.uid(), 'admin'))
  WITH CHECK (public.has_role(auth.uid(), 'admin'));
