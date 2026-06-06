
-- ============================================================
-- Scope gate, pipeline-fix linkage, advanced-detector storage,
-- and RLS hardening for evidence_packages / exploit_runs / sandbox_executions
-- ============================================================

-- 1) SCOPE GATE on target_workspaces ----------------------------
ALTER TABLE public.target_workspaces
  ADD COLUMN IF NOT EXISTS authorization_mode text
    NOT NULL DEFAULT 'unauthorized'
    CHECK (authorization_mode IN ('unauthorized','attestation','bug_bounty','both')),
  ADD COLUMN IF NOT EXISTS attestation_accepted boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS attestation_accepted_at timestamptz,
  ADD COLUMN IF NOT EXISTS attestation_accepted_by uuid,
  ADD COLUMN IF NOT EXISTS bug_bounty_program text,
  ADD COLUMN IF NOT EXISTS bug_bounty_scope_url text,
  ADD COLUMN IF NOT EXISTS authorization_notes text;

-- Helper: is this target authorized for exploit-tier modules?
CREATE OR REPLACE FUNCTION public.target_is_exploit_authorized(_target_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.target_workspaces t
     WHERE t.id = _target_id
       AND (
            (t.authorization_mode IN ('attestation','both') AND t.attestation_accepted = true)
         OR (t.authorization_mode IN ('bug_bounty','both')
             AND COALESCE(t.bug_bounty_program,'') <> ''
             AND COALESCE(t.bug_bounty_scope_url,'') <> '')
       )
  );
$$;

-- 2) PIPELINE LINKAGE: give pending_approvals a real finding_id link
ALTER TABLE public.pending_approvals
  ADD COLUMN IF NOT EXISTS finding_id uuid REFERENCES public.vulnerability_findings(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_pending_approvals_finding ON public.pending_approvals(finding_id);

-- 3) ADVANCED DETECTOR storage ---------------------------------
CREATE TABLE IF NOT EXISTS public.advanced_detector_runs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id uuid NOT NULL REFERENCES public.target_workspaces(id) ON DELETE CASCADE,
  endpoint_id uuid REFERENCES public.discovered_endpoints(id) ON DELETE SET NULL,
  detector text NOT NULL,
  status text NOT NULL DEFAULT 'running',
  primitive text,
  chain_steps jsonb NOT NULL DEFAULT '[]'::jsonb,
  evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
  proven boolean NOT NULL DEFAULT false,
  finding_id uuid REFERENCES public.vulnerability_findings(id) ON DELETE SET NULL,
  duration_ms integer,
  error text,
  created_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT ON public.advanced_detector_runs TO authenticated;
GRANT ALL    ON public.advanced_detector_runs TO service_role;
ALTER TABLE public.advanced_detector_runs ENABLE ROW LEVEL SECURITY;
CREATE POLICY "adr_admin_all" ON public.advanced_detector_runs
  FOR ALL TO authenticated
  USING (public.has_role(auth.uid(),'admin'))
  WITH CHECK (public.has_role(auth.uid(),'admin'));

CREATE INDEX IF NOT EXISTS idx_adr_target  ON public.advanced_detector_runs(target_id);
CREATE INDEX IF NOT EXISTS idx_adr_det     ON public.advanced_detector_runs(detector);

-- 4) RLS HARDENING ---------------------------------------------
-- evidence_packages: admin-only SELECT (drop non-sensitive leak)
DROP POLICY IF EXISTS "evidence sensitive admin only"   ON public.evidence_packages;
DROP POLICY IF EXISTS "evidence_admin_select"           ON public.evidence_packages;
CREATE POLICY "evidence_admin_select" ON public.evidence_packages
  FOR SELECT TO authenticated
  USING (public.has_role(auth.uid(),'admin'));

-- exploit_runs: admin-only SELECT (drop non-sensitive leak)
DROP POLICY IF EXISTS "exploit sensitive admin only" ON public.exploit_runs;
DROP POLICY IF EXISTS "exploit_admin_select"         ON public.exploit_runs;
CREATE POLICY "exploit_admin_select" ON public.exploit_runs
  FOR SELECT TO authenticated
  USING (public.has_role(auth.uid(),'admin'));

-- sandbox_executions: tighten write side to owner-only
DROP POLICY IF EXISTS "sbx all auth"           ON public.sandbox_executions;
DROP POLICY IF EXISTS "sbx_owner_insert"       ON public.sandbox_executions;
DROP POLICY IF EXISTS "sbx_owner_update"       ON public.sandbox_executions;
DROP POLICY IF EXISTS "sbx_owner_delete"       ON public.sandbox_executions;
DROP POLICY IF EXISTS "sbx_owner_select"       ON public.sandbox_executions;

CREATE POLICY "sbx_owner_select" ON public.sandbox_executions
  FOR SELECT TO authenticated
  USING (auth.uid() = user_id OR public.has_role(auth.uid(),'admin'));
CREATE POLICY "sbx_owner_insert" ON public.sandbox_executions
  FOR INSERT TO authenticated
  WITH CHECK (auth.uid() = user_id);
CREATE POLICY "sbx_owner_update" ON public.sandbox_executions
  FOR UPDATE TO authenticated
  USING (auth.uid() = user_id OR public.has_role(auth.uid(),'admin'))
  WITH CHECK (auth.uid() = user_id OR public.has_role(auth.uid(),'admin'));
CREATE POLICY "sbx_owner_delete" ON public.sandbox_executions
  FOR DELETE TO authenticated
  USING (auth.uid() = user_id OR public.has_role(auth.uid(),'admin'));
