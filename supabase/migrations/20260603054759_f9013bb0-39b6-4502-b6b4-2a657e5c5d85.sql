
CREATE TABLE IF NOT EXISTS public.session_jars (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id uuid NOT NULL,
  profile_name text NOT NULL DEFAULT 'default',
  cookies jsonb NOT NULL DEFAULT '{}'::jsonb,
  headers jsonb NOT NULL DEFAULT '{}'::jsonb,
  csrf_token text,
  jwt text,
  last_url text,
  hit_count integer NOT NULL DEFAULT 0,
  updated_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (target_id, profile_name)
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.session_jars TO authenticated;
GRANT ALL ON public.session_jars TO service_role;
ALTER TABLE public.session_jars ENABLE ROW LEVEL SECURITY;
CREATE POLICY session_jars_admin_all ON public.session_jars
  FOR ALL TO authenticated
  USING (public.has_role(auth.uid(), 'admin'))
  WITH CHECK (public.has_role(auth.uid(), 'admin'));

CREATE TABLE IF NOT EXISTS public.chain_finder_runs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id uuid NOT NULL,
  seed_finding_id uuid,
  primitive text,
  proposed_next_step jsonb NOT NULL DEFAULT '{}'::jsonb,
  reasoning text,
  queued_exploit_run_id uuid,
  status text NOT NULL DEFAULT 'proposed',
  result jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.chain_finder_runs TO authenticated;
GRANT ALL ON public.chain_finder_runs TO service_role;
ALTER TABLE public.chain_finder_runs ENABLE ROW LEVEL SECURITY;
CREATE POLICY chain_finder_runs_admin_all ON public.chain_finder_runs
  FOR ALL TO authenticated
  USING (public.has_role(auth.uid(), 'admin'))
  WITH CHECK (public.has_role(auth.uid(), 'admin'));

CREATE INDEX IF NOT EXISTS idx_session_jars_target ON public.session_jars(target_id);
CREATE INDEX IF NOT EXISTS idx_chain_finder_target ON public.chain_finder_runs(target_id);
