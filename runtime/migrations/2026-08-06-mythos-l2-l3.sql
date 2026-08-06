-- Mythos L2 (experience replay) + L3 (metrics). Idempotent; re-runnable by `npm run doctor`.
CREATE TABLE IF NOT EXISTS public.agent_experiences (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id UUID NOT NULL,
  session_id UUID,
  vuln_class TEXT NOT NULL,
  technique TEXT,
  endpoint_pattern TEXT,
  tech_tags TEXT[] DEFAULT '{}',
  outcome TEXT NOT NULL CHECK (outcome IN ('confirmed','rejected','partial','dead_end')),
  confidence NUMERIC DEFAULT 0.5,
  proof_snippet TEXT,
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS agent_experiences_target_idx ON public.agent_experiences(target_id, vuln_class, outcome);
CREATE INDEX IF NOT EXISTS agent_experiences_tech_idx ON public.agent_experiences USING GIN (tech_tags);
GRANT SELECT ON public.agent_experiences TO authenticated;
GRANT ALL ON public.agent_experiences TO service_role;
ALTER TABLE public.agent_experiences ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "read_experiences" ON public.agent_experiences;
CREATE POLICY "read_experiences" ON public.agent_experiences FOR SELECT TO authenticated USING (true);
DROP POLICY IF EXISTS "service_role_all_exp" ON public.agent_experiences;
CREATE POLICY "service_role_all_exp" ON public.agent_experiences FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE TABLE IF NOT EXISTS public.agent_metrics (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id UUID NOT NULL,
  target_id UUID NOT NULL,
  metric TEXT NOT NULL,
  value NUMERIC NOT NULL DEFAULT 0,
  tags JSONB DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS agent_metrics_session_idx ON public.agent_metrics(session_id, metric);
CREATE INDEX IF NOT EXISTS agent_metrics_target_idx ON public.agent_metrics(target_id, metric, created_at DESC);
GRANT SELECT ON public.agent_metrics TO authenticated;
GRANT ALL ON public.agent_metrics TO service_role;
ALTER TABLE public.agent_metrics ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "read_metrics" ON public.agent_metrics;
CREATE POLICY "read_metrics" ON public.agent_metrics FOR SELECT TO authenticated USING (true);
DROP POLICY IF EXISTS "service_role_all_metrics" ON public.agent_metrics;
CREATE POLICY "service_role_all_metrics" ON public.agent_metrics FOR ALL TO service_role USING (true) WITH CHECK (true);
