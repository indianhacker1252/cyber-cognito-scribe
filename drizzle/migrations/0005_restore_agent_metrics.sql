CREATE TABLE public.agent_metrics (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 session_id UUID NOT NULL,
 target_id UUID NOT NULL,
 metric TEXT NOT NULL,
 value NUMERIC NOT NULL DEFAULT 0,
 tags JSONB DEFAULT '{}'::jsonb,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
GRANT SELECT ON public.agent_metrics TO authenticated;
GRANT ALL ON public.agent_metrics TO service_role;
ALTER TABLE public.agent_metrics ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Admins read metrics" ON public.agent_metrics FOR SELECT TO authenticated USING (public.has_role(auth.uid(), 'admin'));
CREATE INDEX agent_metrics_session_idx ON public.agent_metrics(session_id, metric);
CREATE INDEX agent_metrics_target_idx ON public.agent_metrics(target_id, metric, created_at DESC);