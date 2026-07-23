
-- Pass E: context-aware adaptive lessons for UCB1 scoring
ALTER TABLE public.adaptive_lessons
  ADD COLUMN IF NOT EXISTS context_hash text,
  ADD COLUMN IF NOT EXISTS attempt_count integer NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS succeeded_count integer NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_adaptive_lessons_context
  ON public.adaptive_lessons (vuln_class, context_hash);

-- Pass B: planner traces — every agent-planner turn lands here so the Brain
-- panel can render Plan / Act / Observe lanes with the model's rationale.
CREATE TABLE IF NOT EXISTS public.planner_traces (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id uuid NOT NULL REFERENCES public.target_workspaces(id) ON DELETE CASCADE,
  trace_id text NOT NULL,
  turn integer NOT NULL DEFAULT 0,
  world_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
  open_findings integer NOT NULL DEFAULT 0,
  reasoning text,
  actions jsonb NOT NULL DEFAULT '[]'::jsonb,
  provider text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_planner_traces_target
  ON public.planner_traces (target_id, created_at DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON public.planner_traces TO authenticated;
GRANT ALL ON public.planner_traces TO service_role;

ALTER TABLE public.planner_traces ENABLE ROW LEVEL SECURITY;

CREATE POLICY "planner_traces_auth_all"
  ON public.planner_traces FOR ALL
  TO authenticated USING (true) WITH CHECK (true);
