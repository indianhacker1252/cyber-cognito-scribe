
ALTER TABLE public.mythos_runs
  ADD COLUMN IF NOT EXISTS seen_cve_ids text[] NOT NULL DEFAULT '{}'::text[],
  ADD COLUMN IF NOT EXISTS ai_mode text NOT NULL DEFAULT 'auto',
  ADD COLUMN IF NOT EXISTS degraded_reason text;

CREATE INDEX IF NOT EXISTS mythos_runs_seen_cve_gin ON public.mythos_runs USING gin (seen_cve_ids);

ALTER TABLE public.intel_feeds
  ADD COLUMN IF NOT EXISTS extracted_payloads text[],
  ADD COLUMN IF NOT EXISTS affected_tech_stack text[];

ALTER TABLE public.oob_callbacks
  ADD COLUMN IF NOT EXISTS escalated_at timestamptz,
  ADD COLUMN IF NOT EXISTS finding_id uuid;

CREATE INDEX IF NOT EXISTS oob_callbacks_token_idx ON public.oob_callbacks(token);
CREATE INDEX IF NOT EXISTS oob_callbacks_pending_idx ON public.oob_callbacks(target_id) WHERE escalated_at IS NULL;

-- experience_vault: lightweight self-learning store written by the kill-path
CREATE TABLE IF NOT EXISTS public.adaptive_lessons (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id uuid REFERENCES public.target_workspaces(id) ON DELETE CASCADE,
  vuln_class text NOT NULL,
  strategy text NOT NULL,
  payload_hash text NOT NULL,
  succeeded boolean NOT NULL,
  notes text,
  created_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.adaptive_lessons TO authenticated;
GRANT ALL ON public.adaptive_lessons TO service_role;
ALTER TABLE public.adaptive_lessons ENABLE ROW LEVEL SECURITY;
CREATE POLICY "lesson_admin_select" ON public.adaptive_lessons FOR SELECT TO authenticated
  USING (public.has_role(auth.uid(), 'admin'));
CREATE POLICY "lesson_service_all" ON public.adaptive_lessons FOR ALL TO service_role
  USING (true) WITH CHECK (true);

CREATE INDEX IF NOT EXISTS adaptive_lessons_class_strategy_idx
  ON public.adaptive_lessons(vuln_class, strategy, succeeded);
