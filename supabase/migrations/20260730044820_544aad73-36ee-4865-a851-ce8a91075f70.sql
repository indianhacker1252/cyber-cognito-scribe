
-- Agent runtime state tables (Phase 2 of Option B rebuild)

CREATE TABLE public.agent_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id uuid NOT NULL REFERENCES public.target_workspaces(id) ON DELETE CASCADE,
  user_id uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  status text NOT NULL DEFAULT 'queued', -- queued | running | paused | completed | failed | aborted
  goal text,
  model text NOT NULL DEFAULT 'google/gemini-3.6-flash',
  provider text NOT NULL DEFAULT 'lovable', -- lovable | openai | gemini
  budget_credits integer NOT NULL DEFAULT 200,
  budget_seconds integer NOT NULL DEFAULT 3600,
  credits_used integer NOT NULL DEFAULT 0,
  steps_taken integer NOT NULL DEFAULT 0,
  runtime_host text,       -- which worker picked it up
  runtime_pid text,
  started_at timestamptz,
  completed_at timestamptz,
  last_heartbeat timestamptz,
  error_message text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_agent_sessions_target ON public.agent_sessions(target_id, created_at DESC);
CREATE INDEX idx_agent_sessions_status ON public.agent_sessions(status) WHERE status IN ('queued','running');

GRANT SELECT, INSERT, UPDATE, DELETE ON public.agent_sessions TO authenticated;
GRANT ALL ON public.agent_sessions TO service_role;
ALTER TABLE public.agent_sessions ENABLE ROW LEVEL SECURITY;
CREATE POLICY "sessions_read_authed" ON public.agent_sessions FOR SELECT TO authenticated USING (true);
CREATE POLICY "sessions_write_owner_or_admin" ON public.agent_sessions FOR ALL TO authenticated
  USING (user_id = auth.uid() OR public.has_role(auth.uid(),'admin'))
  WITH CHECK (user_id = auth.uid() OR public.has_role(auth.uid(),'admin'));

CREATE TRIGGER trg_agent_sessions_updated BEFORE UPDATE ON public.agent_sessions
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

-- Append-only event log (Plan/Act/Observe stream for BrainPanel)
CREATE TABLE public.agent_events (
  id bigserial PRIMARY KEY,
  session_id uuid NOT NULL REFERENCES public.agent_sessions(id) ON DELETE CASCADE,
  target_id uuid NOT NULL,
  ts timestamptz NOT NULL DEFAULT now(),
  kind text NOT NULL, -- plan | thought | tool_call | tool_result | finding | decision | error | heartbeat
  step integer,
  payload jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX idx_agent_events_session ON public.agent_events(session_id, id DESC);
CREATE INDEX idx_agent_events_target ON public.agent_events(target_id, ts DESC);

GRANT SELECT, INSERT ON public.agent_events TO authenticated;
GRANT ALL ON public.agent_events TO service_role;
GRANT USAGE, SELECT ON SEQUENCE public.agent_events_id_seq TO authenticated;
GRANT ALL ON SEQUENCE public.agent_events_id_seq TO service_role;
ALTER TABLE public.agent_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY "events_read_authed" ON public.agent_events FOR SELECT TO authenticated USING (true);
CREATE POLICY "events_insert_service" ON public.agent_events FOR INSERT TO authenticated WITH CHECK (true);

-- Tool invocation log (for cost + replay)
CREATE TABLE public.tool_invocations (
  id bigserial PRIMARY KEY,
  session_id uuid NOT NULL REFERENCES public.agent_sessions(id) ON DELETE CASCADE,
  target_id uuid NOT NULL,
  step integer,
  tool text NOT NULL,
  args jsonb NOT NULL DEFAULT '{}'::jsonb,
  result jsonb,
  ok boolean NOT NULL DEFAULT true,
  latency_ms integer,
  cost_credits integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_tool_inv_session ON public.tool_invocations(session_id, created_at DESC);

GRANT SELECT, INSERT ON public.tool_invocations TO authenticated;
GRANT ALL ON public.tool_invocations TO service_role;
GRANT USAGE, SELECT ON SEQUENCE public.tool_invocations_id_seq TO authenticated;
GRANT ALL ON SEQUENCE public.tool_invocations_id_seq TO service_role;
ALTER TABLE public.tool_invocations ENABLE ROW LEVEL SECURITY;
CREATE POLICY "toolinv_read_authed" ON public.tool_invocations FOR SELECT TO authenticated USING (true);
CREATE POLICY "toolinv_insert_authed" ON public.tool_invocations FOR INSERT TO authenticated WITH CHECK (true);

-- Realtime for live UI streaming
ALTER PUBLICATION supabase_realtime ADD TABLE public.agent_events;
ALTER PUBLICATION supabase_realtime ADD TABLE public.agent_sessions;

-- Feature flag on target_workspaces (parallel-run for 2 weeks)
ALTER TABLE public.target_workspaces
  ADD COLUMN IF NOT EXISTS use_agent_runtime boolean NOT NULL DEFAULT false;

-- Atomic session claim so multiple VPS workers don't grab the same session
CREATE OR REPLACE FUNCTION public.claim_agent_session(_host text)
RETURNS public.agent_sessions
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  s public.agent_sessions;
BEGIN
  UPDATE public.agent_sessions
     SET status = 'running',
         runtime_host = _host,
         started_at = COALESCE(started_at, now()),
         last_heartbeat = now(),
         updated_at = now()
   WHERE id = (
     SELECT id FROM public.agent_sessions
      WHERE status = 'queued'
      ORDER BY created_at ASC
      FOR UPDATE SKIP LOCKED
      LIMIT 1
   )
   RETURNING * INTO s;
  RETURN s;
END $$;

GRANT EXECUTE ON FUNCTION public.claim_agent_session(text) TO service_role;
