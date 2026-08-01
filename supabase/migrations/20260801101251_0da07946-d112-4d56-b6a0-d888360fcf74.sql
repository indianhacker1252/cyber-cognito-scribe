
-- Lock down agent_sessions: admins see all, users see their own
DROP POLICY IF EXISTS sessions_read_authed ON public.agent_sessions;
CREATE POLICY sessions_read_own_or_admin ON public.agent_sessions
  FOR SELECT TO authenticated
  USING (public.has_role(auth.uid(), 'admin'::app_role) OR user_id = auth.uid());

-- Lock down agent_events: admins only for reads and inserts (service role bypasses RLS)
DROP POLICY IF EXISTS events_read_authed ON public.agent_events;
DROP POLICY IF EXISTS events_insert_service ON public.agent_events;
CREATE POLICY events_read_admin ON public.agent_events
  FOR SELECT TO authenticated
  USING (public.has_role(auth.uid(), 'admin'::app_role));
CREATE POLICY events_insert_admin ON public.agent_events
  FOR INSERT TO authenticated
  WITH CHECK (public.has_role(auth.uid(), 'admin'::app_role));

-- Lock down planner_traces: admin-only
DROP POLICY IF EXISTS planner_traces_auth_all ON public.planner_traces;
CREATE POLICY planner_traces_admin_all ON public.planner_traces
  FOR ALL TO authenticated
  USING (public.has_role(auth.uid(), 'admin'::app_role))
  WITH CHECK (public.has_role(auth.uid(), 'admin'::app_role));
