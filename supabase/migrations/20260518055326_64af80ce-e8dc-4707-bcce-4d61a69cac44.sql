-- Fix: target_workspaces had RLS enabled with zero policies → all inserts/selects blocked.
-- Match the pattern used by every related table (admin-managed, authenticated readable).

CREATE POLICY "target_workspaces_auth_read"
  ON public.target_workspaces FOR SELECT
  TO authenticated
  USING (true);

CREATE POLICY "target_workspaces_admin_insert"
  ON public.target_workspaces FOR INSERT
  TO authenticated
  WITH CHECK (public.has_role(auth.uid(), 'admin'::app_role));

CREATE POLICY "target_workspaces_admin_update"
  ON public.target_workspaces FOR UPDATE
  TO authenticated
  USING (public.has_role(auth.uid(), 'admin'::app_role))
  WITH CHECK (public.has_role(auth.uid(), 'admin'::app_role));

CREATE POLICY "target_workspaces_admin_delete"
  ON public.target_workspaces FOR DELETE
  TO authenticated
  USING (public.has_role(auth.uid(), 'admin'::app_role));
