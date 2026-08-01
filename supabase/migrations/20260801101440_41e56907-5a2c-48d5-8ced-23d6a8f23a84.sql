
DROP POLICY IF EXISTS world_model_auth_all ON public.target_world_model;
CREATE POLICY world_model_admin_all ON public.target_world_model
  FOR ALL TO authenticated
  USING (public.has_role(auth.uid(),'admin'::app_role))
  WITH CHECK (public.has_role(auth.uid(),'admin'::app_role));

DROP POLICY IF EXISTS toolinv_read_authed ON public.tool_invocations;
DROP POLICY IF EXISTS toolinv_insert_authed ON public.tool_invocations;
CREATE POLICY toolinv_read_admin ON public.tool_invocations
  FOR SELECT TO authenticated
  USING (public.has_role(auth.uid(),'admin'::app_role));
CREATE POLICY toolinv_insert_admin ON public.tool_invocations
  FOR INSERT TO authenticated
  WITH CHECK (public.has_role(auth.uid(),'admin'::app_role));
