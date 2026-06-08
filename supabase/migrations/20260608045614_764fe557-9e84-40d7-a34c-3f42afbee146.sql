GRANT SELECT, INSERT, UPDATE, DELETE ON public.vulnerability_findings TO authenticated;
GRANT ALL ON public.vulnerability_findings TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.pending_approvals TO authenticated;
GRANT ALL ON public.pending_approvals TO service_role;
GRANT SELECT ON public.target_workspaces TO authenticated;
GRANT ALL ON public.target_workspaces TO service_role;