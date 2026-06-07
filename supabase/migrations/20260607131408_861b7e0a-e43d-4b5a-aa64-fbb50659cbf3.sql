CREATE POLICY "pending_approvals_auth_read"
ON public.pending_approvals
FOR SELECT
TO authenticated
USING (true);