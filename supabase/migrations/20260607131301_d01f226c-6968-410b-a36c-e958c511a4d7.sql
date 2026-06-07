CREATE POLICY "vulnerability_findings_auth_read"
ON public.vulnerability_findings
FOR SELECT
TO authenticated
USING (true);

CREATE POLICY "vulnerability_findings_admin_insert"
ON public.vulnerability_findings
FOR INSERT
TO authenticated
WITH CHECK (public.has_role(auth.uid(), 'admin'));

CREATE POLICY "vulnerability_findings_admin_update"
ON public.vulnerability_findings
FOR UPDATE
TO authenticated
USING (public.has_role(auth.uid(), 'admin'))
WITH CHECK (public.has_role(auth.uid(), 'admin'));

CREATE POLICY "vulnerability_findings_admin_delete"
ON public.vulnerability_findings
FOR DELETE
TO authenticated
USING (public.has_role(auth.uid(), 'admin'));