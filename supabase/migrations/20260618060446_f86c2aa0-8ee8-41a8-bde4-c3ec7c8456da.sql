
-- Restrict admin-only operational data tables (SELECT to admins only)
DO $$
DECLARE
  t text;
  pol record;
  tables text[] := ARRAY[
    'exploitdb_index','rag_exploits','mythos_chains','mythos_variants','mythos_debates',
    'mythos_runs','canary_baselines','suppression_vectors','attack_graph_nodes','attack_graph_edges',
    'kill_chains','code_findings','scan_logs','discovered_endpoints','method_discoveries',
    'strategy_weights','owasp_coverage','patch_validations','intel_notifications','intel_sync_runs'
  ];
BEGIN
  FOREACH t IN ARRAY tables LOOP
    -- Drop any permissive SELECT policies (USING true) that grant authenticated/public broad read
    FOR pol IN
      SELECT policyname FROM pg_policies
       WHERE schemaname='public' AND tablename=t AND cmd='SELECT'
    LOOP
      EXECUTE format('DROP POLICY IF EXISTS %I ON public.%I', pol.policyname, t);
    END LOOP;
    EXECUTE format('CREATE POLICY "admin_read_%s" ON public.%I FOR SELECT TO authenticated USING (public.has_role(auth.uid(), ''admin''::app_role))', t, t);
  END LOOP;
END $$;

-- Storage: add UPDATE policy for app-packages owners
CREATE POLICY "app_packages_owner_update"
ON storage.objects FOR UPDATE TO authenticated
USING (bucket_id = 'app-packages' AND owner = auth.uid())
WITH CHECK (bucket_id = 'app-packages' AND owner = auth.uid());
