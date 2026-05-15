
-- ============================================================
-- Drop all "Allow all access" public policies
-- ============================================================
DO $$
DECLARE r record;
BEGIN
  FOR r IN
    SELECT schemaname, tablename, policyname
    FROM pg_policies
    WHERE schemaname = 'public'
      AND policyname ILIKE 'Allow all access%'
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I', r.policyname, r.schemaname, r.tablename);
  END LOOP;
END $$;

-- Helper: authenticated read + admin write template applied per-table below.
-- ============================================================
-- ADMIN-ONLY tables (credentials / sensitive PoC / intel)
-- ============================================================
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'auth_profiles','ai_provider_config','external_infra_config',
    'evidence_packages','adaptation_chains','exploit_chains',
    'oob_callbacks','intel_feeds','mythos_patches','code_repositories',
    'experience_vault','pending_approvals','agent_tasks','scan_jobs',
    'exploit_runs'
  ]
  LOOP
    EXECUTE format('CREATE POLICY %I ON public.%I FOR ALL TO authenticated USING (public.has_role(auth.uid(), ''admin''::app_role)) WITH CHECK (public.has_role(auth.uid(), ''admin''::app_role))',
      t || '_admin_all', t);
  END LOOP;
END $$;

-- ============================================================
-- AUTHENTICATED-READ / ADMIN-WRITE tables (operational)
-- ============================================================
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'chat_messages','chat_sessions','scan_logs','discovered_endpoints',
    'mythos_runs','mythos_debates','mythos_variants','mythos_chains',
    'patch_validations','canary_baselines','method_discoveries',
    'code_findings','intel_notifications','intel_sync_runs',
    'strategy_weights','suppression_vectors'
  ]
  LOOP
    EXECUTE format('CREATE POLICY %I ON public.%I FOR SELECT TO authenticated USING (true)', t || '_auth_read', t);
    EXECUTE format('CREATE POLICY %I ON public.%I FOR INSERT TO authenticated WITH CHECK (public.has_role(auth.uid(), ''admin''::app_role))', t || '_admin_insert', t);
    EXECUTE format('CREATE POLICY %I ON public.%I FOR UPDATE TO authenticated USING (public.has_role(auth.uid(), ''admin''::app_role)) WITH CHECK (public.has_role(auth.uid(), ''admin''::app_role))', t || '_admin_update', t);
    EXECUTE format('CREATE POLICY %I ON public.%I FOR DELETE TO authenticated USING (public.has_role(auth.uid(), ''admin''::app_role))', t || '_admin_delete', t);
  END LOOP;
END $$;

-- Drop the redundant public-applied "exploit auth all" policy (admin policy above replaces it)
DROP POLICY IF EXISTS "exploit auth all" ON public.exploit_runs;
