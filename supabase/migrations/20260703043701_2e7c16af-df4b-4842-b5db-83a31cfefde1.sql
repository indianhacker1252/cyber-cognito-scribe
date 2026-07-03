
-- 1) purge_history: add WHERE clause to bulk update
CREATE OR REPLACE FUNCTION public.purge_history(_target_id uuid DEFAULT NULL::uuid, _scope text DEFAULT 'all'::text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
DECLARE
  res jsonb := '{}'::jsonb;
  n int := 0;
  tbl text;
  has_target boolean;
  tables text[] := ARRAY[
    'attack_graph_edges','kill_chain_graph_edges','finding_evidence','request_replays','evidence_packages',
    'pending_approvals','oob_callbacks','exploit_runs','exploit_chains','kill_chains','vulnerability_findings',
    'discovered_forms','discovered_endpoints','method_discoveries','scan_assets','owasp_checklist','owasp_coverage',
    'scan_phase_state','scan_jobs','scan_logs','agent_tasks','advanced_detector_runs','chain_finder_runs',
    'attack_hypotheses','attack_graph_nodes','mythos_variants','mythos_debates','mythos_chains','mythos_patches',
    'mythos_runs','adaptation_chains','sandbox_executions','session_jars','waf_profiles','dead_targets'
  ];
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'forbidden';
  END IF;

  FOREACH tbl IN ARRAY tables LOOP
    BEGIN
      SELECT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name=tbl AND column_name='target_id'
      ) INTO has_target;

      IF _target_id IS NULL THEN
        EXECUTE format('DELETE FROM public.%I WHERE true', tbl);
      ELSIF has_target THEN
        EXECUTE format('DELETE FROM public.%I WHERE target_id = $1', tbl) USING _target_id;
      ELSE
        n := 0;
        res := res || jsonb_build_object(tbl, n);
        CONTINUE;
      END IF;

      GET DIAGNOSTICS n = ROW_COUNT;
      res := res || jsonb_build_object(tbl, n);
    EXCEPTION WHEN undefined_table THEN
      res := res || jsonb_build_object(tbl, 'missing');
    WHEN others THEN
      res := res || jsonb_build_object(tbl, 'error:' || SQLERRM);
    END;
  END LOOP;

  IF _target_id IS NULL THEN
    -- WHERE clause required by Supabase safeguards; id IS NOT NULL matches all rows.
    UPDATE public.target_workspaces SET status='queued', updated_at=now() WHERE id IS NOT NULL;
  ELSE
    UPDATE public.target_workspaces SET status='queued', updated_at=now() WHERE id=_target_id;
  END IF;

  INSERT INTO public.scan_logs(target_id, log_type, message, metadata)
  VALUES (_target_id, 'action', '🧹 Purge history completed', jsonb_build_object('scope',_scope,'deleted',res,'actor_id',auth.uid()));

  RETURN jsonb_build_object('ok', true, 'deleted', res, 'scope', _scope, 'target_id', _target_id);
END;
$function$;

-- 2) Lock down finding_evidence reads to admins only (fixes security finding).
DROP POLICY IF EXISTS "evidence_authenticated_read" ON public.finding_evidence;
CREATE POLICY "evidence_admin_read"
  ON public.finding_evidence
  FOR SELECT
  TO authenticated
  USING (public.has_role(auth.uid(), 'admin'::app_role));
