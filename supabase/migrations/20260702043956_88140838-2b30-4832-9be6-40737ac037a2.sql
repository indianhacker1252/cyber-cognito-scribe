-- OWASP checklist deletion audit trail
CREATE TABLE IF NOT EXISTS public.owasp_checklist_audit (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id uuid NOT NULL,
  target_label text NOT NULL,
  action text NOT NULL,
  confirmation text,
  deleted_count integer NOT NULL DEFAULT 0,
  actor_id uuid,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT ON public.owasp_checklist_audit TO authenticated;
GRANT ALL ON public.owasp_checklist_audit TO service_role;
ALTER TABLE public.owasp_checklist_audit ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "owasp checklist audit admin read" ON public.owasp_checklist_audit;
CREATE POLICY "owasp checklist audit admin read" ON public.owasp_checklist_audit
  FOR SELECT TO authenticated USING (public.has_role(auth.uid(),'admin'));
CREATE INDEX IF NOT EXISTS owasp_checklist_audit_target_idx ON public.owasp_checklist_audit(target_id, created_at DESC);

-- Per-target AI selection for scans.
ALTER TABLE public.target_workspaces
  ADD COLUMN IF NOT EXISTS scan_ai_provider text NOT NULL DEFAULT 'auto';

-- Evidence strict de-duplication: remove old duplicate evidence rows, then prevent future duplicates.
WITH ranked AS (
  SELECT id,
         row_number() OVER (
           PARTITION BY finding_id,
             md5(coalesce(request_raw,'')),
             md5(coalesce(response_raw,'')),
             coalesce(affected_url,''),
             coalesce(method,''),
             coalesce(param,''),
             md5(coalesce(payload,''))
           ORDER BY created_at DESC, id DESC
         ) AS rn
  FROM public.finding_evidence
)
DELETE FROM public.finding_evidence fe
USING ranked r
WHERE fe.id = r.id AND r.rn > 1;

CREATE UNIQUE INDEX IF NOT EXISTS finding_evidence_strict_dedup_idx
  ON public.finding_evidence (
    finding_id,
    md5(coalesce(request_raw,'')),
    md5(coalesce(response_raw,'')),
    coalesce(affected_url,''),
    coalesce(method,''),
    coalesce(param,''),
    md5(coalesce(payload,''))
  );

UPDATE public.vulnerability_findings vf
SET evidence_count = GREATEST(1, COALESCE(e.cnt, 0)),
    last_seen_at = COALESCE(e.last_seen, vf.last_seen_at, vf.created_at)
FROM (
  SELECT finding_id, count(*)::int AS cnt, max(created_at) AS last_seen
  FROM public.finding_evidence
  GROUP BY finding_id
) e
WHERE vf.id = e.finding_id;

-- Safer checklist delete: requires exact UI confirmation and writes an audit row.
DROP FUNCTION IF EXISTS public.delete_owasp_checklist(uuid);
CREATE OR REPLACE FUNCTION public.delete_owasp_checklist(_target_id uuid, _confirmation text DEFAULT NULL)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  n int := 0;
  label text;
  expected text;
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'forbidden';
  END IF;

  SELECT COALESCE(NULLIF(name,''), NULLIF(domain,''), id::text)
    INTO label
    FROM public.target_workspaces
   WHERE id = _target_id;
  label := COALESCE(label, _target_id::text);
  expected := 'DELETE ' || label;

  IF COALESCE(_confirmation, '') <> expected THEN
    RAISE EXCEPTION 'confirmation_mismatch';
  END IF;

  DELETE FROM public.owasp_checklist WHERE target_id = _target_id;
  GET DIAGNOSTICS n = ROW_COUNT;

  INSERT INTO public.owasp_checklist_audit(target_id, target_label, action, confirmation, deleted_count, actor_id, metadata)
  VALUES (_target_id, label, 'delete_checklist', _confirmation, n, auth.uid(), jsonb_build_object('expected', expected));

  INSERT INTO public.scan_logs(target_id, log_type, message, metadata)
  VALUES (_target_id, 'action', '🧾 OWASP checklist deleted with confirmation', jsonb_build_object('kind','owasp_checklist_delete','deleted_count',n,'actor_id',auth.uid()));

  RETURN n;
END;
$$;
GRANT EXECUTE ON FUNCTION public.delete_owasp_checklist(uuid,text) TO authenticated, service_role;

-- Queue only missing OWASP modules for a target; default mode waits until current scan jobs are no longer active.
CREATE OR REPLACE FUNCTION public.enqueue_missing_owasp_modules(_target_id uuid, _force boolean DEFAULT false)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  active_count int := 0;
  queued_count int := 0;
  missing_count int := 0;
  module_names text[] := ARRAY[]::text[];
BEGIN
  IF auth.uid() IS NULL AND current_setting('role', true) <> 'service_role' THEN
    RAISE EXCEPTION 'forbidden';
  END IF;

  SELECT count(*) INTO active_count
  FROM public.scan_jobs
  WHERE target_id = _target_id
    AND status IN ('queued','running')
    AND job_type <> 'report_rewrite';

  IF active_count > 0 AND NOT _force THEN
    RETURN jsonb_build_object('ok', true, 'queued', 0, 'active_jobs', active_count, 'reason', 'scan_still_active');
  END IF;

  WITH missing AS (
    SELECT DISTINCT check_module,
      CASE check_module
        WHEN 'advanced-fuzzer' THEN 'fuzz'
        WHEN 'matrix-fuzzer' THEN 'matrix_fuzz'
        WHEN 'form-attacker' THEN 'form_attack'
        WHEN 'recon-juicy' THEN 'juicy'
        WHEN 'recon-engine' THEN 'recon'
        WHEN 'recon-deep' THEN 'recon'
        WHEN 'ssrf-deep' THEN 'ssrf_deep'
        WHEN 'js-deep-expand' THEN 'js_deep'
        WHEN 'cve-to-exploit' THEN 'cve_exploit'
        WHEN 'cve-version-matcher' THEN 'cve'
        WHEN 'nvd-intel-sync' THEN 'nvd_sync'
        WHEN 'subdomain-enum' THEN 'subdomain_enum'
        WHEN 'auth-confusion-suite' THEN 'jwt_attack'
        WHEN 'auth-deep' THEN 'advanced_detect'
        WHEN 'auth-replay' THEN 'auth_replay'
        WHEN 'graphql-attack' THEN 'graphql'
        WHEN 'bac-tester' THEN 'advanced_detect'
        WHEN 'differential-oracle' THEN 'differential'
        WHEN 'vuln-scanner' THEN 'vuln_scan'
        ELSE 'advanced_detect'
      END AS job_type
    FROM public.owasp_checklist
    WHERE target_id = _target_id
      AND check_module IS NOT NULL
      AND COALESCE(status,'pending') NOT IN ('evidence','passed','complete','attempted')
  ), queued AS (
    INSERT INTO public.scan_jobs(target_id, job_type, priority, status, payload, next_run_at)
    SELECT _target_id, m.job_type, 6, 'queued',
           jsonb_build_object('checklist_rerun', true, 'module', m.check_module, 'queued_by', 'owasp_missing_rerun'),
           now()
    FROM missing m
    WHERE NOT EXISTS (
      SELECT 1 FROM public.scan_jobs sj
      WHERE sj.target_id = _target_id
        AND sj.job_type = m.job_type
        AND sj.status IN ('queued','running')
    )
    RETURNING job_type
  )
  SELECT count(*)::int INTO queued_count FROM queued;

  SELECT count(*), COALESCE(array_agg(DISTINCT check_module) FILTER (WHERE check_module IS NOT NULL), ARRAY[]::text[])
    INTO missing_count, module_names
    FROM public.owasp_checklist
   WHERE target_id = _target_id
     AND COALESCE(status,'pending') NOT IN ('evidence','passed','complete','attempted');

  UPDATE public.owasp_checklist c
     SET status = CASE WHEN c.status IN ('pending','failed') THEN 'queued' ELSE c.status END,
         last_run_at = now(),
         metadata = COALESCE(c.metadata,'{}'::jsonb) || jsonb_build_object(
           'dependency_chain', jsonb_build_object(
             'prerequisite', 'scan_finished',
             'module', c.check_module,
             'queued_at', now(),
             'reason', 'missing evidence/attempt after scan ended'
           )
         )
   WHERE c.target_id = _target_id
     AND c.check_module = ANY(module_names)
     AND COALESCE(c.status,'pending') NOT IN ('evidence','passed','complete','attempted');

  INSERT INTO public.scan_logs(target_id, log_type, message, metadata)
  VALUES (_target_id, 'action', '🔁 Queued missing OWASP modules only', jsonb_build_object('kind','owasp_missing_rerun','queued',queued_count,'missing_checks',missing_count,'modules',module_names));

  RETURN jsonb_build_object('ok', true, 'queued', queued_count, 'missing_checks', missing_count, 'modules', module_names, 'active_jobs', active_count);
END;
$$;
GRANT EXECUTE ON FUNCTION public.enqueue_missing_owasp_modules(uuid,boolean) TO authenticated, service_role;

-- Robust purge-history: clears scan/history data without deleting targets or configuration.
CREATE OR REPLACE FUNCTION public.purge_history(_target_id uuid DEFAULT NULL::uuid, _scope text DEFAULT 'all'::text)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
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
        EXECUTE format('DELETE FROM public.%I', tbl);
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
    UPDATE public.target_workspaces SET status='queued', updated_at=now();
  ELSE
    UPDATE public.target_workspaces SET status='queued', updated_at=now() WHERE id=_target_id;
  END IF;

  INSERT INTO public.scan_logs(target_id, log_type, message, metadata)
  VALUES (_target_id, 'action', '🧹 Purge history completed', jsonb_build_object('scope',_scope,'deleted',res,'actor_id',auth.uid()));

  RETURN jsonb_build_object('ok', true, 'deleted', res, 'scope', _scope, 'target_id', _target_id);
END;
$$;
REVOKE ALL ON FUNCTION public.purge_history(uuid,text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.purge_history(uuid,text) TO authenticated, service_role;