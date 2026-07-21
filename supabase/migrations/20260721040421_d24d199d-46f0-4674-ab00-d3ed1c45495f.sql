
ALTER TABLE public.target_workspaces
  ADD COLUMN IF NOT EXISTS detected_tech jsonb NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS tech_fingerprint jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS tech_stack text[] NOT NULL DEFAULT ARRAY[]::text[];
CREATE INDEX IF NOT EXISTS idx_target_workspaces_detected_tech_gin
  ON public.target_workspaces USING gin (detected_tech);

-- Quiet the noisy "Queued missing OWASP modules only" cron log when nothing was queued.
CREATE OR REPLACE FUNCTION public.enqueue_missing_owasp_modules(_target_id uuid, _force boolean DEFAULT false)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
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

  -- Only log when we actually queued something new. Prevents 4x-daily noise.
  IF queued_count > 0 THEN
    INSERT INTO public.scan_logs(target_id, log_type, message, metadata)
    VALUES (_target_id, 'action', '🔁 Queued missing OWASP modules only',
      jsonb_build_object('kind','owasp_missing_rerun','queued',queued_count,'missing_checks',missing_count,'modules',module_names));
  END IF;

  RETURN jsonb_build_object('ok', true, 'queued', queued_count, 'missing_checks', missing_count, 'modules', module_names, 'active_jobs', active_count);
END;
$function$;
