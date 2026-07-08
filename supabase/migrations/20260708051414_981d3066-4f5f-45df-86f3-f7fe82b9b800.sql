
CREATE OR REPLACE FUNCTION public.abort_target_scan(_target_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  _jobs int := 0;
  _phases int := 0;
BEGIN
  UPDATE public.scan_jobs
     SET status = 'failed',
         completed_at = now(),
         error_message = COALESCE(error_message, 'aborted by user')
   WHERE target_id = _target_id
     AND status IN ('queued','running');
  GET DIAGNOSTICS _jobs = ROW_COUNT;

  UPDATE public.scan_phase_state
     SET status = 'failed',
         completed_at = now(),
         last_heartbeat = now()
   WHERE target_id = _target_id
     AND status = 'running';
  GET DIAGNOSTICS _phases = ROW_COUNT;

  INSERT INTO public.scan_logs (target_id, log_type, message)
  VALUES (_target_id, 'info',
          format('🛑 Scan aborted by user: %s jobs cancelled, %s phases reset', _jobs, _phases));

  RETURN jsonb_build_object('ok', true, 'jobs_cancelled', _jobs, 'phases_reset', _phases);
END;
$$;

GRANT EXECUTE ON FUNCTION public.abort_target_scan(uuid) TO authenticated, service_role;
