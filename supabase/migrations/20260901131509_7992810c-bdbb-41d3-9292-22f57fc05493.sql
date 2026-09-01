CREATE OR REPLACE FUNCTION public.run_weekly_retention_cleanup()
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  result jsonb := '{}'::jsonb;
  affected integer := 0;
BEGIN
  DELETE FROM public.agent_events
   WHERE ts < now() - interval '30 days';
  GET DIAGNOSTICS affected = ROW_COUNT;
  result := result || jsonb_build_object('agent_events', affected);

  DELETE FROM public.tool_invocations
   WHERE created_at < now() - interval '30 days';
  GET DIAGNOSTICS affected = ROW_COUNT;
  result := result || jsonb_build_object('tool_invocations', affected);

  DELETE FROM public.planner_traces
   WHERE created_at < now() - interval '60 days';
  GET DIAGNOSTICS affected = ROW_COUNT;
  result := result || jsonb_build_object('planner_traces', affected);

  DELETE FROM public.scan_logs
   WHERE created_at < now() - interval '30 days';
  GET DIAGNOSTICS affected = ROW_COUNT;
  result := result || jsonb_build_object('scan_logs', affected);

  DELETE FROM public.scan_jobs
   WHERE status IN ('completed', 'failed', 'cancelled', 'aborted')
     AND COALESCE(completed_at, created_at) < now() - interval '30 days';
  GET DIAGNOSTICS affected = ROW_COUNT;
  result := result || jsonb_build_object('scan_jobs', affected);

  DELETE FROM public.sandbox_executions
   WHERE status NOT IN ('queued', 'running', 'pending')
     AND created_at < now() - interval '30 days';
  GET DIAGNOSTICS affected = ROW_COUNT;
  result := result || jsonb_build_object('sandbox_executions', affected);

  DELETE FROM public.intel_sync_runs
   WHERE status IN ('completed', 'failed')
     AND COALESCE(completed_at, started_at) < now() - interval '90 days';
  GET DIAGNOSTICS affected = ROW_COUNT;
  result := result || jsonb_build_object('intel_sync_runs', affected);

  DELETE FROM public.agent_sessions
   WHERE status IN ('completed', 'failed', 'aborted')
     AND COALESCE(completed_at, updated_at, created_at) < now() - interval '90 days';
  GET DIAGNOSTICS affected = ROW_COUNT;
  result := result || jsonb_build_object('agent_sessions', affected);

  RETURN jsonb_build_object('ok', true, 'ran_at', now(), 'deleted', result);
END;
$$;

REVOKE ALL ON FUNCTION public.run_weekly_retention_cleanup() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.run_weekly_retention_cleanup() TO service_role;

CREATE EXTENSION IF NOT EXISTS pg_cron;

DO $$
BEGIN
  PERFORM cron.unschedule('weekly-retention-cleanup');
EXCEPTION WHEN OTHERS THEN
  NULL;
END $$;

SELECT cron.schedule(
  'weekly-retention-cleanup',
  '30 2 * * 0',
  $cron$SELECT public.run_weekly_retention_cleanup();$cron$
);