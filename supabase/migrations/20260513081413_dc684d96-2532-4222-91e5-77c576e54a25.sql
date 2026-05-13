
CREATE OR REPLACE FUNCTION public.fail_stuck_mythos_runs()
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  n integer;
BEGIN
  WITH upd AS (
    UPDATE public.mythos_runs
       SET status = 'failed',
           completed_at = now(),
           thought_log = COALESCE(thought_log, '[]'::jsonb) ||
             jsonb_build_array(jsonb_build_object(
               'ts', now(), 'phase', current_phase, 'msg',
               'Auto-failed: no progress for >60min (stuck-run sweeper)'))
     WHERE status = 'running'
       AND updated_at < now() - interval '60 minutes'
    RETURNING 1
  )
  SELECT count(*) INTO n FROM upd;
  RETURN n;
END;
$$;

CREATE EXTENSION IF NOT EXISTS pg_cron;

DO $$
BEGIN
  PERFORM cron.unschedule('fail-stuck-mythos-runs');
EXCEPTION WHEN OTHERS THEN NULL;
END $$;

SELECT cron.schedule(
  'fail-stuck-mythos-runs',
  '*/10 * * * *',
  $$ SELECT public.fail_stuck_mythos_runs(); $$
);
