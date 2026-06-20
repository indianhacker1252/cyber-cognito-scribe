CREATE OR REPLACE FUNCTION public.block_orphan_mythos_steps()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  s text;
BEGIN
  IF NEW.job_type <> 'mythos_step' THEN RETURN NEW; END IF;
  IF NEW.payload IS NULL OR NEW.payload->>'runId' IS NULL THEN RETURN NULL; END IF;
  SELECT status INTO s FROM public.mythos_runs WHERE id = (NEW.payload->>'runId')::uuid;
  IF s IS DISTINCT FROM 'running' THEN
    RAISE NOTICE 'block_orphan_mythos_steps: dropping mythos_step for run %, status=%', NEW.payload->>'runId', COALESCE(s,'missing');
    RETURN NULL;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS block_orphan_mythos_steps_trg ON public.scan_jobs;
CREATE TRIGGER block_orphan_mythos_steps_trg
  BEFORE INSERT ON public.scan_jobs
  FOR EACH ROW EXECUTE FUNCTION public.block_orphan_mythos_steps();

TRUNCATE TABLE public.scan_jobs RESTART IDENTITY;