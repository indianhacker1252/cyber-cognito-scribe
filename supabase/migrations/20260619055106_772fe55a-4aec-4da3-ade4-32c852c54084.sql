CREATE INDEX IF NOT EXISTS scan_jobs_queue_poll_idx
  ON public.scan_jobs (status, next_run_at, priority DESC, created_at)
  WHERE status = 'queued';

CREATE INDEX IF NOT EXISTS scan_jobs_stuck_sweep_idx
  ON public.scan_jobs (status, started_at)
  WHERE status = 'running';

CREATE INDEX IF NOT EXISTS scan_jobs_mythos_dedup_idx
  ON public.scan_jobs (job_type, (payload->>'runId'), (payload->>'nextPhase'))
  WHERE status = 'queued';