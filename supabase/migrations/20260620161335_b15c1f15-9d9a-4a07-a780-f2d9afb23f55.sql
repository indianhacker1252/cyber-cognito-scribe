UPDATE public.mythos_runs SET status='failed', completed_at=now() WHERE status IN ('running','paused');
TRUNCATE TABLE public.scan_jobs RESTART IDENTITY;