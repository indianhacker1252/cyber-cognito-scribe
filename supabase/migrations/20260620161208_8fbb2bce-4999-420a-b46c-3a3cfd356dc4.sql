TRUNCATE TABLE public.scan_jobs RESTART IDENTITY;
-- Note: VACUUM FULL cannot run in a tx; TRUNCATE already reclaims the heap.