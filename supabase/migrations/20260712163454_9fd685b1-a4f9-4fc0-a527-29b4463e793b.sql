-- Ghost-target sweep: purge scan_jobs and phase state belonging to targets
-- that no longer exist. Also add a foreign-key style cleanup trigger so
-- deleted targets cascade their pending work.
DELETE FROM public.scan_jobs
 WHERE target_id IS NOT NULL
   AND target_id NOT IN (SELECT id FROM public.target_workspaces);

DELETE FROM public.scan_phase_state
 WHERE target_id IS NOT NULL
   AND target_id NOT IN (SELECT id FROM public.target_workspaces);
