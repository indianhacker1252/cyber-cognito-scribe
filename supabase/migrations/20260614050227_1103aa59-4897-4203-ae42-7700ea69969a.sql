GRANT SELECT, INSERT, UPDATE, DELETE ON public.scan_jobs TO authenticated;
GRANT ALL ON public.scan_jobs TO service_role;

GRANT SELECT, INSERT, UPDATE, DELETE ON public.request_replays TO authenticated;
GRANT ALL ON public.request_replays TO service_role;

GRANT SELECT, INSERT, UPDATE, DELETE ON public.exploit_chains TO authenticated;
GRANT ALL ON public.exploit_chains TO service_role;

GRANT SELECT, INSERT, UPDATE ON public.mythos_runs TO authenticated;
GRANT ALL ON public.mythos_runs TO service_role;

GRANT SELECT, INSERT, UPDATE ON public.mythos_chains TO authenticated;
GRANT ALL ON public.mythos_chains TO service_role;

GRANT SELECT, INSERT, UPDATE ON public.vulnerability_findings TO authenticated;
GRANT ALL ON public.vulnerability_findings TO service_role;

GRANT SELECT, INSERT, UPDATE ON public.scan_logs TO authenticated;
GRANT ALL ON public.scan_logs TO service_role;

ALTER TABLE public.vulnerability_findings
  ADD CONSTRAINT vulnerability_findings_raw_evidence_for_new_rows
  CHECK (
    created_at < '2026-06-14 00:00:00+00'::timestamptz
    OR request_raw IS NOT NULL
    OR response_raw IS NOT NULL
    OR source IS NULL
    OR source IN ('manual', 'chat')
  ) NOT VALID;