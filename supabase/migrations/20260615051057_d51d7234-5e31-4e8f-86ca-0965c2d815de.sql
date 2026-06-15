ALTER TABLE public.vulnerability_findings
  ADD COLUMN IF NOT EXISTS affected_url text,
  ADD COLUMN IF NOT EXISTS vuln_class text,
  ADD COLUMN IF NOT EXISTS evidence jsonb DEFAULT '{}'::jsonb;

ALTER TABLE public.vulnerability_findings
  DROP CONSTRAINT IF EXISTS vulnerability_findings_proof_tier_check;

ALTER TABLE public.vulnerability_findings
  ADD CONSTRAINT vulnerability_findings_proof_tier_check
  CHECK (proof_tier IN ('signal', 'reflected', 'exploited', 'suspected', 'indicator', 'advisory'));

ALTER TABLE public.vulnerability_findings
  DROP CONSTRAINT IF EXISTS vulnerability_findings_raw_evidence_for_new_rows;

ALTER TABLE public.vulnerability_findings
  ADD CONSTRAINT vulnerability_findings_evidence_for_new_rows
  CHECK (
    created_at < '2026-06-14 00:00:00+00'::timestamptz
    OR request_raw IS NOT NULL
    OR response_raw IS NOT NULL
    OR COALESCE(jsonb_typeof(hard_evidence), 'null') = 'object' AND hard_evidence <> '{}'::jsonb
    OR COALESCE(jsonb_typeof(evidence), 'null') = 'object' AND evidence <> '{}'::jsonb
    OR source IS NULL
    OR source IN ('manual', 'chat')
  ) NOT VALID;

GRANT SELECT, INSERT, UPDATE ON public.vulnerability_findings TO authenticated;
GRANT ALL ON public.vulnerability_findings TO service_role;