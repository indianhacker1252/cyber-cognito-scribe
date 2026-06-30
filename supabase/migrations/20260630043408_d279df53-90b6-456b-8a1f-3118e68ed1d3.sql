
CREATE TABLE IF NOT EXISTS public.finding_evidence (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id uuid NOT NULL REFERENCES public.vulnerability_findings(id) ON DELETE CASCADE,
  target_id uuid NOT NULL,
  affected_url text,
  method text,
  param text,
  payload text,
  status_code int,
  request_raw text,
  response_raw text,
  evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS finding_evidence_finding_idx ON public.finding_evidence(finding_id, created_at DESC);
CREATE INDEX IF NOT EXISTS finding_evidence_target_idx  ON public.finding_evidence(target_id, created_at DESC);

GRANT SELECT ON public.finding_evidence TO authenticated;
GRANT ALL ON public.finding_evidence TO service_role;
ALTER TABLE public.finding_evidence ENABLE ROW LEVEL SECURITY;

CREATE POLICY "evidence_authenticated_read" ON public.finding_evidence
  FOR SELECT TO authenticated USING (true);

ALTER TABLE public.vulnerability_findings
  ADD COLUMN IF NOT EXISTS evidence_count int NOT NULL DEFAULT 1,
  ADD COLUMN IF NOT EXISTS first_seen_at timestamptz NOT NULL DEFAULT now(),
  ADD COLUMN IF NOT EXISTS last_seen_at  timestamptz NOT NULL DEFAULT now(),
  ADD COLUMN IF NOT EXISTS group_key text;

CREATE INDEX IF NOT EXISTS vf_group_key_idx ON public.vulnerability_findings(target_id, group_key);
