
CREATE TABLE IF NOT EXISTS public.ai_confidence_calibration (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id uuid NULL,
  vuln_class text NOT NULL,
  score int NOT NULL,
  verdict text NOT NULL,
  provider text NOT NULL,
  evidence_weights jsonb NOT NULL DEFAULT '{}'::jsonb,
  evidence_total int NOT NULL DEFAULT 0,
  outcome text NULL,
  outcome_marked_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE ON public.ai_confidence_calibration TO authenticated;
GRANT ALL ON public.ai_confidence_calibration TO service_role;
ALTER TABLE public.ai_confidence_calibration ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "admin read calibration" ON public.ai_confidence_calibration;
CREATE POLICY "admin read calibration" ON public.ai_confidence_calibration
  FOR SELECT TO authenticated
  USING (public.has_role(auth.uid(), 'admin'));

DROP POLICY IF EXISTS "admin update calibration" ON public.ai_confidence_calibration;
CREATE POLICY "admin update calibration" ON public.ai_confidence_calibration
  FOR UPDATE TO authenticated
  USING (public.has_role(auth.uid(), 'admin'));

DROP POLICY IF EXISTS "service insert calibration" ON public.ai_confidence_calibration;
CREATE POLICY "service insert calibration" ON public.ai_confidence_calibration
  FOR INSERT TO authenticated
  WITH CHECK (true);

CREATE INDEX IF NOT EXISTS ai_conf_calib_target_idx ON public.ai_confidence_calibration(target_id);
CREATE INDEX IF NOT EXISTS ai_conf_calib_verdict_idx ON public.ai_confidence_calibration(verdict, created_at DESC);
