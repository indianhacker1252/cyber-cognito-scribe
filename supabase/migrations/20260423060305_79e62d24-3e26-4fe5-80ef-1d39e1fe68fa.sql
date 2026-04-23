-- Mythos debate transcripts: two adversarial agents discussing a param/payload
CREATE TABLE IF NOT EXISTS public.mythos_debates (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id uuid NOT NULL,
  run_id uuid,
  endpoint_url text,
  param_name text,
  param_value text,
  vuln_class text,
  -- Conversation between Agent A (recon analyst) and Agent B (exploit strategist)
  transcript jsonb NOT NULL DEFAULT '[]'::jsonb,
  -- Final agreed payload, action result, FP debate
  agreed_payload text,
  agreed_rationale text,
  test_result jsonb DEFAULT '{}'::jsonb,
  fp_verdict text DEFAULT 'unknown', -- true_positive | false_positive | inconclusive
  fp_reasoning text,
  confidence_score integer DEFAULT 0,
  -- Self-correlation: what each agent learned
  agent_a_learning text,
  agent_b_learning text,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.mythos_debates ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all access to mythos_debates" ON public.mythos_debates FOR ALL USING (true) WITH CHECK (true);
CREATE INDEX IF NOT EXISTS mythos_debates_target_idx ON public.mythos_debates(target_id, created_at DESC);

-- Patch validation: results of static checks before persisting
CREATE TABLE IF NOT EXISTS public.patch_validations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  patch_id uuid,
  finding_id uuid,
  target_id uuid NOT NULL,
  -- Static check results
  syntax_ok boolean DEFAULT false,
  lint_warnings jsonb DEFAULT '[]'::jsonb,
  risk_score integer DEFAULT 50, -- 0=safe, 100=high risk
  risk_factors jsonb DEFAULT '[]'::jsonb,
  -- Threshold gate
  passed_threshold boolean DEFAULT false,
  threshold_used integer DEFAULT 70,
  validator_notes text,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.patch_validations ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all access to patch_validations" ON public.patch_validations FOR ALL USING (true) WITH CHECK (true);
CREATE INDEX IF NOT EXISTS patch_validations_target_idx ON public.patch_validations(target_id, created_at DESC);

-- Add validation columns to mythos_patches
ALTER TABLE public.mythos_patches
  ADD COLUMN IF NOT EXISTS validation_status text DEFAULT 'pending',
  ADD COLUMN IF NOT EXISTS validation_id uuid,
  ADD COLUMN IF NOT EXISTS risk_score integer DEFAULT 50;

-- Add fuzz job route mapping (for variant gen)
-- (scan_jobs already supports custom job_type, no schema change needed; worker route added below)
