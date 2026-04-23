-- ============ MYTHOS MODE SCHEMA ============

-- Per-target opt-in for auto Mythos after recon
ALTER TABLE public.target_workspaces
  ADD COLUMN IF NOT EXISTS auto_mythos boolean NOT NULL DEFAULT false;

-- Codebase ingestion (Pillar 1)
CREATE TABLE IF NOT EXISTS public.code_repositories (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id uuid NOT NULL,
  repo_url text,
  branch text DEFAULT 'main',
  language text,
  file_count integer DEFAULT 0,
  ingestion_status text NOT NULL DEFAULT 'pending',
  ingestion_log jsonb DEFAULT '[]'::jsonb,
  source_tree jsonb DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.code_repositories ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all access to code_repositories" ON public.code_repositories FOR ALL USING (true) WITH CHECK (true);

CREATE TABLE IF NOT EXISTS public.code_findings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  repository_id uuid NOT NULL,
  target_id uuid NOT NULL,
  vuln_class text NOT NULL,
  severity text NOT NULL DEFAULT 'medium',
  file_path text NOT NULL,
  line_start integer,
  line_end integer,
  source_snippet text,
  sink_snippet text,
  taint_path jsonb DEFAULT '[]'::jsonb,
  reachability_confirmed boolean DEFAULT false,
  linked_dast_finding_id uuid,
  ai_reasoning text,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.code_findings ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all access to code_findings" ON public.code_findings FOR ALL USING (true) WITH CHECK (true);

-- Long-horizon agent runs (Pillar 3)
CREATE TABLE IF NOT EXISTS public.mythos_runs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id uuid NOT NULL,
  status text NOT NULL DEFAULT 'queued',
  trigger_type text NOT NULL DEFAULT 'manual',
  iteration integer NOT NULL DEFAULT 0,
  max_iterations integer NOT NULL DEFAULT 8,
  thought_log jsonb DEFAULT '[]'::jsonb,
  findings_count integer DEFAULT 0,
  chains_count integer DEFAULT 0,
  variants_count integer DEFAULT 0,
  current_phase text DEFAULT 'init',
  started_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.mythos_runs ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all access to mythos_runs" ON public.mythos_runs FOR ALL USING (true) WITH CHECK (true);

-- Auto-discovered exploit chains (Pillar 2)
CREATE TABLE IF NOT EXISTS public.mythos_chains (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  run_id uuid,
  target_id uuid NOT NULL,
  chain_name text NOT NULL,
  chain_narrative text,
  steps jsonb NOT NULL DEFAULT '[]'::jsonb,
  finding_ids jsonb DEFAULT '[]'::jsonb,
  combined_severity text DEFAULT 'high',
  combined_cvss numeric,
  execution_status text DEFAULT 'proposed',
  execution_evidence jsonb DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.mythos_chains ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all access to mythos_chains" ON public.mythos_chains FOR ALL USING (true) WITH CHECK (true);

-- Zero-day variant generation (Pillar 4)
CREATE TABLE IF NOT EXISTS public.mythos_variants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  run_id uuid,
  target_id uuid NOT NULL,
  parent_cve text,
  vuln_class text NOT NULL,
  root_cause_pattern text,
  variant_payload text NOT NULL,
  variant_rationale text,
  test_endpoint text,
  test_status text DEFAULT 'pending',
  test_result jsonb DEFAULT '{}'::jsonb,
  is_zero_day_candidate boolean DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.mythos_variants ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all access to mythos_variants" ON public.mythos_variants FOR ALL USING (true) WITH CHECK (true);

-- Auto-generated defensive patches (Pillar 5)
CREATE TABLE IF NOT EXISTS public.mythos_patches (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id uuid,
  target_id uuid NOT NULL,
  patch_type text NOT NULL DEFAULT 'code',
  language text,
  framework text,
  patch_diff text,
  waf_rule text,
  config_change text,
  rationale text,
  applied boolean DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.mythos_patches ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all access to mythos_patches" ON public.mythos_patches FOR ALL USING (true) WITH CHECK (true);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_code_findings_target ON public.code_findings(target_id);
CREATE INDEX IF NOT EXISTS idx_mythos_runs_target ON public.mythos_runs(target_id);
CREATE INDEX IF NOT EXISTS idx_mythos_runs_status ON public.mythos_runs(status);
CREATE INDEX IF NOT EXISTS idx_mythos_chains_run ON public.mythos_chains(run_id);
CREATE INDEX IF NOT EXISTS idx_mythos_variants_run ON public.mythos_variants(run_id);
CREATE INDEX IF NOT EXISTS idx_mythos_patches_finding ON public.mythos_patches(finding_id);

-- updated_at triggers
CREATE TRIGGER update_code_repositories_updated_at BEFORE UPDATE ON public.code_repositories
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();
CREATE TRIGGER update_mythos_runs_updated_at BEFORE UPDATE ON public.mythos_runs
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();