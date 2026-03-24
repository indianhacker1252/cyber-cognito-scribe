
CREATE TABLE public.adaptation_chains (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  finding_id UUID REFERENCES public.vulnerability_findings(id) ON DELETE SET NULL,
  approval_id UUID REFERENCES public.pending_approvals(id) ON DELETE SET NULL,
  target_id UUID NOT NULL REFERENCES public.target_workspaces(id) ON DELETE CASCADE,
  initial_request JSONB DEFAULT '{}'::jsonb,
  filter_classification TEXT,
  adaptation_steps JSONB DEFAULT '[]'::jsonb,
  final_poc_script TEXT,
  final_poc_language TEXT DEFAULT 'python',
  verification_status TEXT NOT NULL DEFAULT 'pending',
  ai_reasoning TEXT,
  audit_report_markdown TEXT,
  cvss_score NUMERIC,
  cvss_vector TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

ALTER TABLE public.adaptation_chains ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow all access to adaptation_chains"
  ON public.adaptation_chains FOR ALL
  TO public
  USING (true)
  WITH CHECK (true);

CREATE TRIGGER update_adaptation_chains_updated_at
  BEFORE UPDATE ON public.adaptation_chains
  FOR EACH ROW
  EXECUTE FUNCTION public.update_updated_at_column();
