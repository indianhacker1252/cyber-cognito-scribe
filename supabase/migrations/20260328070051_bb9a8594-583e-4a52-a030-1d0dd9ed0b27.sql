
CREATE TABLE public.suppression_vectors (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  target_id UUID REFERENCES public.target_workspaces(id) ON DELETE CASCADE,
  finding_type TEXT NOT NULL,
  vuln_class TEXT,
  request_pattern JSONB DEFAULT '{}'::jsonb,
  response_pattern JSONB DEFAULT '{}'::jsonb,
  suppression_reason TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  created_by TEXT DEFAULT 'human'
);

ALTER TABLE public.suppression_vectors ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow all access to suppression_vectors" ON public.suppression_vectors FOR ALL TO public USING (true) WITH CHECK (true);

ALTER TABLE public.vulnerability_findings ADD COLUMN IF NOT EXISTS reachability_status TEXT DEFAULT 'unknown';
ALTER TABLE public.vulnerability_findings ADD COLUMN IF NOT EXISTS triage_reasoning TEXT;
ALTER TABLE public.vulnerability_findings ADD COLUMN IF NOT EXISTS confidence_score INTEGER DEFAULT 0;

ALTER TABLE public.pending_approvals ADD COLUMN IF NOT EXISTS reachability_status TEXT DEFAULT 'unknown';
ALTER TABLE public.pending_approvals ADD COLUMN IF NOT EXISTS triage_reasoning TEXT;
ALTER TABLE public.pending_approvals ADD COLUMN IF NOT EXISTS confidence_score INTEGER DEFAULT 0;
