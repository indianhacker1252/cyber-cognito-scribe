
CREATE TABLE public.evidence_packages (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  finding_id UUID REFERENCES public.vulnerability_findings(id) ON DELETE CASCADE,
  approval_id UUID REFERENCES public.pending_approvals(id) ON DELETE SET NULL,
  target_id UUID NOT NULL REFERENCES public.target_workspaces(id) ON DELETE CASCADE,
  poc_script TEXT,
  script_language TEXT DEFAULT 'python',
  terminal_output TEXT,
  validation_status TEXT NOT NULL DEFAULT 'pending',
  http_request_data JSONB DEFAULT '{}'::jsonb,
  http_response_data JSONB DEFAULT '{}'::jsonb,
  report_markdown TEXT,
  cvss_vector TEXT,
  cvss_score NUMERIC,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  validated_at TIMESTAMP WITH TIME ZONE
);

ALTER TABLE public.evidence_packages ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow all access to evidence_packages" ON public.evidence_packages FOR ALL TO public USING (true) WITH CHECK (true);

-- Add poc and report fields to vulnerability_findings if not present
ALTER TABLE public.vulnerability_findings ADD COLUMN IF NOT EXISTS validation_status TEXT DEFAULT 'unverified';
ALTER TABLE public.vulnerability_findings ADD COLUMN IF NOT EXISTS evidence_package_id UUID REFERENCES public.evidence_packages(id) ON DELETE SET NULL;
