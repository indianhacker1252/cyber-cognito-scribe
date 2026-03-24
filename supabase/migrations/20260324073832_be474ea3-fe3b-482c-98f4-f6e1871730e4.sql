
-- Create approval status enum
CREATE TYPE public.approval_status AS ENUM ('pending', 'approved', 'rejected', 'escalated');

-- Create pending_approvals table for HITL queue
CREATE TABLE public.pending_approvals (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  target_id UUID NOT NULL REFERENCES public.target_workspaces(id) ON DELETE CASCADE,
  endpoint_id UUID REFERENCES public.discovered_endpoints(id) ON DELETE SET NULL,
  finding_type TEXT NOT NULL,
  severity severity_level NOT NULL DEFAULT 'medium',
  title TEXT NOT NULL,
  description TEXT,
  evidence JSONB NOT NULL DEFAULT '{}',
  parameter TEXT,
  payload_used TEXT,
  baseline_response JSONB,
  mutated_response JSONB,
  cve_ids TEXT[] DEFAULT '{}',
  cvss_score NUMERIC(3,1),
  status approval_status NOT NULL DEFAULT 'pending',
  reviewer_notes TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  reviewed_at TIMESTAMP WITH TIME ZONE
);

-- Enable RLS
ALTER TABLE public.pending_approvals ENABLE ROW LEVEL SECURITY;

-- Public access (security tool, not multi-tenant)
CREATE POLICY "Allow all access to pending_approvals" ON public.pending_approvals FOR ALL USING (true) WITH CHECK (true);

-- Enable realtime for approvals
ALTER PUBLICATION supabase_realtime ADD TABLE public.pending_approvals;

-- Indexes
CREATE INDEX idx_pending_approvals_status ON public.pending_approvals(status);
CREATE INDEX idx_pending_approvals_target ON public.pending_approvals(target_id);
CREATE INDEX idx_pending_approvals_severity ON public.pending_approvals(severity);
