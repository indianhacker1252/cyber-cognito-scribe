
ALTER TABLE public.pending_approvals ADD COLUMN IF NOT EXISTS confidence_level text DEFAULT 'medium';
ALTER TABLE public.pending_approvals ADD COLUMN IF NOT EXISTS ai_verified boolean DEFAULT false;
ALTER TABLE public.pending_approvals ADD COLUMN IF NOT EXISTS ai_verification_notes text;
ALTER TABLE public.pending_approvals ADD COLUMN IF NOT EXISTS request_data jsonb DEFAULT '{}'::jsonb;
ALTER TABLE public.pending_approvals ADD COLUMN IF NOT EXISTS response_data jsonb DEFAULT '{}'::jsonb;

ALTER TABLE public.vulnerability_findings ADD COLUMN IF NOT EXISTS confidence_level text DEFAULT 'medium';
ALTER TABLE public.vulnerability_findings ADD COLUMN IF NOT EXISTS ai_verified boolean DEFAULT false;
