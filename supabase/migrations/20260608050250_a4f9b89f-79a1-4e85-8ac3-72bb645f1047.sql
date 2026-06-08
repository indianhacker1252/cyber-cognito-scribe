ALTER TABLE public.target_workspaces
  ADD COLUMN IF NOT EXISTS custom_payloads jsonb NOT NULL DEFAULT '[]'::jsonb;

GRANT SELECT, INSERT, UPDATE, DELETE ON public.target_workspaces TO authenticated;
GRANT ALL ON public.target_workspaces TO service_role;