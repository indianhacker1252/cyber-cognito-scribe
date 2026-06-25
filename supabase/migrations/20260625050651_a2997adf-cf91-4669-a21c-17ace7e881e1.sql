
CREATE TABLE IF NOT EXISTS public.waf_profiles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id UUID NOT NULL REFERENCES public.target_workspaces(id) ON DELETE CASCADE,
  waf_type TEXT DEFAULT 'generic',
  fingerprint JSONB DEFAULT '{}'::jsonb,
  blocked_techniques JSONB DEFAULT '[]'::jsonb,
  working_techniques JSONB DEFAULT '[]'::jsonb,
  last_updated TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(target_id)
);

CREATE INDEX IF NOT EXISTS idx_waf_profiles_target ON public.waf_profiles(target_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON public.waf_profiles TO authenticated;
GRANT ALL ON public.waf_profiles TO service_role;

ALTER TABLE public.waf_profiles ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Authenticated read waf profiles" ON public.waf_profiles
FOR SELECT TO authenticated USING (true);

CREATE POLICY "Service role manages waf profiles" ON public.waf_profiles
FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "Admins manage waf profiles" ON public.waf_profiles
FOR ALL TO authenticated USING (public.has_role(auth.uid(),'admin')) WITH CHECK (public.has_role(auth.uid(),'admin'));
