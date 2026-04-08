CREATE TABLE public.ai_provider_config (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  provider TEXT NOT NULL,
  api_key TEXT NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT true,
  priority INTEGER NOT NULL DEFAULT 1,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  UNIQUE(provider)
);

ALTER TABLE public.ai_provider_config ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all access to ai_provider_config" ON public.ai_provider_config FOR ALL USING (true) WITH CHECK (true);