
CREATE TABLE IF NOT EXISTS public.external_infra_config (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  service text NOT NULL UNIQUE,
  mode text NOT NULL DEFAULT 'disabled',
  endpoint_url text,
  auth_token text,
  extra_config jsonb DEFAULT '{}'::jsonb,
  is_active boolean NOT NULL DEFAULT false,
  last_health_check timestamptz,
  health_status text DEFAULT 'unknown',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.external_infra_config ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Allow all access to external_infra_config"
  ON public.external_infra_config FOR ALL
  USING (true) WITH CHECK (true);

CREATE TRIGGER update_external_infra_config_updated_at
  BEFORE UPDATE ON public.external_infra_config
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();
