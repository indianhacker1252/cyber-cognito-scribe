
CREATE TABLE IF NOT EXISTS public.oob_callbacks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token text NOT NULL UNIQUE,
  target_id uuid,
  finding_id uuid,
  vuln_class text,
  payload_context text,
  callback_type text NOT NULL DEFAULT 'http',
  source_ip text,
  user_agent text,
  request_method text,
  request_path text,
  request_headers jsonb DEFAULT '{}'::jsonb,
  request_body text,
  received_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_oob_token ON public.oob_callbacks(token);
CREATE INDEX IF NOT EXISTS idx_oob_target ON public.oob_callbacks(target_id);
ALTER TABLE public.oob_callbacks ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all access to oob_callbacks" ON public.oob_callbacks FOR ALL USING (true) WITH CHECK (true);

CREATE TABLE IF NOT EXISTS public.auth_profiles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id uuid NOT NULL,
  profile_name text NOT NULL DEFAULT 'default',
  auth_type text NOT NULL DEFAULT 'cookie',
  cookie_header text,
  bearer_token text,
  login_url text,
  login_method text DEFAULT 'POST',
  login_body_template text,
  login_username text,
  login_password text,
  session_extract_regex text,
  last_validated_at timestamptz,
  is_valid boolean DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_auth_target ON public.auth_profiles(target_id);
ALTER TABLE public.auth_profiles ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all access to auth_profiles" ON public.auth_profiles FOR ALL USING (true) WITH CHECK (true);
CREATE TRIGGER trg_auth_profiles_updated BEFORE UPDATE ON public.auth_profiles
  FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

CREATE TABLE IF NOT EXISTS public.exploit_chains (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id uuid NOT NULL,
  chain_name text NOT NULL,
  chain_steps jsonb NOT NULL DEFAULT '[]'::jsonb,
  state_variables jsonb DEFAULT '{}'::jsonb,
  execution_log jsonb DEFAULT '[]'::jsonb,
  status text NOT NULL DEFAULT 'pending',
  final_evidence jsonb DEFAULT '{}'::jsonb,
  severity text DEFAULT 'medium',
  created_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz
);
CREATE INDEX IF NOT EXISTS idx_chain_target ON public.exploit_chains(target_id);
ALTER TABLE public.exploit_chains ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all access to exploit_chains" ON public.exploit_chains FOR ALL USING (true) WITH CHECK (true);

CREATE TABLE IF NOT EXISTS public.scan_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id uuid NOT NULL,
  job_type text NOT NULL,
  priority int NOT NULL DEFAULT 5,
  status text NOT NULL DEFAULT 'queued',
  payload jsonb DEFAULT '{}'::jsonb,
  result jsonb DEFAULT '{}'::jsonb,
  error_message text,
  attempts int NOT NULL DEFAULT 0,
  max_attempts int NOT NULL DEFAULT 3,
  created_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz,
  completed_at timestamptz,
  next_run_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_jobs_status_next ON public.scan_jobs(status, next_run_at);
CREATE INDEX IF NOT EXISTS idx_jobs_target ON public.scan_jobs(target_id);
ALTER TABLE public.scan_jobs ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all access to scan_jobs" ON public.scan_jobs FOR ALL USING (true) WITH CHECK (true);

CREATE TABLE IF NOT EXISTS public.canary_baselines (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id uuid NOT NULL,
  canary_name text NOT NULL,
  payload text NOT NULL,
  baseline_status int,
  baseline_body_hash text,
  baseline_body_length int,
  baseline_blocked boolean DEFAULT false,
  current_status int,
  current_body_hash text,
  current_body_length int,
  current_blocked boolean DEFAULT false,
  drift_detected boolean DEFAULT false,
  last_checked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_canary_target ON public.canary_baselines(target_id);
ALTER TABLE public.canary_baselines ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all access to canary_baselines" ON public.canary_baselines FOR ALL USING (true) WITH CHECK (true);
