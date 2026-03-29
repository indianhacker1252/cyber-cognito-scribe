
-- Experience Vault: stores scan experiences for learning
CREATE TABLE public.experience_vault (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  target_id UUID REFERENCES public.target_workspaces(id) ON DELETE CASCADE,
  tech_stack JSONB DEFAULT '{}'::jsonb,
  vuln_class TEXT NOT NULL,
  payload_used TEXT NOT NULL,
  http_method TEXT DEFAULT 'GET',
  response_status INTEGER,
  response_length INTEGER,
  response_snippet TEXT,
  outcome TEXT NOT NULL CHECK (outcome IN ('confirmed', 'false_positive', 'blocked', 'error')),
  confidence_score INTEGER DEFAULT 0,
  reward_score NUMERIC DEFAULT 0,
  embedding_vector TEXT,
  metadata JSONB DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE public.experience_vault ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all access to experience_vault" ON public.experience_vault FOR ALL TO public USING (true) WITH CHECK (true);

-- Strategy Weights: tech-stack effectiveness weighting
CREATE TABLE public.strategy_weights (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  tech_stack_key TEXT NOT NULL,
  vuln_class TEXT NOT NULL,
  tool_name TEXT NOT NULL,
  success_count INTEGER DEFAULT 0,
  failure_count INTEGER DEFAULT 0,
  effectiveness_pct NUMERIC DEFAULT 50,
  last_updated TIMESTAMPTZ DEFAULT now(),
  UNIQUE (tech_stack_key, vuln_class, tool_name)
);

ALTER TABLE public.strategy_weights ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all access to strategy_weights" ON public.strategy_weights FOR ALL TO public USING (true) WITH CHECK (true);

-- Method Discovery: stores discovered HTTP method/header combinations
CREATE TABLE public.method_discoveries (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  target_id UUID REFERENCES public.target_workspaces(id) ON DELETE CASCADE,
  endpoint_url TEXT NOT NULL,
  http_method TEXT NOT NULL,
  custom_headers JSONB DEFAULT '{}'::jsonb,
  response_status INTEGER,
  response_diff_pct NUMERIC DEFAULT 0,
  is_interesting BOOLEAN DEFAULT false,
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE public.method_discoveries ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all access to method_discoveries" ON public.method_discoveries FOR ALL TO public USING (true) WITH CHECK (true);

-- Indexes for fast lookups
CREATE INDEX idx_experience_vault_tech ON public.experience_vault USING gin (tech_stack);
CREATE INDEX idx_experience_vault_vuln ON public.experience_vault (vuln_class, outcome);
CREATE INDEX idx_strategy_weights_key ON public.strategy_weights (tech_stack_key, vuln_class);
CREATE INDEX idx_method_discoveries_target ON public.method_discoveries (target_id, is_interesting);
