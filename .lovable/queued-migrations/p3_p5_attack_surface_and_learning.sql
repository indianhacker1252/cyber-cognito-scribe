-- Queued migration — apply after Lovable Cloud resumes (or on the self-hosted VPS DB).
-- Ships P3 (ranked attack surface) and P5 (adaptive learning tables).

CREATE TABLE IF NOT EXISTS public.attack_surface (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id UUID NOT NULL REFERENCES public.targets(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  method TEXT NOT NULL DEFAULT 'GET',
  params JSONB NOT NULL DEFAULT '{}'::jsonb,
  tech TEXT[] NOT NULL DEFAULT '{}',
  auth_required BOOLEAN NOT NULL DEFAULT false,
  priority_score NUMERIC NOT NULL DEFAULT 0,
  last_probed TIMESTAMPTZ,
  verdicts JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (target_id, url, method)
);
CREATE INDEX IF NOT EXISTS idx_attack_surface_target_priority
  ON public.attack_surface(target_id, priority_score DESC);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.attack_surface TO authenticated;
GRANT ALL ON public.attack_surface TO service_role;
ALTER TABLE public.attack_surface ENABLE ROW LEVEL SECURITY;
CREATE POLICY "attack_surface owner rw" ON public.attack_surface
  FOR ALL TO authenticated
  USING (EXISTS (SELECT 1 FROM public.targets t WHERE t.id = attack_surface.target_id AND t.user_id = auth.uid()))
  WITH CHECK (EXISTS (SELECT 1 FROM public.targets t WHERE t.id = attack_surface.target_id AND t.user_id = auth.uid()));

CREATE TABLE IF NOT EXISTS public.technique_stats (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  technique TEXT NOT NULL,
  target_class TEXT NOT NULL DEFAULT 'generic',
  tries INTEGER NOT NULL DEFAULT 0,
  wins INTEGER NOT NULL DEFAULT 0,
  ucb1_score NUMERIC NOT NULL DEFAULT 0,
  last_used TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (technique, target_class)
);
GRANT SELECT ON public.technique_stats TO authenticated;
GRANT ALL ON public.technique_stats TO service_role;
ALTER TABLE public.technique_stats ENABLE ROW LEVEL SECURITY;
CREATE POLICY "technique_stats read all authed" ON public.technique_stats
  FOR SELECT TO authenticated USING (true);

CREATE TABLE IF NOT EXISTS public.bench_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ran_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  bench_name TEXT NOT NULL,
  precision NUMERIC,
  recall NUMERIC,
  f1 NUMERIC,
  detail JSONB NOT NULL DEFAULT '{}'::jsonb
);
GRANT SELECT ON public.bench_runs TO authenticated;
GRANT ALL ON public.bench_runs TO service_role;
ALTER TABLE public.bench_runs ENABLE ROW LEVEL SECURITY;
CREATE POLICY "bench_runs read all authed" ON public.bench_runs
  FOR SELECT TO authenticated USING (true);
