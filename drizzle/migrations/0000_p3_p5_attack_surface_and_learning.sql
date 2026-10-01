CREATE TABLE IF NOT EXISTS public.attack_surface (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id UUID NOT NULL REFERENCES public.target_workspaces(id) ON DELETE CASCADE,
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
CREATE POLICY "attack_surface authed rw" ON public.attack_surface
  FOR ALL TO authenticated USING (true) WITH CHECK (true);

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

-- UCB1 helper: record technique outcome and recompute score.
CREATE OR REPLACE FUNCTION public.record_technique_outcome(_technique text, _target_class text, _won boolean)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  _total_tries bigint;
BEGIN
  INSERT INTO public.technique_stats(technique, target_class, tries, wins, last_used, updated_at)
  VALUES (_technique, COALESCE(_target_class,'generic'), 1, CASE WHEN _won THEN 1 ELSE 0 END, now(), now())
  ON CONFLICT (technique, target_class) DO UPDATE
    SET tries = technique_stats.tries + 1,
        wins = technique_stats.wins + CASE WHEN _won THEN 1 ELSE 0 END,
        last_used = now(),
        updated_at = now();
  SELECT GREATEST(sum(tries),1) INTO _total_tries FROM public.technique_stats WHERE target_class = COALESCE(_target_class,'generic');
  UPDATE public.technique_stats
     SET ucb1_score = (wins::numeric / NULLIF(tries,0)) + sqrt(2.0 * ln(_total_tries::numeric) / NULLIF(tries,0))
   WHERE target_class = COALESCE(_target_class,'generic');
END $$;
GRANT EXECUTE ON FUNCTION public.record_technique_outcome(text,text,boolean) TO authenticated, service_role;