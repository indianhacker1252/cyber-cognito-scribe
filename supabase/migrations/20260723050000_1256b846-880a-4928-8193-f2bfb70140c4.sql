
CREATE TABLE IF NOT EXISTS public.target_world_model (
  target_id uuid PRIMARY KEY REFERENCES public.target_workspaces(id) ON DELETE CASCADE,
  model jsonb NOT NULL DEFAULT '{}'::jsonb,
  updated_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT, UPDATE, DELETE ON public.target_world_model TO authenticated;
GRANT ALL ON public.target_world_model TO service_role;

ALTER TABLE public.target_world_model ENABLE ROW LEVEL SECURITY;

CREATE POLICY "world_model_auth_all"
  ON public.target_world_model FOR ALL
  TO authenticated
  USING (true) WITH CHECK (true);

CREATE OR REPLACE FUNCTION public.update_world_model_updated_at()
RETURNS trigger LANGUAGE plpgsql SET search_path = public AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END $$;

DROP TRIGGER IF EXISTS trg_world_model_updated_at ON public.target_world_model;
CREATE TRIGGER trg_world_model_updated_at
  BEFORE UPDATE ON public.target_world_model
  FOR EACH ROW EXECUTE FUNCTION public.update_world_model_updated_at();

CREATE OR REPLACE FUNCTION public.merge_world_model(_target_id uuid, _patch jsonb)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE merged jsonb;
BEGIN
  INSERT INTO public.target_world_model(target_id, model)
  VALUES (_target_id, COALESCE(_patch, '{}'::jsonb))
  ON CONFLICT (target_id) DO UPDATE
    SET model = public.target_world_model.model || COALESCE(_patch, '{}'::jsonb),
        updated_at = now()
  RETURNING model INTO merged;
  RETURN merged;
END $$;

GRANT EXECUTE ON FUNCTION public.merge_world_model(uuid, jsonb) TO authenticated, service_role;
