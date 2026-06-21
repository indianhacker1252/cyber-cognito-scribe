
CREATE TABLE IF NOT EXISTS public.scan_assets (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id uuid NOT NULL REFERENCES public.target_workspaces(id) ON DELETE CASCADE,
  host text NOT NULL,
  base_url text NOT NULL,
  source text NOT NULL DEFAULT 'apex',
  is_dead boolean NOT NULL DEFAULT false,
  last_scanned_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (target_id, host)
);
GRANT SELECT ON public.scan_assets TO authenticated;
GRANT ALL ON public.scan_assets TO service_role;
ALTER TABLE public.scan_assets ENABLE ROW LEVEL SECURITY;
CREATE POLICY "scan_assets admin read" ON public.scan_assets FOR SELECT TO authenticated USING (public.has_role(auth.uid(),'admin'));
CREATE INDEX IF NOT EXISTS scan_assets_target_idx ON public.scan_assets(target_id);

CREATE TABLE IF NOT EXISTS public.discovered_forms (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id uuid NOT NULL REFERENCES public.target_workspaces(id) ON DELETE CASCADE,
  page_url text NOT NULL,
  action_url text NOT NULL,
  method text NOT NULL DEFAULT 'POST',
  enctype text NOT NULL DEFAULT 'application/x-www-form-urlencoded',
  fields jsonb NOT NULL DEFAULT '[]'::jsonb,
  has_file_upload boolean NOT NULL DEFAULT false,
  last_attacked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (target_id, action_url, method)
);
GRANT SELECT ON public.discovered_forms TO authenticated;
GRANT ALL ON public.discovered_forms TO service_role;
ALTER TABLE public.discovered_forms ENABLE ROW LEVEL SECURITY;
CREATE POLICY "discovered_forms admin read" ON public.discovered_forms FOR SELECT TO authenticated USING (public.has_role(auth.uid(),'admin'));
CREATE INDEX IF NOT EXISTS discovered_forms_target_idx ON public.discovered_forms(target_id);

CREATE TABLE IF NOT EXISTS public.kill_chain_graph_edges (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id uuid NOT NULL REFERENCES public.target_workspaces(id) ON DELETE CASCADE,
  parent_finding_id uuid REFERENCES public.vulnerability_findings(id) ON DELETE CASCADE,
  child_finding_id uuid REFERENCES public.vulnerability_findings(id) ON DELETE CASCADE,
  primitive_consumed text,
  primitive_produced text,
  depth integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (parent_finding_id, child_finding_id)
);
GRANT SELECT ON public.kill_chain_graph_edges TO authenticated;
GRANT ALL ON public.kill_chain_graph_edges TO service_role;
ALTER TABLE public.kill_chain_graph_edges ENABLE ROW LEVEL SECURITY;
CREATE POLICY "kc_edges admin read" ON public.kill_chain_graph_edges FOR SELECT TO authenticated USING (public.has_role(auth.uid(),'admin'));
CREATE INDEX IF NOT EXISTS kc_edges_target_idx ON public.kill_chain_graph_edges(target_id);
CREATE INDEX IF NOT EXISTS kc_edges_parent_idx ON public.kill_chain_graph_edges(parent_finding_id);
