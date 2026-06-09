
CREATE TABLE public.attack_graph_nodes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id uuid NOT NULL REFERENCES public.target_workspaces(id) ON DELETE CASCADE,
  node_type text NOT NULL,
  label text NOT NULL,
  capability_tags text[] NOT NULL DEFAULT '{}',
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  source_finding_id uuid,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_agn_target ON public.attack_graph_nodes(target_id);

CREATE TABLE public.attack_graph_edges (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id uuid NOT NULL REFERENCES public.target_workspaces(id) ON DELETE CASCADE,
  from_node uuid NOT NULL REFERENCES public.attack_graph_nodes(id) ON DELETE CASCADE,
  to_node   uuid NOT NULL REFERENCES public.attack_graph_nodes(id) ON DELETE CASCADE,
  technique text NOT NULL,
  cost integer NOT NULL DEFAULT 10,
  confidence numeric NOT NULL DEFAULT 0.5,
  evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_age_target ON public.attack_graph_edges(target_id);
CREATE INDEX idx_age_from ON public.attack_graph_edges(from_node);

CREATE TABLE public.kill_chains (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id uuid NOT NULL REFERENCES public.target_workspaces(id) ON DELETE CASCADE,
  goal text NOT NULL,
  total_cost integer NOT NULL,
  severity text NOT NULL DEFAULT 'high',
  node_path uuid[] NOT NULL,
  step_plan jsonb NOT NULL,
  status text NOT NULL DEFAULT 'proposed',
  execution_result jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_kc_target ON public.kill_chains(target_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON public.attack_graph_nodes TO authenticated;
GRANT ALL ON public.attack_graph_nodes TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.attack_graph_edges TO authenticated;
GRANT ALL ON public.attack_graph_edges TO service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.kill_chains TO authenticated;
GRANT ALL ON public.kill_chains TO service_role;

ALTER TABLE public.attack_graph_nodes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.attack_graph_edges ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.kill_chains ENABLE ROW LEVEL SECURITY;

CREATE POLICY "agn_auth_read"  ON public.attack_graph_nodes FOR SELECT TO authenticated USING (true);
CREATE POLICY "agn_admin_write" ON public.attack_graph_nodes FOR ALL    TO authenticated USING (public.has_role(auth.uid(),'admin')) WITH CHECK (public.has_role(auth.uid(),'admin'));
CREATE POLICY "age_auth_read"  ON public.attack_graph_edges FOR SELECT TO authenticated USING (true);
CREATE POLICY "age_admin_write" ON public.attack_graph_edges FOR ALL    TO authenticated USING (public.has_role(auth.uid(),'admin')) WITH CHECK (public.has_role(auth.uid(),'admin'));
CREATE POLICY "kc_auth_read"   ON public.kill_chains FOR SELECT TO authenticated USING (true);
CREATE POLICY "kc_admin_write"  ON public.kill_chains FOR ALL    TO authenticated USING (public.has_role(auth.uid(),'admin')) WITH CHECK (public.has_role(auth.uid(),'admin'));

CREATE TRIGGER trg_kc_upd BEFORE UPDATE ON public.kill_chains
FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();
