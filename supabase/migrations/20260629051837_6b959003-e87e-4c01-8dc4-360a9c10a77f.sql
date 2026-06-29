
CREATE TABLE IF NOT EXISTS public.scan_phase_state (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id uuid NOT NULL,
  phase text NOT NULL,
  status text NOT NULL DEFAULT 'pending',
  checks_attempted int NOT NULL DEFAULT 0,
  checks_passed int NOT NULL DEFAULT 0,
  findings_count int NOT NULL DEFAULT 0,
  last_heartbeat timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz,
  completed_at timestamptz,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (target_id, phase)
);
GRANT SELECT ON public.scan_phase_state TO authenticated;
GRANT ALL ON public.scan_phase_state TO service_role;
ALTER TABLE public.scan_phase_state ENABLE ROW LEVEL SECURITY;
CREATE POLICY "phase_state admin read" ON public.scan_phase_state FOR SELECT TO authenticated
USING (public.has_role(auth.uid(),'admin'));
CREATE INDEX IF NOT EXISTS scan_phase_state_target_idx ON public.scan_phase_state(target_id, phase);
CREATE INDEX IF NOT EXISTS scan_phase_state_heartbeat_idx ON public.scan_phase_state(last_heartbeat) WHERE status = 'running';

CREATE TABLE IF NOT EXISTS public.owasp_checklist (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id uuid NOT NULL,
  category text NOT NULL,
  check_name text NOT NULL,
  status text NOT NULL DEFAULT 'pending',
  evidence_count int NOT NULL DEFAULT 0,
  last_run_at timestamptz,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (target_id, category, check_name)
);
GRANT SELECT ON public.owasp_checklist TO authenticated;
GRANT ALL ON public.owasp_checklist TO service_role;
ALTER TABLE public.owasp_checklist ENABLE ROW LEVEL SECURITY;
CREATE POLICY "owasp_checklist admin read" ON public.owasp_checklist FOR SELECT TO authenticated
USING (public.has_role(auth.uid(),'admin'));
CREATE INDEX IF NOT EXISTS owasp_checklist_target_idx ON public.owasp_checklist(target_id, category);

ALTER TABLE public.vulnerability_findings ADD COLUMN IF NOT EXISTS dedup_key text;
CREATE UNIQUE INDEX IF NOT EXISTS vf_dedup_unique_idx ON public.vulnerability_findings(target_id, dedup_key) WHERE dedup_key IS NOT NULL;

CREATE TABLE IF NOT EXISTS public.attack_hypotheses (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id uuid NOT NULL,
  round int NOT NULL DEFAULT 1,
  asset_host text,
  endpoint_url text,
  method text DEFAULT 'GET',
  vuln_class text,
  hypothesis text NOT NULL,
  mutation jsonb NOT NULL DEFAULT '{}'::jsonb,
  expected_proof text,
  status text NOT NULL DEFAULT 'pending',
  result jsonb,
  finding_id uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT ON public.attack_hypotheses TO authenticated;
GRANT ALL ON public.attack_hypotheses TO service_role;
ALTER TABLE public.attack_hypotheses ENABLE ROW LEVEL SECURITY;
CREATE POLICY "hypotheses admin read" ON public.attack_hypotheses FOR SELECT TO authenticated
USING (public.has_role(auth.uid(),'admin'));
CREATE INDEX IF NOT EXISTS attack_hypotheses_target_idx ON public.attack_hypotheses(target_id, status);

ALTER TABLE public.scan_assets ADD COLUMN IF NOT EXISTS phase_state jsonb NOT NULL DEFAULT '{}'::jsonb;

DROP TRIGGER IF EXISTS scan_phase_state_updated_at ON public.scan_phase_state;
CREATE TRIGGER scan_phase_state_updated_at BEFORE UPDATE ON public.scan_phase_state FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();
DROP TRIGGER IF EXISTS owasp_checklist_updated_at ON public.owasp_checklist;
CREATE TRIGGER owasp_checklist_updated_at BEFORE UPDATE ON public.owasp_checklist FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();
DROP TRIGGER IF EXISTS attack_hypotheses_updated_at ON public.attack_hypotheses;
CREATE TRIGGER attack_hypotheses_updated_at BEFORE UPDATE ON public.attack_hypotheses FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

CREATE OR REPLACE FUNCTION public.seed_owasp_checklist(_target_id uuid)
RETURNS int LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
  checks text[][] := ARRAY[
    ['A01_broken_access_control','idor_numeric_id'],
    ['A01_broken_access_control','idor_uuid'],
    ['A01_broken_access_control','horizontal_priv_escalation'],
    ['A01_broken_access_control','vertical_priv_escalation'],
    ['A01_broken_access_control','forced_browsing'],
    ['A02_crypto_failures','tls_version'],
    ['A02_crypto_failures','weak_ciphers'],
    ['A02_crypto_failures','exposed_secrets_in_js'],
    ['A02_crypto_failures','env_file_exposure'],
    ['A02_crypto_failures','git_exposure'],
    ['A03_injection','reflected_xss'],
    ['A03_injection','stored_xss'],
    ['A03_injection','dom_xss'],
    ['A03_injection','sqli_error_based'],
    ['A03_injection','sqli_boolean_blind'],
    ['A03_injection','sqli_time_based'],
    ['A03_injection','ssti'],
    ['A03_injection','command_injection'],
    ['A03_injection','ldap_injection'],
    ['A03_injection','xxe'],
    ['A03_injection','header_injection'],
    ['A04_insecure_design','business_logic_bypass'],
    ['A04_insecure_design','race_conditions'],
    ['A05_misconfig','default_credentials'],
    ['A05_misconfig','directory_listing'],
    ['A05_misconfig','verbose_errors'],
    ['A05_misconfig','security_headers_missing'],
    ['A05_misconfig','cors_misconfig'],
    ['A05_misconfig','admin_panel_exposed'],
    ['A05_misconfig','debug_endpoints'],
    ['A06_vuln_components','outdated_tech'],
    ['A06_vuln_components','known_cve_match'],
    ['A07_auth_failures','jwt_none_alg'],
    ['A07_auth_failures','jwt_weak_secret'],
    ['A07_auth_failures','oauth_redirect'],
    ['A07_auth_failures','session_fixation'],
    ['A07_auth_failures','password_policy'],
    ['A08_software_integrity','prototype_pollution'],
    ['A08_software_integrity','dependency_confusion'],
    ['A09_logging','no_rate_limit'],
    ['A09_logging','no_audit_trail'],
    ['A10_ssrf','ssrf_basic'],
    ['A10_ssrf','ssrf_cloud_metadata'],
    ['A10_ssrf','ssrf_oob'],
    ['A10_ssrf','ssrf_dns_rebind']
  ];
  i int;
BEGIN
  FOR i IN 1..array_length(checks,1) LOOP
    INSERT INTO public.owasp_checklist(target_id, category, check_name)
    VALUES (_target_id, checks[i][1], checks[i][2])
    ON CONFLICT DO NOTHING;
  END LOOP;
  RETURN (SELECT count(*) FROM public.owasp_checklist WHERE target_id = _target_id)::int;
END $$;
GRANT EXECUTE ON FUNCTION public.seed_owasp_checklist(uuid) TO authenticated, service_role;
