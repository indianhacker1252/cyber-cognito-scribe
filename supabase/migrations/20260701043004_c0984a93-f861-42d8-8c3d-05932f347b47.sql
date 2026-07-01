
-- 1) Add check_module column so UI can show which scanner is blocking a check
ALTER TABLE public.owasp_checklist
  ADD COLUMN IF NOT EXISTS check_module text;

-- 2) Expanded checklist seed (was 45 → now 82 checks) + explicit module mapping.
CREATE OR REPLACE FUNCTION public.seed_owasp_checklist(_target_id uuid)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $function$
DECLARE
  checks text[][] := ARRAY[
    -- A01 Broken Access Control
    ['A01_broken_access_control','idor_numeric_id','bac-tester'],
    ['A01_broken_access_control','idor_uuid','bac-tester'],
    ['A01_broken_access_control','horizontal_priv_escalation','differential-oracle'],
    ['A01_broken_access_control','vertical_priv_escalation','differential-oracle'],
    ['A01_broken_access_control','forced_browsing','recon-juicy'],
    ['A01_broken_access_control','path_traversal','matrix-fuzzer'],
    ['A01_broken_access_control','method_override','matrix-fuzzer'],
    ['A01_broken_access_control','cors_wildcard_creds','recon-juicy'],
    -- A02 Crypto
    ['A02_crypto_failures','tls_version','recon-juicy'],
    ['A02_crypto_failures','weak_ciphers','recon-juicy'],
    ['A02_crypto_failures','hsts_missing','recon-juicy'],
    ['A02_crypto_failures','exposed_secrets_in_js','js-deep-expand'],
    ['A02_crypto_failures','env_file_exposure','recon-juicy'],
    ['A02_crypto_failures','git_exposure','recon-juicy'],
    ['A02_crypto_failures','backup_files','recon-juicy'],
    ['A02_crypto_failures','api_keys_in_html','recon-engine'],
    -- A03 Injection
    ['A03_injection','reflected_xss','advanced-fuzzer'],
    ['A03_injection','stored_xss','form-attacker'],
    ['A03_injection','dom_xss','dom-fuzz'],
    ['A03_injection','sqli_error_based','advanced-fuzzer'],
    ['A03_injection','sqli_boolean_blind','advanced-fuzzer'],
    ['A03_injection','sqli_time_based','advanced-fuzzer'],
    ['A03_injection','nosql_injection','matrix-fuzzer'],
    ['A03_injection','ssti','advanced-fuzzer'],
    ['A03_injection','command_injection','advanced-fuzzer'],
    ['A03_injection','ldap_injection','matrix-fuzzer'],
    ['A03_injection','xxe','advanced-fuzzer'],
    ['A03_injection','header_injection','matrix-fuzzer'],
    ['A03_injection','crlf_injection','matrix-fuzzer'],
    ['A03_injection','graphql_injection','graphql-attack'],
    ['A03_injection','template_injection','advanced-fuzzer'],
    -- A04 Insecure Design
    ['A04_insecure_design','business_logic_bypass','business-logic-fuzzer'],
    ['A04_insecure_design','race_conditions','race-runner'],
    ['A04_insecure_design','workflow_skip','business-logic-fuzzer'],
    ['A04_insecure_design','price_manipulation','business-logic-fuzzer'],
    -- A05 Misconfig
    ['A05_misconfig','default_credentials','auth-deep'],
    ['A05_misconfig','directory_listing','recon-juicy'],
    ['A05_misconfig','verbose_errors','matrix-fuzzer'],
    ['A05_misconfig','security_headers_missing','recon-juicy'],
    ['A05_misconfig','cors_misconfig','recon-juicy'],
    ['A05_misconfig','admin_panel_exposed','recon-juicy'],
    ['A05_misconfig','debug_endpoints','recon-juicy'],
    ['A05_misconfig','risky_http_methods','recon-juicy'],
    ['A05_misconfig','clickjacking_xfo','recon-juicy'],
    ['A05_misconfig','csp_missing','recon-juicy'],
    ['A05_misconfig','samesite_cookie','recon-juicy'],
    -- A06 Vulnerable Components
    ['A06_vuln_components','outdated_tech','cve-version-matcher'],
    ['A06_vuln_components','known_cve_match','cve-to-exploit'],
    ['A06_vuln_components','jquery_outdated','js-deep-expand'],
    ['A06_vuln_components','wordpress_plugins','vuln-scanner'],
    ['A06_vuln_components','nvd_recent_cve','nvd-intel-sync'],
    -- A07 Auth Failures
    ['A07_auth_failures','jwt_none_alg','auth-confusion-suite'],
    ['A07_auth_failures','jwt_weak_secret','auth-confusion-suite'],
    ['A07_auth_failures','jwt_algorithm_confusion','auth-confusion-suite'],
    ['A07_auth_failures','oauth_redirect','auth-deep'],
    ['A07_auth_failures','session_fixation','auth-replay'],
    ['A07_auth_failures','password_policy','auth-deep'],
    ['A07_auth_failures','no_mfa_bypass','auth-deep'],
    ['A07_auth_failures','account_enumeration','auth-deep'],
    ['A07_auth_failures','credential_stuffing_gate','auth-deep'],
    -- A08 Software & Data Integrity
    ['A08_software_integrity','prototype_pollution','prototype-pollution-gadgets'],
    ['A08_software_integrity','dependency_confusion','cve-version-matcher'],
    ['A08_software_integrity','sri_missing','recon-juicy'],
    ['A08_software_integrity','insecure_deserialization','advanced-fuzzer'],
    ['A08_software_integrity','cache_deception','cache-attack'],
    ['A08_software_integrity','http_smuggling','desync-smuggling-v2'],
    -- A09 Logging & Monitoring
    ['A09_logging','no_rate_limit','matrix-fuzzer'],
    ['A09_logging','no_audit_trail','recon-juicy'],
    ['A09_logging','error_leaks_stack','matrix-fuzzer'],
    ['A09_logging','info_disclosure_headers','recon-juicy'],
    -- A10 SSRF
    ['A10_ssrf','ssrf_basic','ssrf-deep'],
    ['A10_ssrf','ssrf_cloud_metadata','ssrf-deep'],
    ['A10_ssrf','ssrf_oob','ssrf-deep'],
    ['A10_ssrf','ssrf_dns_rebind','ssrf-deep'],
    ['A10_ssrf','ssrf_gopher','ssrf-deep'],
    ['A10_ssrf','ssrf_file_scheme','ssrf-deep'],
    -- Recon / Intel add-ons
    ['A05_misconfig','subdomain_takeover','subdomain-enum'],
    ['A05_misconfig','dns_spf_dmarc','recon-juicy'],
    ['A05_misconfig','open_ports_exposed','recon-deep'],
    ['A05_misconfig','s3_bucket_exposed','recon-juicy'],
    ['A02_crypto_failures','pii_in_response','matrix-fuzzer'],
    ['A03_injection','file_upload_polyglot','form-attacker'],
    ['A03_injection','open_redirect','matrix-fuzzer']
  ];
  i int;
BEGIN
  FOR i IN 1..array_length(checks,1) LOOP
    INSERT INTO public.owasp_checklist(target_id, category, check_name, check_module)
    VALUES (_target_id, checks[i][1], checks[i][2], checks[i][3])
    ON CONFLICT (target_id, category, check_name)
    DO UPDATE SET check_module = EXCLUDED.check_module;
  END LOOP;
  RETURN (SELECT count(*) FROM public.owasp_checklist WHERE target_id = _target_id)::int;
END
$function$;

-- 3) Auto-seed checklist whenever a new target_workspace is created
CREATE OR REPLACE FUNCTION public.trg_seed_owasp_on_target()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $$
BEGIN
  PERFORM public.seed_owasp_checklist(NEW.id);
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS target_workspaces_seed_owasp ON public.target_workspaces;
CREATE TRIGGER target_workspaces_seed_owasp
AFTER INSERT ON public.target_workspaces
FOR EACH ROW EXECUTE FUNCTION public.trg_seed_owasp_on_target();

-- 4) Backfill checklist for existing targets that have no rows yet
DO $$
DECLARE r record;
BEGIN
  FOR r IN
    SELECT t.id FROM public.target_workspaces t
    LEFT JOIN public.owasp_checklist c ON c.target_id = t.id
    GROUP BY t.id HAVING count(c.id) = 0
  LOOP
    PERFORM public.seed_owasp_checklist(r.id);
  END LOOP;
END $$;

-- 5) Admin-callable delete
CREATE OR REPLACE FUNCTION public.delete_owasp_checklist(_target_id uuid)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $$
DECLARE n int;
BEGIN
  IF NOT (public.has_role(auth.uid(),'admin') OR auth.uid() IS NOT NULL) THEN
    RAISE EXCEPTION 'forbidden';
  END IF;
  DELETE FROM public.owasp_checklist WHERE target_id = _target_id;
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END $$;

GRANT EXECUTE ON FUNCTION public.delete_owasp_checklist(uuid) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.seed_owasp_checklist(uuid) TO authenticated, service_role;
