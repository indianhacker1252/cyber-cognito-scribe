-- P2: proof_evidence table (one row per oracle verdict per finding)
CREATE TABLE IF NOT EXISTS public.proof_evidence (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  finding_id UUID REFERENCES public.vulnerability_findings(id) ON DELETE CASCADE,
  target_id UUID REFERENCES public.target_workspaces(id) ON DELETE CASCADE,
  oracle TEXT NOT NULL,
  verdict TEXT NOT NULL CHECK (verdict IN ('confirmed','rejected','inconclusive')),
  detail JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_proof_evidence_finding ON public.proof_evidence(finding_id);
CREATE INDEX IF NOT EXISTS idx_proof_evidence_target ON public.proof_evidence(target_id);
GRANT SELECT, INSERT ON public.proof_evidence TO authenticated;
GRANT ALL ON public.proof_evidence TO service_role;
ALTER TABLE public.proof_evidence ENABLE ROW LEVEL SECURITY;
CREATE POLICY "proof_evidence authed read" ON public.proof_evidence FOR SELECT TO authenticated USING (true);
CREATE POLICY "proof_evidence service write" ON public.proof_evidence FOR INSERT TO authenticated WITH CHECK (true);

-- P6: agent_experiences (replay bank for the planner)
CREATE TABLE IF NOT EXISTS public.agent_experiences (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id UUID,
  session_id UUID,
  vuln_class TEXT NOT NULL,
  technique TEXT,
  endpoint_pattern TEXT,
  tech_tags TEXT[] NOT NULL DEFAULT '{}',
  outcome TEXT NOT NULL CHECK (outcome IN ('confirmed','rejected','partial','dead_end')),
  confidence NUMERIC,
  proof_snippet TEXT,
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_agent_experiences_target ON public.agent_experiences(target_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_experiences_tech ON public.agent_experiences USING gin(tech_tags);
GRANT SELECT, INSERT ON public.agent_experiences TO authenticated;
GRANT ALL ON public.agent_experiences TO service_role;
ALTER TABLE public.agent_experiences ENABLE ROW LEVEL SECURITY;
CREATE POLICY "agent_experiences authed read" ON public.agent_experiences FOR SELECT TO authenticated USING (true);
CREATE POLICY "agent_experiences service write" ON public.agent_experiences FOR INSERT TO authenticated WITH CHECK (true);

-- P6: seed 20 synthetic kill-chain experiences so the planner has a cold-start corpus
INSERT INTO public.agent_experiences (vuln_class, technique, endpoint_pattern, tech_tags, outcome, confidence, notes) VALUES
('sqli','error_based_union','/api/*?id=','{php,mysql}',       'confirmed',0.95,'union-based leak via id= on PHP/MySQL stacks'),
('sqli','time_based_blind', '/search?q=', '{nodejs,postgres}', 'confirmed',0.88,'pg_sleep(5) oracle on /search'),
('xss', 'reflected_payload','/search?q=', '{react,nextjs}',    'dead_end', 0.1, 'React auto-escapes; dead end unless dangerouslySetInnerHTML'),
('xss', 'dom_sink_hashchange','/#','{spa,vuejs}',             'confirmed',0.9, 'window.location.hash sink'),
('idor','sequential_id','/api/users/:id','{rest}',             'confirmed',0.92,'two-context diff on /api/users/{N+1}'),
('idor','uuid_leak','/api/orders/:uuid','{rest}',              'partial',  0.6, 'uuid leaked via /orders list → cross-user read'),
('ssrf','gopher_lan','/fetch?url=','{nodejs}',                 'confirmed',0.9, 'gopher:// to 169.254.169.254 cloud metadata'),
('ssrf','dns_rebind','/webhook','{generic}',                   'partial',  0.5, 'needs OOB callback infra'),
('rce', 'sstti_jinja','/render?t=','{python,flask}',           'confirmed',0.95,'{{7*7}} → 49'),
('ssti','handlebars_proto','/mail','{nodejs,handlebars}',      'confirmed',0.9, '#with constructor.prototype pollution'),
('redirect','open_redirect','/go?url=','{generic}',            'confirmed',0.85,'raw url= echoed in Location:'),
('auth_bypass','jwt_none_alg','/api/*','{jwt}',                'confirmed',0.98,'alg:none accepted'),
('auth_bypass','jwt_hs256_confusion','/api/*','{jwt,rs256}',   'confirmed',0.9, 'HS256 signed with RSA pubkey'),
('bac','role_header_tamper','/admin/*','{rest}',               'partial',  0.6, 'X-User-Role: admin accepted on some routes'),
('lfi','path_traversal','/download?file=','{php}',             'confirmed',0.9, '../../../etc/passwd signature'),
('xxe','external_entity','/upload-xml','{java,soap}',          'confirmed',0.88,'file:// entity exfil'),
('nosqli','operator_injection','/login','{nodejs,mongo}',      'confirmed',0.9, '{"$ne":null} password bypass'),
('deserial','java_commons','/invoke','{java,struts}',          'confirmed',0.95,'ysoserial CommonsCollections5 chain'),
('race','double_spend','/checkout','{rest}',                   'confirmed',0.8, '20 parallel requests → duplicate credit'),
('cache','web_cache_poison','/','{nginx,varnish}',             'partial',  0.6, 'X-Forwarded-Host header reflected into cache');