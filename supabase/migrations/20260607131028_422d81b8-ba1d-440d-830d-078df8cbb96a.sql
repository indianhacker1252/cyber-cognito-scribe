ALTER TABLE public.vulnerability_findings
  ADD COLUMN IF NOT EXISTS finding_type text;

CREATE INDEX IF NOT EXISTS idx_vulnerability_findings_finding_type
  ON public.vulnerability_findings(finding_type);

UPDATE public.vulnerability_findings
   SET finding_type = COALESCE(
     finding_type,
     NULLIF((hard_evidence->>'winning_class'), ''),
     NULLIF((hard_evidence->>'vuln_class'), ''),
     NULLIF((hard_evidence->>'templateId'), ''),
     CASE
       WHEN title ILIKE '%xss%' OR payload ~* '<script|onerror|onload|javascript:' THEN 'xss'
       WHEN title ILIKE '%sqli%' OR title ILIKE '%sql%' OR payload ~* 'union|select|or\s+1=1|sql' THEN 'sqli'
       WHEN title ILIKE '%ssrf%' THEN 'ssrf'
       WHEN title ILIKE '%idor%' OR title ILIKE '%bola%' THEN 'idor'
       ELSE 'unknown'
     END
   )
 WHERE finding_type IS NULL;