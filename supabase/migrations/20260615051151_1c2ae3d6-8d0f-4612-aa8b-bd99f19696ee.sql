CREATE OR REPLACE FUNCTION public.normalize_vulnerability_finding_evidence()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
DECLARE
  evidence_obj jsonb := COALESCE(NEW.evidence, '{}'::jsonb);
  hard_obj jsonb := COALESCE(NEW.hard_evidence, '{}'::jsonb);
  req_url text;
  status_text text;
  body_text text;
BEGIN
  IF NEW.finding_type IS NULL THEN
    NEW.finding_type := COALESCE(NEW.vuln_class, NEW.source, 'scanner_finding');
  END IF;

  IF hard_obj = '{}'::jsonb AND evidence_obj <> '{}'::jsonb THEN
    NEW.hard_evidence := evidence_obj;
    hard_obj := evidence_obj;
  END IF;

  req_url := COALESCE(
    NEW.affected_url,
    evidence_obj->>'url',
    evidence_obj->>'endpoint',
    evidence_obj->>'affected_url',
    hard_obj->>'url',
    hard_obj->>'endpoint',
    hard_obj->>'affected_url'
  );

  IF NEW.request_raw IS NULL AND req_url IS NOT NULL AND req_url <> '' THEN
    NEW.request_raw := 'GET ' || req_url || ' HTTP/1.1' || E'\r\n' || 'User-Agent: CyberScope/1.0';
  END IF;

  status_text := COALESCE(
    evidence_obj->>'status',
    evidence_obj->>'statusCode',
    evidence_obj->>'newStatus',
    hard_obj->>'status',
    hard_obj->>'statusCode',
    hard_obj->>'newStatus',
    '200'
  );
  body_text := COALESCE(
    evidence_obj->>'snippet',
    evidence_obj->>'body',
    evidence_obj->>'bodySnippet',
    evidence_obj->>'verifyBody',
    hard_obj->>'snippet',
    hard_obj->>'body',
    hard_obj->>'bodySnippet',
    hard_obj->>'verifyBody',
    NEW.description,
    NEW.title
  );

  IF NEW.response_raw IS NULL AND body_text IS NOT NULL THEN
    NEW.response_raw := 'HTTP/1.1 ' || status_text || E'\r\n\r\n' || left(body_text, 32768);
  END IF;

  IF NEW.response_diff IS NULL OR NEW.response_diff = '{}'::jsonb THEN
    NEW.response_diff := jsonb_build_object(
      'status', status_text,
      'response_length', length(COALESCE(body_text, '')),
      'has_request', NEW.request_raw IS NOT NULL,
      'has_response', NEW.response_raw IS NOT NULL,
      'source', COALESCE(NEW.source, NEW.finding_type)
    );
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS normalize_vulnerability_finding_evidence_before_insert ON public.vulnerability_findings;
CREATE TRIGGER normalize_vulnerability_finding_evidence_before_insert
BEFORE INSERT ON public.vulnerability_findings
FOR EACH ROW
EXECUTE FUNCTION public.normalize_vulnerability_finding_evidence();