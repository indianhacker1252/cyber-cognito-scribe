
-- Compute a temporary key up front, dedupe by it, then backfill dedup_key safely.
WITH keyed AS (
  SELECT id, target_id, created_at,
    lower(COALESCE(split_part(regexp_replace(COALESCE(affected_url,''),'^https?://',''),'/',1),'')) || '|GET|/|' ||
    lower(COALESCE(evidence->>'param','')) || '|' ||
    lower(COALESCE(vuln_class, finding_type, source,'generic')) AS k
    FROM public.vulnerability_findings
), ranked AS (
  SELECT id, target_id, k,
         row_number() OVER (PARTITION BY target_id, k ORDER BY created_at ASC) AS rn,
         count(*)     OVER (PARTITION BY target_id, k) AS c
    FROM keyed
)
DELETE FROM public.vulnerability_findings v
 USING ranked r
 WHERE v.id = r.id AND r.rn > 1;

UPDATE public.vulnerability_findings
   SET dedup_key = lower(COALESCE(split_part(regexp_replace(COALESCE(affected_url,''),'^https?://',''),'/',1),'')) || '|GET|/|' ||
                   lower(COALESCE(evidence->>'param','')) || '|' ||
                   lower(COALESCE(vuln_class, finding_type, source,'generic'))
 WHERE dedup_key IS NULL OR dedup_key = '';

-- Trigger to auto-populate dedup_key on future inserts
CREATE OR REPLACE FUNCTION public.auto_dedup_finding()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
DECLARE
  host text := '';
  path text := '/';
  apex text := '';
  param text := '';
  cls text := '';
  url text := '';
BEGIN
  IF NEW.dedup_key IS NOT NULL AND NEW.dedup_key <> '' AND NEW.group_key IS NOT NULL THEN
    RETURN NEW;
  END IF;
  url := COALESCE(NEW.affected_url, NEW.evidence->>'url', NEW.evidence->>'endpoint', NEW.hard_evidence->>'url', '');
  BEGIN
    IF url <> '' THEN
      host := lower(split_part(regexp_replace(url, '^https?://', ''), '/', 1));
      path := '/' || split_part(regexp_replace(url, '^https?://[^/]+/?', ''), '?', 1);
    END IF;
  EXCEPTION WHEN others THEN host := ''; path := '/'; END;
  path := regexp_replace(path, '/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '/:uuid', 'gi');
  path := regexp_replace(path, '/\d+(?=/|$)', '/:id', 'g');
  path := regexp_replace(path, '/+$', '');
  IF path = '' THEN path := '/'; END IF;
  apex := array_to_string((regexp_split_to_array(host, '\.'))[greatest(array_length(regexp_split_to_array(host,'\.'),1)-1,1):], '.');
  param := lower(COALESCE(NEW.evidence->>'param', ''));
  cls := lower(COALESCE(NEW.vuln_class, NEW.finding_type, NEW.source, 'generic'));
  IF NEW.dedup_key IS NULL OR NEW.dedup_key = '' THEN
    NEW.dedup_key := host || '|GET|' || path || '|' || param || '|' || cls;
  END IF;
  IF NEW.group_key IS NULL THEN
    NEW.group_key := COALESCE(NULLIF(apex,''), host, NEW.target_id::text) || '|' || cls || '|' || param;
  END IF;
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS trg_auto_dedup_finding ON public.vulnerability_findings;
CREATE TRIGGER trg_auto_dedup_finding
  BEFORE INSERT ON public.vulnerability_findings
  FOR EACH ROW EXECUTE FUNCTION public.auto_dedup_finding();

-- OWASP delete: accept plain name, "name — domain", or domain
CREATE OR REPLACE FUNCTION public.delete_owasp_checklist(_target_id uuid, _confirmation text DEFAULT NULL::text)
 RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path TO 'public'
AS $function$
DECLARE
  n int := 0; label_name text; label_domain text; candidates text[]; chosen text;
BEGIN
  IF auth.uid() IS NULL THEN RAISE EXCEPTION 'forbidden'; END IF;
  SELECT NULLIF(name,''), NULLIF(domain,'') INTO label_name, label_domain
    FROM public.target_workspaces WHERE id = _target_id;
  candidates := ARRAY[]::text[];
  IF label_name IS NOT NULL THEN
    candidates := candidates || ('DELETE ' || label_name);
    IF label_domain IS NOT NULL AND label_domain <> label_name THEN
      candidates := candidates || ('DELETE ' || label_name || ' — ' || label_domain);
    END IF;
  END IF;
  IF label_domain IS NOT NULL THEN candidates := candidates || ('DELETE ' || label_domain); END IF;
  candidates := candidates || ('DELETE ' || _target_id::text);
  IF _confirmation = ANY(candidates) THEN chosen := _confirmation; END IF;
  IF chosen IS NULL THEN
    RAISE EXCEPTION 'confirmation_mismatch: expected one of %', array_to_string(candidates, ' | ');
  END IF;
  DELETE FROM public.owasp_checklist WHERE target_id = _target_id;
  GET DIAGNOSTICS n = ROW_COUNT;
  INSERT INTO public.owasp_checklist_audit(target_id, target_label, action, confirmation, deleted_count, actor_id, metadata)
  VALUES (_target_id, COALESCE(label_name, label_domain, _target_id::text), 'delete_checklist', _confirmation, n, auth.uid(),
          jsonb_build_object('accepted', chosen, 'candidates', candidates));
  INSERT INTO public.scan_logs(target_id, log_type, message, metadata)
  VALUES (_target_id, 'action', '🧾 OWASP checklist deleted with confirmation',
          jsonb_build_object('kind','owasp_checklist_delete','deleted_count',n,'actor_id',auth.uid()));
  RETURN n;
END; $function$;
