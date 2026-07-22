CREATE OR REPLACE FUNCTION public.enforce_finding_proof_gate()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = public
AS $$
DECLARE
  ev jsonb := COALESCE(NEW.evidence, '{}'::jsonb);
  he jsonb := COALESCE(NEW.hard_evidence, '{}'::jsonb);
  body text := COALESCE(NEW.response_raw, '') || ' ' || COALESCE(NEW.payload, '') || ' ' || COALESCE(ev::text,'') || ' ' || COALESCE(he::text,'');
  ai_score int := COALESCE( (ev->'ai_confidence'->>'confidenceScore')::int, 0 );
  ai_verdict text := COALESCE( ev->'ai_confidence'->>'verdict', '' );
  has_hard boolean := (
       NEW.proof_tier IN ('exploited','confirmed')
    OR body ~* 'CYBERSCOPE_PROVEN|SPECTER_LLM_CONFIRMED|oob[_-]?(callback|hit|received)|root:.*:0:0:|iam/security-credentials|you have an error in your sql syntax|ORA-[0-9]{4,5}|PG::SyntaxError'
  );
  orig_sev text := COALESCE(NEW.severity::text,'unknown');
BEGIN
  IF has_hard THEN RETURN NEW; END IF;
  IF ai_score >= 85 AND ai_verdict IN ('confirmed','likely') THEN RETURN NEW; END IF;
  NEW.severity := 'info';
  NEW.proof_tier := COALESCE(NEW.proof_tier, 'suspected');
  NEW.evidence := ev || jsonb_build_object(
    'gate_demoted', true,
    'gate_reason', CASE WHEN ai_score = 0 THEN 'no_ai_confidence_no_hard_marker' ELSE 'ai_score_below_threshold' END,
    'gate_original_severity', orig_sev,
    'gate_ai_score', ai_score,
    'gate_ai_verdict', ai_verdict
  );
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_enforce_finding_proof_gate ON public.vulnerability_findings;
CREATE TRIGGER trg_enforce_finding_proof_gate
BEFORE INSERT ON public.vulnerability_findings
FOR EACH ROW EXECUTE FUNCTION public.enforce_finding_proof_gate();