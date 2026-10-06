-- P2: close the proof-gate loop. The existing enforce_finding_proof_gate trigger
-- demotes unproven findings to 'info'. This migration adds the reverse path:
-- when a proof_evidence row with verdict='confirmed' arrives for a finding
-- that was gate-demoted, the finding is promoted back to its original severity
-- and marked proof_tier='confirmed'.

CREATE OR REPLACE FUNCTION public.promote_finding_on_proof()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $func$
DECLARE
  orig text;
BEGIN
  IF NEW.verdict <> 'confirmed' THEN
    RETURN NEW;
  END IF;

  SELECT evidence->>'gate_original_severity' INTO orig
  FROM public.vulnerability_findings
  WHERE id = NEW.finding_id;

  IF orig IS NOT NULL AND orig <> 'unknown' THEN
    UPDATE public.vulnerability_findings
    SET severity = orig::severity_level,
        proof_tier = 'confirmed',
        evidence = COALESCE(evidence, '{}'::jsonb) || jsonb_build_object(
          'gate_promoted', true,
          'gate_promoted_by_oracle', NEW.oracle,
          'gate_promoted_at', now()
        )
    WHERE id = NEW.finding_id;
  ELSE
    UPDATE public.vulnerability_findings
    SET proof_tier = 'confirmed',
        evidence = COALESCE(evidence, '{}'::jsonb) || jsonb_build_object(
          'gate_promoted', true,
          'gate_promoted_by_oracle', NEW.oracle,
          'gate_promoted_at', now()
        )
    WHERE id = NEW.finding_id
      AND proof_tier IS DISTINCT FROM 'confirmed';
  END IF;

  RETURN NEW;
END;
$func$;

DROP TRIGGER IF EXISTS trg_promote_finding_on_proof ON public.proof_evidence;
CREATE TRIGGER trg_promote_finding_on_proof
  AFTER INSERT ON public.proof_evidence
  FOR EACH ROW
  EXECUTE FUNCTION public.promote_finding_on_proof();

-- Index so the gate/promotion path stays fast at scale.
CREATE INDEX IF NOT EXISTS idx_proof_evidence_finding_verdict
  ON public.proof_evidence (finding_id, verdict);

COMMENT ON FUNCTION public.promote_finding_on_proof() IS
  'P2 proof gate: promotes a gate-demoted finding back to its original severity when a confirmed oracle verdict is recorded in proof_evidence.';