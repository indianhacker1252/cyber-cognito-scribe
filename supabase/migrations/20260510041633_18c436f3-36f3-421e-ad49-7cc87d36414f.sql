
-- Backfill validation_status based on existing confidence_score
UPDATE public.vulnerability_findings
   SET validation_status = 'confirmed'
 WHERE confidence_score >= 95
   AND (validation_status IS NULL OR validation_status IN ('unverified',''));

UPDATE public.vulnerability_findings
   SET validation_status = 'needs_review'
 WHERE confidence_score >= 75 AND confidence_score < 95
   AND (validation_status IS NULL OR validation_status IN ('unverified',''));

UPDATE public.vulnerability_findings
   SET validation_status = 'inconclusive'
 WHERE (confidence_score IS NULL OR confidence_score < 75)
   AND (validation_status IS NULL OR validation_status IN ('unverified',''));

-- Index for report filtering
CREATE INDEX IF NOT EXISTS idx_vf_target_status
  ON public.vulnerability_findings(target_id, validation_status);
