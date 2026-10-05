
-- Restrict internal learning/proof tables to admins (read) and service_role (write).
-- agent_experiences
DROP POLICY IF EXISTS "agent_experiences authed read" ON public.agent_experiences;
DROP POLICY IF EXISTS "agent_experiences service write" ON public.agent_experiences;
CREATE POLICY "agent_experiences admin read" ON public.agent_experiences
  FOR SELECT TO authenticated USING (public.has_role(auth.uid(), 'admin'));
CREATE POLICY "agent_experiences service write" ON public.agent_experiences
  FOR INSERT TO service_role WITH CHECK (true);

-- bench_runs
DROP POLICY IF EXISTS "bench_runs read all authed" ON public.bench_runs;
CREATE POLICY "bench_runs admin read" ON public.bench_runs
  FOR SELECT TO authenticated USING (public.has_role(auth.uid(), 'admin'));

-- proof_evidence
DROP POLICY IF EXISTS "proof_evidence authed read" ON public.proof_evidence;
DROP POLICY IF EXISTS "proof_evidence service write" ON public.proof_evidence;
CREATE POLICY "proof_evidence admin read" ON public.proof_evidence
  FOR SELECT TO authenticated USING (public.has_role(auth.uid(), 'admin'));
CREATE POLICY "proof_evidence service write" ON public.proof_evidence
  FOR INSERT TO service_role WITH CHECK (true);
