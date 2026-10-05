
-- attack_surface: admin-only read, service_role writes
DROP POLICY IF EXISTS "attack_surface authed rw" ON public.attack_surface;
CREATE POLICY "attack_surface admin read" ON public.attack_surface
  FOR SELECT TO authenticated USING (public.has_role(auth.uid(), 'admin'));
CREATE POLICY "attack_surface service write" ON public.attack_surface
  FOR ALL TO service_role USING (true) WITH CHECK (true);

-- technique_stats: admin-only read
DROP POLICY IF EXISTS "technique_stats read all authed" ON public.technique_stats;
CREATE POLICY "technique_stats admin read" ON public.technique_stats
  FOR SELECT TO authenticated USING (public.has_role(auth.uid(), 'admin'));

-- ai_confidence_calibration: restrict INSERT to service_role
DROP POLICY IF EXISTS "service insert calibration" ON public.ai_confidence_calibration;
CREATE POLICY "ai_calibration service insert" ON public.ai_confidence_calibration
  FOR INSERT TO service_role WITH CHECK (true);
