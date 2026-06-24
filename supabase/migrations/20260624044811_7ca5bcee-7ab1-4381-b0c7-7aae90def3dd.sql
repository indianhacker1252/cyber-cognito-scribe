DROP POLICY IF EXISTS "rag read all auth" ON public.rag_corpus;
CREATE POLICY "rag corpus admin read" ON public.rag_corpus
  FOR SELECT TO authenticated
  USING (public.has_role(auth.uid(), 'admin'));