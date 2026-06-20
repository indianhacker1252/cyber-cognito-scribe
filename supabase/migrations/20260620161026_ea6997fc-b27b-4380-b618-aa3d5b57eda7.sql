-- 1) Reclaim disk: bloat sources
TRUNCATE TABLE public.mythos_variants RESTART IDENTITY CASCADE;
DELETE FROM public.scan_jobs WHERE status IN ('done','failed') AND COALESCE(completed_at, created_at) < now() - interval '1 day';
DELETE FROM public.scan_logs WHERE created_at < now() - interval '3 days';
DELETE FROM public.mythos_debates WHERE created_at < now() - interval '7 days';

-- 2) Admin-only SELECT on sensitive tables (replaces USING(true))
DROP POLICY IF EXISTS chat_messages_auth_read ON public.chat_messages;
CREATE POLICY chat_messages_admin_read ON public.chat_messages
  FOR SELECT TO authenticated USING (public.has_role(auth.uid(),'admin'));

DROP POLICY IF EXISTS chat_sessions_auth_read ON public.chat_sessions;
CREATE POLICY chat_sessions_admin_read ON public.chat_sessions
  FOR SELECT TO authenticated USING (public.has_role(auth.uid(),'admin'));

DROP POLICY IF EXISTS target_workspaces_auth_read ON public.target_workspaces;
CREATE POLICY target_workspaces_admin_read ON public.target_workspaces
  FOR SELECT TO authenticated USING (public.has_role(auth.uid(),'admin'));

-- 3) Admin-callable purge function (clears DB to match UI "Clear" actions)
CREATE OR REPLACE FUNCTION public.purge_history(_target_id uuid DEFAULT NULL, _scope text DEFAULT 'all')
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  res jsonb := '{}'::jsonb;
  n int;
BEGIN
  IF NOT public.has_role(auth.uid(),'admin') THEN
    RETURN jsonb_build_object('ok',false,'error','forbidden');
  END IF;

  IF _target_id IS NULL THEN
    TRUNCATE TABLE public.mythos_variants RESTART IDENTITY CASCADE;
    DELETE FROM public.scan_logs;           GET DIAGNOSTICS n = ROW_COUNT; res := res || jsonb_build_object('scan_logs',n);
    DELETE FROM public.scan_jobs;           GET DIAGNOSTICS n = ROW_COUNT; res := res || jsonb_build_object('scan_jobs',n);
    DELETE FROM public.mythos_debates;      GET DIAGNOSTICS n = ROW_COUNT; res := res || jsonb_build_object('mythos_debates',n);
    DELETE FROM public.mythos_runs;         GET DIAGNOSTICS n = ROW_COUNT; res := res || jsonb_build_object('mythos_runs',n);
    DELETE FROM public.agent_tasks;         GET DIAGNOSTICS n = ROW_COUNT; res := res || jsonb_build_object('agent_tasks',n);
    DELETE FROM public.evidence_packages;   GET DIAGNOSTICS n = ROW_COUNT; res := res || jsonb_build_object('evidence_packages',n);
    DELETE FROM public.oob_callbacks;       GET DIAGNOSTICS n = ROW_COUNT; res := res || jsonb_build_object('oob_callbacks',n);
    DELETE FROM public.exploit_runs;        GET DIAGNOSTICS n = ROW_COUNT; res := res || jsonb_build_object('exploit_runs',n);
    DELETE FROM public.discovered_endpoints;GET DIAGNOSTICS n = ROW_COUNT; res := res || jsonb_build_object('discovered_endpoints',n);
    DELETE FROM public.vulnerability_findings; GET DIAGNOSTICS n = ROW_COUNT; res := res || jsonb_build_object('vulnerability_findings',n);
    DELETE FROM public.chat_messages;       GET DIAGNOSTICS n = ROW_COUNT; res := res || jsonb_build_object('chat_messages',n);
    DELETE FROM public.chat_sessions;       GET DIAGNOSTICS n = ROW_COUNT; res := res || jsonb_build_object('chat_sessions',n);
  ELSE
    DELETE FROM public.scan_logs            WHERE target_id=_target_id; GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('scan_logs',n);
    DELETE FROM public.scan_jobs            WHERE target_id=_target_id; GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('scan_jobs',n);
    DELETE FROM public.mythos_debates       WHERE target_id=_target_id; GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('mythos_debates',n);
    DELETE FROM public.mythos_variants      WHERE target_id=_target_id; GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('mythos_variants',n);
    DELETE FROM public.mythos_runs          WHERE target_id=_target_id; GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('mythos_runs',n);
    DELETE FROM public.agent_tasks          WHERE target_id=_target_id; GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('agent_tasks',n);
    DELETE FROM public.evidence_packages    WHERE target_id=_target_id; GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('evidence_packages',n);
    DELETE FROM public.oob_callbacks        WHERE target_id=_target_id; GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('oob_callbacks',n);
    DELETE FROM public.exploit_runs         WHERE target_id=_target_id; GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('exploit_runs',n);
    DELETE FROM public.discovered_endpoints WHERE target_id=_target_id; GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('discovered_endpoints',n);
    DELETE FROM public.vulnerability_findings WHERE target_id=_target_id; GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('vulnerability_findings',n);
  END IF;

  RETURN jsonb_build_object('ok',true,'deleted',res,'scope',_scope);
END;
$$;

REVOKE ALL ON FUNCTION public.purge_history(uuid,text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.purge_history(uuid,text) TO authenticated;