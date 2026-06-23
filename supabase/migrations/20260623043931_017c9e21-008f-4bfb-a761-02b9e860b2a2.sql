
-- 1) scan_assets.scheme
ALTER TABLE public.scan_assets
  ADD COLUMN IF NOT EXISTS scheme text NOT NULL DEFAULT 'https';

-- 2) scan_jobs dispatch index
CREATE INDEX IF NOT EXISTS scan_jobs_dispatch_idx
  ON public.scan_jobs (job_type, status, priority DESC, created_at);

-- 3) full purge function (covers every table the scanner writes to)
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
    DELETE FROM public.scan_logs;                  GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('scan_logs',n);
    DELETE FROM public.scan_jobs;                  GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('scan_jobs',n);
    DELETE FROM public.mythos_debates;             GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('mythos_debates',n);
    DELETE FROM public.mythos_runs;                GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('mythos_runs',n);
    DELETE FROM public.mythos_chains;              GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('mythos_chains',n);
    DELETE FROM public.mythos_patches;             GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('mythos_patches',n);
    DELETE FROM public.agent_tasks;                GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('agent_tasks',n);
    DELETE FROM public.evidence_packages;          GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('evidence_packages',n);
    DELETE FROM public.oob_callbacks;              GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('oob_callbacks',n);
    DELETE FROM public.exploit_runs;               GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('exploit_runs',n);
    DELETE FROM public.discovered_endpoints;       GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('discovered_endpoints',n);
    DELETE FROM public.discovered_forms;           GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('discovered_forms',n);
    DELETE FROM public.vulnerability_findings;     GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('vulnerability_findings',n);
    DELETE FROM public.chat_messages;              GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('chat_messages',n);
    DELETE FROM public.chat_sessions;              GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('chat_sessions',n);
    DELETE FROM public.scan_assets;                GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('scan_assets',n);
    DELETE FROM public.kill_chain_graph_edges;     GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('kill_chain_graph_edges',n);
    DELETE FROM public.advanced_detector_runs;     GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('advanced_detector_runs',n);
    DELETE FROM public.chain_finder_runs;          GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('chain_finder_runs',n);
    DELETE FROM public.request_replays;            GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('request_replays',n);
    DELETE FROM public.attack_graph_edges;         GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('attack_graph_edges',n);
    DELETE FROM public.attack_graph_nodes;         GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('attack_graph_nodes',n);
  ELSE
    DELETE FROM public.scan_logs              WHERE target_id=_target_id; GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('scan_logs',n);
    DELETE FROM public.scan_jobs              WHERE target_id=_target_id; GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('scan_jobs',n);
    DELETE FROM public.mythos_debates         WHERE target_id=_target_id; GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('mythos_debates',n);
    DELETE FROM public.mythos_variants        WHERE target_id=_target_id; GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('mythos_variants',n);
    DELETE FROM public.mythos_runs            WHERE target_id=_target_id; GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('mythos_runs',n);
    DELETE FROM public.mythos_chains          WHERE target_id=_target_id; GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('mythos_chains',n);
    DELETE FROM public.agent_tasks            WHERE target_id=_target_id; GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('agent_tasks',n);
    DELETE FROM public.evidence_packages      WHERE target_id=_target_id; GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('evidence_packages',n);
    DELETE FROM public.oob_callbacks          WHERE target_id=_target_id; GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('oob_callbacks',n);
    DELETE FROM public.exploit_runs           WHERE target_id=_target_id; GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('exploit_runs',n);
    DELETE FROM public.discovered_endpoints   WHERE target_id=_target_id; GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('discovered_endpoints',n);
    DELETE FROM public.discovered_forms       WHERE target_id=_target_id; GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('discovered_forms',n);
    DELETE FROM public.vulnerability_findings WHERE target_id=_target_id; GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('vulnerability_findings',n);
    DELETE FROM public.scan_assets            WHERE target_id=_target_id; GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('scan_assets',n);
    DELETE FROM public.kill_chain_graph_edges WHERE target_id=_target_id; GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('kill_chain_graph_edges',n);
    DELETE FROM public.advanced_detector_runs WHERE target_id=_target_id; GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('advanced_detector_runs',n);
    DELETE FROM public.chain_finder_runs      WHERE target_id=_target_id; GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('chain_finder_runs',n);
    DELETE FROM public.request_replays        WHERE target_id=_target_id; GET DIAGNOSTICS n=ROW_COUNT; res := res || jsonb_build_object('request_replays',n);
  END IF;

  RETURN jsonb_build_object('ok',true,'deleted',res,'scope',_scope);
END;
$$;

REVOKE ALL ON FUNCTION public.purge_history(uuid,text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.purge_history(uuid,text) TO authenticated;
