
-- Create enums
CREATE TYPE public.target_status AS ENUM ('queued', 'scanning', 'completed', 'error');
CREATE TYPE public.task_status AS ENUM ('pending', 'running', 'completed', 'failed');
CREATE TYPE public.severity_level AS ENUM ('critical', 'high', 'medium', 'low', 'info');
CREATE TYPE public.log_type AS ENUM ('thought', 'action', 'result', 'error', 'info');

-- Create target_workspaces table
CREATE TABLE public.target_workspaces (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  name TEXT NOT NULL,
  domain TEXT,
  ip_range TEXT,
  api_schema_url TEXT,
  status target_status NOT NULL DEFAULT 'queued',
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Create discovered_endpoints table
CREATE TABLE public.discovered_endpoints (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  target_id UUID NOT NULL REFERENCES public.target_workspaces(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  method TEXT NOT NULL DEFAULT 'GET',
  headers JSONB DEFAULT '{}',
  parameters JSONB DEFAULT '{}',
  status_code INTEGER,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Create vulnerability_findings table
CREATE TABLE public.vulnerability_findings (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  endpoint_id UUID REFERENCES public.discovered_endpoints(id) ON DELETE SET NULL,
  target_id UUID NOT NULL REFERENCES public.target_workspaces(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  severity severity_level NOT NULL DEFAULT 'info',
  cvss_score NUMERIC(3,1),
  description TEXT,
  poc TEXT,
  payload TEXT,
  remediation TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Create agent_tasks table
CREATE TABLE public.agent_tasks (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  target_id UUID NOT NULL REFERENCES public.target_workspaces(id) ON DELETE CASCADE,
  task_type TEXT NOT NULL,
  status task_status NOT NULL DEFAULT 'pending',
  thought_log JSONB DEFAULT '[]',
  result JSONB,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Create scan_logs table (for real-time streaming)
CREATE TABLE public.scan_logs (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  task_id UUID REFERENCES public.agent_tasks(id) ON DELETE SET NULL,
  target_id UUID REFERENCES public.target_workspaces(id) ON DELETE SET NULL,
  log_type log_type NOT NULL DEFAULT 'info',
  message TEXT NOT NULL,
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS on all tables
ALTER TABLE public.target_workspaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.discovered_endpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vulnerability_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_logs ENABLE ROW LEVEL SECURITY;

-- Public read/write policies (this is a tool, not multi-tenant user data)
CREATE POLICY "Allow all access to target_workspaces" ON public.target_workspaces FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Allow all access to discovered_endpoints" ON public.discovered_endpoints FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Allow all access to vulnerability_findings" ON public.vulnerability_findings FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Allow all access to agent_tasks" ON public.agent_tasks FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Allow all access to scan_logs" ON public.scan_logs FOR ALL USING (true) WITH CHECK (true);

-- Enable realtime for scan_logs
ALTER PUBLICATION supabase_realtime ADD TABLE public.scan_logs;

-- Create updated_at trigger function
CREATE OR REPLACE FUNCTION public.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SET search_path = public;

-- Add triggers
CREATE TRIGGER update_target_workspaces_updated_at BEFORE UPDATE ON public.target_workspaces FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();
CREATE TRIGGER update_agent_tasks_updated_at BEFORE UPDATE ON public.agent_tasks FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();

-- Create indexes
CREATE INDEX idx_discovered_endpoints_target ON public.discovered_endpoints(target_id);
CREATE INDEX idx_vulnerability_findings_target ON public.vulnerability_findings(target_id);
CREATE INDEX idx_vulnerability_findings_severity ON public.vulnerability_findings(severity);
CREATE INDEX idx_agent_tasks_target ON public.agent_tasks(target_id);
CREATE INDEX idx_scan_logs_task ON public.scan_logs(task_id);
CREATE INDEX idx_scan_logs_created ON public.scan_logs(created_at DESC);
