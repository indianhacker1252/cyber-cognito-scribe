
-- Phase 10: Intelligence Feed Ingestion Engine

-- Intel feed entries from HackerOne, Bugcrowd, etc.
CREATE TABLE public.intel_feeds (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source TEXT NOT NULL DEFAULT 'hackerone',
  source_url TEXT,
  report_id TEXT,
  title TEXT NOT NULL,
  vulnerability_class TEXT,
  severity TEXT DEFAULT 'medium',
  affected_tech_stack JSONB DEFAULT '{}'::jsonb,
  extracted_payloads JSONB DEFAULT '[]'::jsonb,
  bypass_techniques JSONB DEFAULT '[]'::jsonb,
  waf_bypass_logic TEXT,
  raw_summary TEXT,
  ai_interpretation TEXT,
  test_template JSONB,
  template_script TEXT,
  template_language TEXT DEFAULT 'python',
  signal_strength TEXT DEFAULT 'medium',
  matched_targets JSONB DEFAULT '[]'::jsonb,
  rescan_triggered BOOLEAN DEFAULT false,
  ingested_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  processed_at TIMESTAMP WITH TIME ZONE,
  status TEXT DEFAULT 'pending'
);

ALTER TABLE public.intel_feeds ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all access to intel_feeds" ON public.intel_feeds FOR ALL USING (true) WITH CHECK (true);

-- Dashboard notifications for intel alerts
CREATE TABLE public.intel_notifications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  intel_feed_id UUID REFERENCES public.intel_feeds(id) ON DELETE CASCADE,
  target_id UUID REFERENCES public.target_workspaces(id) ON DELETE CASCADE,
  notification_type TEXT NOT NULL DEFAULT 'new_disclosure',
  title TEXT NOT NULL,
  message TEXT,
  is_read BOOLEAN DEFAULT false,
  action_url TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

ALTER TABLE public.intel_notifications ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all access to intel_notifications" ON public.intel_notifications FOR ALL USING (true) WITH CHECK (true);

-- Sync schedule tracking
CREATE TABLE public.intel_sync_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  started_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  completed_at TIMESTAMP WITH TIME ZONE,
  reports_fetched INTEGER DEFAULT 0,
  reports_processed INTEGER DEFAULT 0,
  templates_generated INTEGER DEFAULT 0,
  rescans_triggered INTEGER DEFAULT 0,
  status TEXT DEFAULT 'running',
  error_message TEXT
);

ALTER TABLE public.intel_sync_runs ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Allow all access to intel_sync_runs" ON public.intel_sync_runs FOR ALL USING (true) WITH CHECK (true);

-- Enable realtime for notifications
ALTER PUBLICATION supabase_realtime ADD TABLE public.intel_notifications;
