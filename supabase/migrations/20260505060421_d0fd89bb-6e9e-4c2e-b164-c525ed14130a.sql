-- Bug bounty platform tokens (per user)
create table public.bug_bounty_tokens (
  user_id uuid not null primary key,
  h1_username text,
  h1_api_token text,
  h1_program_handle text,
  bc_api_token text,
  bc_program_handle text,
  updated_at timestamptz not null default now()
);
alter table public.bug_bounty_tokens enable row level security;
create policy "bbt self" on public.bug_bounty_tokens for all to authenticated
  using (auth.uid() = user_id) with check (auth.uid() = user_id);

-- Submissions log
create table public.bug_bounty_submissions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  finding_id uuid,
  target_id uuid,
  platform text not null,                -- hackerone | bugcrowd | export
  program_handle text,
  remote_id text,
  status text not null default 'pending',-- pending | submitted | failed | exported
  title text,
  severity text,
  request_payload jsonb default '{}',
  response_payload jsonb default '{}',
  error_message text,
  created_at timestamptz not null default now()
);
alter table public.bug_bounty_submissions enable row level security;
create policy "bbs self" on public.bug_bounty_submissions for all to authenticated
  using (auth.uid() = user_id or public.has_role(auth.uid(),'admin'))
  with check (auth.uid() = user_id);

-- Uploaded application packages
create table public.app_packages (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  target_id uuid,
  filename text not null,
  storage_path text not null,
  package_type text not null default 'unknown', -- apk|exe|ipa|zip|jar|dmg|other
  size_bytes bigint default 0,
  status text not null default 'queued',        -- queued|extracting|analyzing|done|failed
  manifest jsonb default '{}',
  extracted_strings_count integer default 0,
  ai_summary text,
  error_message text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table public.app_packages enable row level security;
create policy "appkg self" on public.app_packages for all to authenticated
  using (auth.uid() = user_id or public.has_role(auth.uid(),'admin'))
  with check (auth.uid() = user_id);

-- Findings discovered inside an uploaded package
create table public.app_package_findings (
  id uuid primary key default gen_random_uuid(),
  package_id uuid not null references public.app_packages(id) on delete cascade,
  user_id uuid not null,
  severity text not null default 'medium',
  vuln_class text not null,
  title text not null,
  description text,
  file_path text,
  line_start integer,
  snippet text,
  remediation text,
  ai_reasoning text,
  cvss_score numeric,
  created_at timestamptz not null default now()
);
alter table public.app_package_findings enable row level security;
create policy "appkgf self" on public.app_package_findings for all to authenticated
  using (auth.uid() = user_id or public.has_role(auth.uid(),'admin'))
  with check (auth.uid() = user_id);

-- Sandboxed exploit executions
create table public.sandbox_executions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid,
  finding_id uuid,
  target_id uuid,
  mode text not null default 'auto',          -- worker|edge|auto
  executor text,                              -- docker_worker|edge_function
  language text default 'curl',
  script text,
  status text not null default 'pending',     -- pending|running|done|failed
  exit_code integer,
  output text,
  evidence jsonb default '{}',
  proven boolean default false,
  duration_ms integer,
  created_at timestamptz not null default now()
);
alter table public.sandbox_executions enable row level security;
create policy "sbx all auth" on public.sandbox_executions for all to authenticated
  using (true) with check (true);

-- Storage bucket for uploaded packages (private)
insert into storage.buckets (id, name, public) values ('app-packages','app-packages', false)
  on conflict (id) do nothing;
create policy "appkg upload own" on storage.objects for insert to authenticated
  with check (bucket_id = 'app-packages' and auth.uid()::text = (storage.foldername(name))[1]);
create policy "appkg read own" on storage.objects for select to authenticated
  using (bucket_id = 'app-packages' and (auth.uid()::text = (storage.foldername(name))[1] or public.has_role(auth.uid(),'admin')));
create policy "appkg delete own" on storage.objects for delete to authenticated
  using (bucket_id = 'app-packages' and auth.uid()::text = (storage.foldername(name))[1]);