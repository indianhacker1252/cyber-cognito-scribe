
create table if not exists public.request_replays (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null,
  finding_id uuid,
  target_id uuid,
  label text,
  request jsonb not null default '{}'::jsonb,
  response jsonb default '{}'::jsonb,
  diff jsonb default '{}'::jsonb,
  is_interesting boolean not null default false,
  created_at timestamptz not null default now()
);
alter table public.request_replays enable row level security;
create policy "replays self" on public.request_replays for all to authenticated
  using (auth.uid() = user_id or public.has_role(auth.uid(),'admin'))
  with check (auth.uid() = user_id);

create table if not exists public.exploit_runs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid,
  finding_id uuid,
  target_id uuid,
  exploit_source text not null default 'internal',
  exploit_ref text,
  status text not null default 'pending',
  output text,
  evidence jsonb default '{}'::jsonb,
  proof_tier text default 'signal',
  sensitive boolean not null default true,
  duration_ms integer,
  created_at timestamptz not null default now()
);
alter table public.exploit_runs enable row level security;
create policy "exploit auth all" on public.exploit_runs for all to authenticated
  using (true) with check (true);
create policy "exploit sensitive admin only" on public.exploit_runs for select to authenticated
  using (sensitive = false or public.has_role(auth.uid(),'admin') or auth.uid() = user_id);

create table if not exists public.exploitdb_index (
  id uuid primary key default gen_random_uuid(),
  edb_id text unique,
  cve text,
  cwe text,
  vuln_class text,
  title text not null,
  platform text,
  type text,
  exploit_code text,
  source_url text,
  tags jsonb default '[]'::jsonb,
  created_at timestamptz not null default now()
);
alter table public.exploitdb_index enable row level security;
create policy "edb read auth" on public.exploitdb_index for select to authenticated using (true);
create policy "edb admin write" on public.exploitdb_index for all to authenticated
  using (public.has_role(auth.uid(),'admin')) with check (public.has_role(auth.uid(),'admin'));

create index if not exists idx_edb_cve on public.exploitdb_index(cve);
create index if not exists idx_edb_class on public.exploitdb_index(vuln_class);
