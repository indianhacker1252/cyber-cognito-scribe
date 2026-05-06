
-- 1. Proof tier + sensitive flag on findings
alter table public.vulnerability_findings
  add column if not exists proof_tier text not null default 'signal'
    check (proof_tier in ('signal','reflected','exploited')),
  add column if not exists sensitive boolean not null default false,
  add column if not exists hard_evidence jsonb default '{}'::jsonb;

alter table public.evidence_packages
  add column if not exists sensitive boolean not null default false;

alter table public.sandbox_executions
  add column if not exists sensitive boolean not null default false;

-- 2. RAG corpus for Gemini-distilled VAPT playbooks (read by local Ollama)
create table if not exists public.rag_corpus (
  id uuid primary key default gen_random_uuid(),
  topic text not null,
  vuln_class text,
  phase text,
  content text not null,
  source text not null default 'gemini-distill',
  tags jsonb default '[]'::jsonb,
  created_at timestamptz not null default now()
);
alter table public.rag_corpus enable row level security;
create policy "rag read all auth" on public.rag_corpus for select to authenticated using (true);
create policy "rag admin write" on public.rag_corpus for all to authenticated
  using (public.has_role(auth.uid(),'admin'))
  with check (public.has_role(auth.uid(),'admin'));

-- 3. AI tutoring session log (Gemini correcting local model)
create table if not exists public.ai_tutoring_sessions (
  id uuid primary key default gen_random_uuid(),
  target_id uuid,
  finding_id uuid,
  local_model_output text,
  gemini_correction text,
  delta_score integer default 0,
  saved_to_corpus boolean default false,
  created_at timestamptz not null default now()
);
alter table public.ai_tutoring_sessions enable row level security;
create policy "tutor admin all" on public.ai_tutoring_sessions for all to authenticated
  using (public.has_role(auth.uid(),'admin'))
  with check (public.has_role(auth.uid(),'admin'));

-- 4. Tighten sensitive evidence visibility on existing tables.
-- We keep existing public read policies but layer admin-only for sensitive rows.
drop policy if exists "evidence sensitive admin only" on public.evidence_packages;
create policy "evidence sensitive admin only" on public.evidence_packages
  for select to authenticated
  using ( sensitive = false or public.has_role(auth.uid(),'admin') );

drop policy if exists "sbx sensitive admin only" on public.sandbox_executions;
create policy "sbx sensitive admin only" on public.sandbox_executions
  for select to authenticated
  using ( sensitive = false or public.has_role(auth.uid(),'admin') or auth.uid() = user_id );

-- 5. Helper to gate bounty submissions to proven exploits only
create or replace function public.assert_finding_submittable(_finding_id uuid)
returns boolean
language plpgsql
stable security definer
set search_path = public
as $$
declare
  pt text; sev text;
begin
  select proof_tier, severity::text into pt, sev
    from public.vulnerability_findings where id = _finding_id;
  if pt is null then return false; end if;
  -- Must be exploited tier; admins can override only via direct DB.
  return pt = 'exploited';
end $$;

-- 6. Index for proof tier filtering
create index if not exists idx_vf_proof_tier on public.vulnerability_findings(proof_tier);
create index if not exists idx_rag_topic on public.rag_corpus(topic);
