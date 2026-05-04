
-- Roles enum
do $$ begin
  create type public.app_role as enum ('admin','user');
exception when duplicate_object then null; end $$;

-- Profiles
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  display_name text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table public.profiles enable row level security;
drop policy if exists "profiles self read" on public.profiles;
create policy "profiles self read" on public.profiles for select to authenticated using (auth.uid() = id);
drop policy if exists "profiles self update" on public.profiles;
create policy "profiles self update" on public.profiles for update to authenticated using (auth.uid() = id);

-- User roles
create table if not exists public.user_roles (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  role public.app_role not null,
  created_at timestamptz not null default now(),
  unique (user_id, role)
);
alter table public.user_roles enable row level security;

create or replace function public.has_role(_user_id uuid, _role public.app_role)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.user_roles where user_id = _user_id and role = _role)
$$;

drop policy if exists "roles self read" on public.user_roles;
create policy "roles self read" on public.user_roles for select to authenticated
  using (auth.uid() = user_id or public.has_role(auth.uid(),'admin'));
drop policy if exists "roles admin manage" on public.user_roles;
create policy "roles admin manage" on public.user_roles for all to authenticated
  using (public.has_role(auth.uid(),'admin')) with check (public.has_role(auth.uid(),'admin'));

-- Scan credits
create table if not exists public.scan_credits (
  user_id uuid primary key references auth.users(id) on delete cascade,
  remaining integer not null default 3,
  total_granted integer not null default 3,
  total_used integer not null default 0,
  updated_at timestamptz not null default now()
);
alter table public.scan_credits enable row level security;
drop policy if exists "credits self read" on public.scan_credits;
create policy "credits self read" on public.scan_credits for select to authenticated
  using (auth.uid() = user_id or public.has_role(auth.uid(),'admin'));
drop policy if exists "credits admin manage" on public.scan_credits;
create policy "credits admin manage" on public.scan_credits for all to authenticated
  using (public.has_role(auth.uid(),'admin')) with check (public.has_role(auth.uid(),'admin'));

-- Scan usage log
create table if not exists public.scan_usage (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  target_id uuid,
  scan_type text not null,
  consumed integer not null default 1,
  created_at timestamptz not null default now()
);
alter table public.scan_usage enable row level security;
drop policy if exists "usage self read" on public.scan_usage;
create policy "usage self read" on public.scan_usage for select to authenticated
  using (auth.uid() = user_id or public.has_role(auth.uid(),'admin'));

-- External DB mirror config
create table if not exists public.external_db_config (
  user_id uuid primary key references auth.users(id) on delete cascade,
  enabled boolean not null default false,
  pg_connection_string text,
  last_test_at timestamptz,
  last_test_ok boolean,
  last_error text,
  updated_at timestamptz not null default now()
);
alter table public.external_db_config enable row level security;
drop policy if exists "extdb self" on public.external_db_config;
create policy "extdb self" on public.external_db_config for all to authenticated
  using (auth.uid() = user_id) with check (auth.uid() = user_id);

-- Trigger: auto-create profile + 3 credits on signup
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, email, display_name)
    values (new.id, new.email, coalesce(new.raw_user_meta_data->>'name', split_part(new.email,'@',1)))
    on conflict (id) do nothing;
  insert into public.scan_credits (user_id, remaining, total_granted)
    values (new.id, 3, 3) on conflict (user_id) do nothing;
  insert into public.user_roles (user_id, role)
    values (new.id, 'user') on conflict do nothing;
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- Atomic consume credit (admins bypass)
create or replace function public.consume_scan_credit(_target_id uuid, _scan_type text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  uid uuid := auth.uid();
  is_admin boolean;
  rem integer;
begin
  if uid is null then
    return jsonb_build_object('ok', false, 'error', 'not_authenticated');
  end if;
  is_admin := public.has_role(uid, 'admin');
  if is_admin then
    insert into public.scan_usage(user_id,target_id,scan_type,consumed) values (uid,_target_id,_scan_type,0);
    return jsonb_build_object('ok', true, 'admin', true, 'remaining', null);
  end if;
  update public.scan_credits
     set remaining = remaining - 1, total_used = total_used + 1, updated_at = now()
   where user_id = uid and remaining > 0
   returning remaining into rem;
  if rem is null then
    return jsonb_build_object('ok', false, 'error', 'no_credits');
  end if;
  insert into public.scan_usage(user_id,target_id,scan_type,consumed) values (uid,_target_id,_scan_type,1);
  return jsonb_build_object('ok', true, 'admin', false, 'remaining', rem);
end $$;

-- Admin grant
create or replace function public.grant_scan_credits(_user_id uuid, _amount integer)
returns jsonb language plpgsql security definer set search_path = public as $$
declare new_rem integer;
begin
  if not public.has_role(auth.uid(),'admin') then
    return jsonb_build_object('ok', false, 'error', 'forbidden');
  end if;
  insert into public.scan_credits(user_id,remaining,total_granted)
    values (_user_id, _amount, _amount)
  on conflict (user_id) do update
    set remaining = public.scan_credits.remaining + _amount,
        total_granted = public.scan_credits.total_granted + _amount,
        updated_at = now()
  returning remaining into new_rem;
  return jsonb_build_object('ok', true, 'remaining', new_rem);
end $$;

-- updated_at triggers
create trigger profiles_updated before update on public.profiles
  for each row execute function public.update_updated_at_column();
create trigger credits_updated before update on public.scan_credits
  for each row execute function public.update_updated_at_column();
create trigger extdb_updated before update on public.external_db_config
  for each row execute function public.update_updated_at_column();
