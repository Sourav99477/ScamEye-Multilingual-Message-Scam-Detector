-- Run this in Supabase Dashboard -> SQL Editor.
-- Supabase Auth stores credential hashes in auth.users. Do not create your own password column.

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  display_name text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.scan_history (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  message_text text not null,
  danger_level text not null check (danger_level in ('High','Medium','Low','Unclear')),
  classification text not null default 'Inconclusive',
  scam_type text not null default 'Unclear',
  warning_signs jsonb not null default '[]'::jsonb,
  explanation text not null default '',
  action text not null default '',
  confidence text not null default 'Low' check (confidence in ('High','Medium','Low')),
  rule_score integer not null default 0 check (rule_score between 0 and 100),
  language text not null default '',
  source text not null default 'text' check (source in ('text','screenshot')),
  created_at timestamptz not null default now()
);

create index if not exists scan_history_user_created_idx
  on public.scan_history (user_id, created_at desc);

alter table public.profiles enable row level security;
alter table public.scan_history enable row level security;

-- Users can read/update only their own profile. The Flask service creates profile rows.
drop policy if exists "Users can read own profile" on public.profiles;
create policy "Users can read own profile" on public.profiles
  for select to authenticated using ((select auth.uid()) = id);
drop policy if exists "Users can update own profile" on public.profiles;
create policy "Users can update own profile" on public.profiles
  for update to authenticated using ((select auth.uid()) = id) with check ((select auth.uid()) = id);

-- User-facing client access is limited to the authenticated owner's records.
-- Flask currently performs DB writes with a server-only service-role key and filters by verified user ID.
drop policy if exists "Users can read own scans" on public.scan_history;
create policy "Users can read own scans" on public.scan_history
  for select to authenticated using ((select auth.uid()) = user_id);
drop policy if exists "Users can insert own scans" on public.scan_history;
create policy "Users can insert own scans" on public.scan_history
  for insert to authenticated with check ((select auth.uid()) = user_id);
drop policy if exists "Users can delete own scans" on public.scan_history;
create policy "Users can delete own scans" on public.scan_history
  for delete to authenticated using ((select auth.uid()) = user_id);

-- Create/update a profile when a new auth user is registered.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = ''
as $$
begin
  insert into public.profiles (id, email, display_name)
  values (new.id, new.email, coalesce(new.raw_user_meta_data ->> 'display_name', ''))
  on conflict (id) do update set email = excluded.email;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute procedure public.handle_new_user();

-- Keep profile email in sync when auth email changes.
create or replace function public.handle_updated_user()
returns trigger
language plpgsql
security definer set search_path = ''
as $$
begin
  update public.profiles set email = new.email, updated_at = now() where id = new.id;
  return new;
end;
$$;
drop trigger if exists on_auth_user_updated on auth.users;
create trigger on_auth_user_updated
after update of email on auth.users
for each row execute procedure public.handle_updated_user();
