-- BEDROUK initial schema
-- Run this file in Supabase SQL Editor for a fresh project.

create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null default '',
  avatar_url text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.tasks (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  title text not null check (char_length(title) between 1 and 200),
  is_done boolean not null default false,
  sort_order integer not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  title text not null default '',
  content text not null default '',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.projects (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  title text not null check (char_length(title) between 1 and 160),
  description text not null default '',
  status text not null default 'active' check (status in ('active', 'paused', 'completed')),
  progress integer not null default 0 check (progress between 0 and 100),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists tasks_user_created_idx on public.tasks (user_id, created_at desc);
create index if not exists notes_user_updated_idx on public.notes (user_id, updated_at desc);
create index if not exists projects_user_created_idx on public.projects (user_id, created_at desc);

-- Keep updated_at current on edits.
create or replace function public.set_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists tasks_set_updated_at on public.tasks;
create trigger tasks_set_updated_at before update on public.tasks
for each row execute function public.set_updated_at();

drop trigger if exists notes_set_updated_at on public.notes;
create trigger notes_set_updated_at before update on public.notes
for each row execute function public.set_updated_at();

drop trigger if exists projects_set_updated_at on public.projects;
create trigger projects_set_updated_at before update on public.projects
for each row execute function public.set_updated_at();

drop trigger if exists profiles_set_updated_at on public.profiles;
create trigger profiles_set_updated_at before update on public.profiles
for each row execute function public.set_updated_at();

-- Create a profile automatically when a new Auth user is created.
create schema if not exists private;

create or replace function private.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, display_name, avatar_url)
  values (
    new.id,
    coalesce(new.raw_user_meta_data ->> 'full_name', new.raw_user_meta_data ->> 'name', ''),
    new.raw_user_meta_data ->> 'avatar_url'
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

revoke all on function private.handle_new_user() from public, anon, authenticated;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute function private.handle_new_user();

-- Explicit grants: signed-out visitors get no access to private user data.
alter table public.profiles enable row level security;
alter table public.tasks enable row level security;
alter table public.notes enable row level security;
alter table public.projects enable row level security;

revoke all on table public.profiles, public.tasks, public.notes, public.projects from anon, authenticated;
grant select, insert, update, delete on table public.profiles, public.tasks, public.notes, public.projects to authenticated;

-- Profiles: each user can access only their own profile.
drop policy if exists "profile_select_own" on public.profiles;
create policy "profile_select_own" on public.profiles
for select to authenticated using ((select auth.uid()) = id);

drop policy if exists "profile_insert_own" on public.profiles;
create policy "profile_insert_own" on public.profiles
for insert to authenticated with check ((select auth.uid()) = id);

drop policy if exists "profile_update_own" on public.profiles;
create policy "profile_update_own" on public.profiles
for update to authenticated
using ((select auth.uid()) = id)
with check ((select auth.uid()) = id);

drop policy if exists "profile_delete_own" on public.profiles;
create policy "profile_delete_own" on public.profiles
for delete to authenticated using ((select auth.uid()) = id);

-- Tasks: each user can manage only their own tasks.
drop policy if exists "tasks_select_own" on public.tasks;
create policy "tasks_select_own" on public.tasks
for select to authenticated using ((select auth.uid()) = user_id);

drop policy if exists "tasks_insert_own" on public.tasks;
create policy "tasks_insert_own" on public.tasks
for insert to authenticated with check ((select auth.uid()) = user_id);

drop policy if exists "tasks_update_own" on public.tasks;
create policy "tasks_update_own" on public.tasks
for update to authenticated
using ((select auth.uid()) = user_id)
with check ((select auth.uid()) = user_id);

drop policy if exists "tasks_delete_own" on public.tasks;
create policy "tasks_delete_own" on public.tasks
for delete to authenticated using ((select auth.uid()) = user_id);

-- Notes: each user can manage only their own notes.
drop policy if exists "notes_select_own" on public.notes;
create policy "notes_select_own" on public.notes
for select to authenticated using ((select auth.uid()) = user_id);

drop policy if exists "notes_insert_own" on public.notes;
create policy "notes_insert_own" on public.notes
for insert to authenticated with check ((select auth.uid()) = user_id);

drop policy if exists "notes_update_own" on public.notes;
create policy "notes_update_own" on public.notes
for update to authenticated
using ((select auth.uid()) = user_id)
with check ((select auth.uid()) = user_id);

drop policy if exists "notes_delete_own" on public.notes;
create policy "notes_delete_own" on public.notes
for delete to authenticated using ((select auth.uid()) = user_id);

-- Projects: each user can manage only their own projects.
drop policy if exists "projects_select_own" on public.projects;
create policy "projects_select_own" on public.projects
for select to authenticated using ((select auth.uid()) = user_id);

drop policy if exists "projects_insert_own" on public.projects;
create policy "projects_insert_own" on public.projects
for insert to authenticated with check ((select auth.uid()) = user_id);

drop policy if exists "projects_update_own" on public.projects;
create policy "projects_update_own" on public.projects
for update to authenticated
using ((select auth.uid()) = user_id)
with check ((select auth.uid()) = user_id);

drop policy if exists "projects_delete_own" on public.projects;
create policy "projects_delete_own" on public.projects
for delete to authenticated using ((select auth.uid()) = user_id);
