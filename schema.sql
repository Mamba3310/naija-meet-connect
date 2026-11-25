-- Naija Meet & Connect database schema.
-- Apply in the Supabase SQL Editor for this project.
create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null check (char_length(display_name) between 1 and 60),
  birthdate date not null,
  city text not null check (char_length(city) between 1 and 80),
  neighborhood text check (char_length(neighborhood) <= 80),
  bio text not null default '' check (char_length(bio) <= 300),
  interests text[] not null default '{}',
  vibes text[] not null default '{}',
  avatar_url text,
  discoverable boolean not null default false,
  is_plus boolean not null default false,
  verified boolean not null default false,
  travel_city text check (char_length(travel_city) <= 80),
  travel_neighborhood text check (char_length(travel_neighborhood) <= 80),
  travel_until date,
  consented_at timestamptz,
  created_at timestamptz not null default now(),
  constraint profile_adult_only check (birthdate <= (current_date - interval '18 years')::date)
);

-- Upgrade an existing profiles table as well; CREATE TABLE IF NOT EXISTS does not add columns.
alter table public.profiles add column if not exists display_name text not null default 'New member';
alter table public.profiles add column if not exists birthdate date;
alter table public.profiles add column if not exists city text not null default 'Nigeria';
alter table public.profiles add column if not exists neighborhood text;
alter table public.profiles add column if not exists bio text not null default '';
alter table public.profiles add column if not exists interests text[] not null default '{}';
alter table public.profiles add column if not exists vibes text[] not null default '{}';
alter table public.profiles add column if not exists is_plus boolean not null default false;
alter table public.profiles add column if not exists verified boolean not null default false;
alter table public.profiles add column if not exists travel_city text;
alter table public.profiles add column if not exists travel_neighborhood text;
alter table public.profiles add column if not exists travel_until date;
alter table public.profiles add column if not exists avatar_url text;
alter table public.profiles add column if not exists discoverable boolean not null default false;
alter table public.profiles add column if not exists consented_at timestamptz;
alter table public.profiles add column if not exists created_at timestamptz not null default now();

create table if not exists public.friend_requests (
  id uuid primary key default gen_random_uuid(),
  sender_id uuid not null references public.profiles(id) on delete cascade,
  receiver_id uuid not null references public.profiles(id) on delete cascade,
  status text not null default 'pending' check (status in ('pending','accepted','declined','cancelled')),
  created_at timestamptz not null default now(),
  responded_at timestamptz,
  constraint friend_request_not_self check (sender_id <> receiver_id),
  constraint friend_request_unique_pair unique (sender_id,receiver_id)
);

create table if not exists public.posts (
  id uuid primary key default gen_random_uuid(),
  author_id uuid not null references public.profiles(id) on delete cascade,
  content text not null check (char_length(content) between 1 and 1000),
  city text not null default 'Nigeria' check (char_length(city) between 1 and 80),
  neighborhood text check (char_length(neighborhood) <= 80),
  vibe text check (char_length(vibe) <= 80),
  meetup_at timestamptz,
  created_at timestamptz not null default now()
);
alter table public.posts add column if not exists city text not null default 'Nigeria';
alter table public.posts add column if not exists neighborhood text;
alter table public.posts add column if not exists vibe text;
alter table public.posts add column if not exists meetup_at timestamptz;

create table if not exists public.hangout_circles (
  id uuid primary key default gen_random_uuid(),
  host_id uuid not null references public.profiles(id) on delete cascade,
  title text not null check (char_length(title) between 5 and 120),
  description text not null default '' check (char_length(description) <= 1000),
  city text not null check (char_length(city) <= 80),
  neighborhood text not null check (char_length(neighborhood) <= 80),
  venue_name text not null check (char_length(venue_name) between 2 and 120),
  starts_at timestamptz not null,
  capacity smallint not null default 8 check (capacity between 4 and 8),
  status text not null default 'open' check (status in ('open','full','cancelled','completed')),
  created_at timestamptz not null default now()
);

create table if not exists public.hangout_circle_members (
  circle_id uuid not null references public.hangout_circles(id) on delete cascade,
  member_id uuid not null references public.profiles(id) on delete cascade,
  status text not null default 'pending' check (status in ('pending','accepted','declined')),
  created_at timestamptz not null default now(),
  primary key(circle_id,member_id)
);

create table if not exists public.verification_requests (
  id uuid primary key default gen_random_uuid(),
  member_id uuid not null references public.profiles(id) on delete cascade,
  provider text not null,
  status text not null default 'pending' check (status in ('pending','verified','rejected')),
  created_at timestamptz not null default now(),
  reviewed_at timestamptz
);

-- Private safety details are intentionally not persisted by the client; the share-plan flow uses the device share sheet.


create table if not exists public.reports (
  id uuid primary key default gen_random_uuid(),
  reporter_id uuid not null references public.profiles(id) on delete cascade,
  reported_profile_id uuid not null references public.profiles(id) on delete cascade,
  post_id uuid references public.posts(id) on delete set null,
  reason text not null check (char_length(reason) between 3 and 1000),
  created_at timestamptz not null default now(),
  constraint report_not_self check (reporter_id <> reported_profile_id)
);

alter table public.profiles enable row level security;
alter table public.friend_requests enable row level security;
alter table public.posts enable row level security;
alter table public.reports enable row level security;
alter table public.hangout_circles enable row level security;
alter table public.hangout_circle_members enable row level security;
alter table public.verification_requests enable row level security;

drop policy if exists "members read opted-in profiles" on public.profiles;
create policy "members read opted-in profiles" on public.profiles for select to authenticated using (discoverable = true or id = (select auth.uid()));
drop policy if exists "members update own profile" on public.profiles;
create policy "members update own profile" on public.profiles for update to authenticated using (id = (select auth.uid())) with check (id = (select auth.uid()) and birthdate <= (current_date - interval '18 years')::date);

-- Ordinary members cannot grant themselves Plus or a verification badge.
create or replace function public.protect_profile_entitlements()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if auth.role() <> 'service_role' then
    new.is_plus := old.is_plus;
    new.verified := old.verified;
  end if;
  return new;
end;
$$;
drop trigger if exists protect_profile_entitlements on public.profiles;
create trigger protect_profile_entitlements before update on public.profiles for each row execute function public.protect_profile_entitlements();
drop policy if exists "members create own profile" on public.profiles;
create policy "members create own profile" on public.profiles for insert to authenticated with check (id = (select auth.uid()) and discoverable = true and is_plus = false and verified = false and birthdate <= (current_date - interval '18 years')::date);

drop policy if exists "send friend requests" on public.friend_requests;
create policy "send friend requests" on public.friend_requests for insert to authenticated with check (sender_id = (select auth.uid()) and sender_id <> receiver_id and exists (select 1 from public.profiles p where p.id = receiver_id and p.discoverable));
drop policy if exists "read own friend requests" on public.friend_requests;
create policy "read own friend requests" on public.friend_requests for select to authenticated using (sender_id = (select auth.uid()) or receiver_id = (select auth.uid()));
drop policy if exists "recipients respond to requests" on public.friend_requests;
create policy "recipients respond to requests" on public.friend_requests for update to authenticated using (receiver_id = (select auth.uid())) with check (receiver_id = (select auth.uid()) and status in ('accepted','declined'));

drop policy if exists "members read community posts" on public.posts;
create policy "members read community posts" on public.posts for select to authenticated using (exists (select 1 from public.profiles p where p.id = author_id and p.discoverable));
drop policy if exists "members create own posts" on public.posts;
create policy "members create own posts" on public.posts for insert to authenticated with check (author_id = (select auth.uid()));
drop policy if exists "authors delete own posts" on public.posts;
create policy "authors delete own posts" on public.posts for delete to authenticated using (author_id = (select auth.uid()));

drop policy if exists "members create own hangout circles" on public.hangout_circles;
create policy "members create own hangout circles" on public.hangout_circles for insert to authenticated with check (host_id = (select auth.uid()) and exists (select 1 from public.profiles p where p.id = (select auth.uid()) and p.is_plus = true and p.verified = true));
drop policy if exists "members read hangout circles" on public.hangout_circles;
create policy "members read hangout circles" on public.hangout_circles for select to authenticated using (status = 'open' or host_id = (select auth.uid()));
drop policy if exists "hosts update own hangout circles" on public.hangout_circles;
create policy "hosts update own hangout circles" on public.hangout_circles for update to authenticated using (host_id = (select auth.uid())) with check (host_id = (select auth.uid()));
drop policy if exists "members read own circle memberships" on public.hangout_circle_members;
create policy "members read own circle memberships" on public.hangout_circle_members for select to authenticated using (member_id = (select auth.uid()) or exists (select 1 from public.hangout_circles c where c.id = circle_id and c.host_id = (select auth.uid())));
drop policy if exists "verified members request circle seats" on public.hangout_circle_members;
create policy "verified members request circle seats" on public.hangout_circle_members for insert to authenticated with check (member_id = (select auth.uid()) and exists (select 1 from public.profiles p where p.id = (select auth.uid()) and p.verified = true));
drop policy if exists "hosts manage circle membership" on public.hangout_circle_members;
create policy "hosts manage circle membership" on public.hangout_circle_members for update to authenticated using (exists (select 1 from public.hangout_circles c where c.id = circle_id and c.host_id = (select auth.uid()))) with check (exists (select 1 from public.hangout_circles c where c.id = circle_id and c.host_id = (select auth.uid())));
drop policy if exists "members create own verification requests" on public.verification_requests;
create policy "members create own verification requests" on public.verification_requests for insert to authenticated with check (member_id = (select auth.uid()));
drop policy if exists "members read own verification requests" on public.verification_requests;
create policy "members read own verification requests" on public.verification_requests for select to authenticated using (member_id = (select auth.uid()));
drop policy if exists "members submit reports" on public.reports;
create policy "members submit reports" on public.reports for insert to authenticated with check (reporter_id = (select auth.uid()) and reporter_id <> reported_profile_id);
drop policy if exists "members read own reports" on public.reports;
create policy "members read own reports" on public.reports for select to authenticated using (reporter_id = (select auth.uid()));

create or replace function public.create_profile_for_new_member()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles(id,display_name,birthdate,city,neighborhood,bio,interests,vibes,avatar_url,discoverable,consented_at)
  values (
    new.id,
    coalesce(nullif(trim(new.raw_user_meta_data->>'display_name'),''),'New member'),
    (new.raw_user_meta_data->>'birthdate')::date,
    coalesce(nullif(trim(new.raw_user_meta_data->>'city'),''),'Nigeria'),
    nullif(trim(new.raw_user_meta_data->>'neighborhood'),''),
    coalesce(new.raw_user_meta_data->>'bio',''),
    coalesce(array(select jsonb_array_elements_text(coalesce(new.raw_user_meta_data->'interests','[]'::jsonb))),'{}'),
    coalesce(array(select jsonb_array_elements_text(coalesce(new.raw_user_meta_data->'vibes','[]'::jsonb))),'{}'),
    nullif(new.raw_user_meta_data->>'avatar_url',''),
    coalesce((new.raw_user_meta_data->>'discoverable')::boolean,false),
    case when coalesce((new.raw_user_meta_data->>'discoverable')::boolean,false) then now() else null end
  );
  return new;
end;
$$;

drop trigger if exists on_auth_user_created_profile on auth.users;
create trigger on_auth_user_created_profile after insert on auth.users for each row execute function public.create_profile_for_new_member();
