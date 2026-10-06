-- Osaka Travel Studio: invited collaborators and shared trip access

create schema if not exists private;

create table if not exists public.trip_members (
  trip_id uuid not null references public.trips(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'editor' check (role = 'editor'),
  joined_at timestamptz not null default now(),
  primary key (trip_id, user_id)
);

create table if not exists public.trip_invitations (
  id uuid primary key default gen_random_uuid(),
  trip_id uuid not null references public.trips(id) on delete cascade,
  email text not null check (email = lower(trim(email)) and char_length(email) between 3 and 320),
  role text not null default 'editor' check (role = 'editor'),
  invited_by uuid not null references auth.users(id) on delete cascade,
  accepted_at timestamptz,
  accepted_user_id uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  unique (trip_id, email)
);

create index if not exists trip_members_user_id_idx on public.trip_members(user_id);
create index if not exists trip_invitations_email_idx on public.trip_invitations(lower(email));
create index if not exists trips_owner_trip_key_idx on public.trips(user_id, trip_key);

alter table public.trip_members enable row level security;
alter table public.trip_invitations enable row level security;

create or replace function private.user_can_access_trip(target_trip_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select (select auth.uid()) is not null and exists (
    select 1 from public.trips t
    where t.id = target_trip_id
      and (
        t.user_id = (select auth.uid())
        or exists (
          select 1 from public.trip_members m
          where m.trip_id = t.id and m.user_id = (select auth.uid())
        )
      )
  );
$$;

create or replace function private.user_owns_trip(target_trip_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select (select auth.uid()) is not null and exists (
    select 1 from public.trips t
    where t.id = target_trip_id and t.user_id = (select auth.uid())
  );
$$;

revoke all on function private.user_can_access_trip(uuid) from public, anon;
revoke all on function private.user_owns_trip(uuid) from public, anon;
grant usage on schema private to authenticated;
grant execute on function private.user_can_access_trip(uuid) to authenticated;
grant execute on function private.user_owns_trip(uuid) to authenticated;

drop policy if exists "Users manage their own trip catalog" on public.trips;
drop policy if exists "Trip owners create trips" on public.trips;
drop policy if exists "Trip members view trips" on public.trips;
drop policy if exists "Trip owners update trips" on public.trips;
drop policy if exists "Trip owners delete trips" on public.trips;

create policy "Trip members view trips" on public.trips
for select to authenticated
using (private.user_can_access_trip(id));

create policy "Trip owners create trips" on public.trips
for insert to authenticated
with check ((select auth.uid()) = user_id);

create policy "Trip owners update trips" on public.trips
for update to authenticated
using ((select auth.uid()) = user_id)
with check ((select auth.uid()) = user_id);

create policy "Trip owners delete trips" on public.trips
for delete to authenticated
using ((select auth.uid()) = user_id);

drop policy if exists "Users manage their own trips" on public.trip_data;
drop policy if exists "Trip members view trip data" on public.trip_data;
drop policy if exists "Trip members create trip data" on public.trip_data;
drop policy if exists "Trip members update trip data" on public.trip_data;
drop policy if exists "Trip owners delete trip data" on public.trip_data;

create policy "Trip members view trip data" on public.trip_data
for select to authenticated
using (exists (
  select 1 from public.trips t
  where t.user_id = trip_data.user_id
    and t.trip_key = trip_data.trip_key
    and private.user_can_access_trip(t.id)
));

create policy "Trip members create trip data" on public.trip_data
for insert to authenticated
with check (exists (
  select 1 from public.trips t
  where t.user_id = trip_data.user_id
    and t.trip_key = trip_data.trip_key
    and private.user_can_access_trip(t.id)
));

create policy "Trip members update trip data" on public.trip_data
for update to authenticated
using (exists (
  select 1 from public.trips t
  where t.user_id = trip_data.user_id
    and t.trip_key = trip_data.trip_key
    and private.user_can_access_trip(t.id)
))
with check (exists (
  select 1 from public.trips t
  where t.user_id = trip_data.user_id
    and t.trip_key = trip_data.trip_key
    and private.user_can_access_trip(t.id)
));

create policy "Trip owners delete trip data" on public.trip_data
for delete to authenticated
using ((select auth.uid()) = user_id);

drop policy if exists "Trip collaborators view membership" on public.trip_members;
drop policy if exists "Trip owners manage membership" on public.trip_members;
drop policy if exists "Members leave shared trips" on public.trip_members;

create policy "Trip collaborators view membership" on public.trip_members
for select to authenticated
using (private.user_can_access_trip(trip_id));

create policy "Trip owners manage membership" on public.trip_members
for all to authenticated
using (private.user_owns_trip(trip_id))
with check (private.user_owns_trip(trip_id));

create policy "Members leave shared trips" on public.trip_members
for delete to authenticated
using ((select auth.uid()) = user_id);

drop policy if exists "Trip owners manage invitations" on public.trip_invitations;
drop policy if exists "Invitees view invitations" on public.trip_invitations;

create policy "Trip owners manage invitations" on public.trip_invitations
for all to authenticated
using (private.user_owns_trip(trip_id))
with check (private.user_owns_trip(trip_id) and invited_by = (select auth.uid()));

create policy "Invitees view invitations" on public.trip_invitations
for select to authenticated
using (lower(email) = lower(coalesce((select auth.jwt() ->> 'email'), '')));

create or replace function public.accept_trip_invitations()
returns integer
language plpgsql
security definer
set search_path = ''
as $$
declare
  caller_id uuid := (select auth.uid());
  caller_email text := lower(coalesce((select auth.jwt() ->> 'email'), ''));
  accepted_count integer := 0;
begin
  if caller_id is null or caller_email = '' then
    raise exception 'Authenticated email is required';
  end if;

  insert into public.trip_members (trip_id, user_id, role)
  select i.trip_id, caller_id, 'editor'
  from public.trip_invitations i
  where lower(i.email) = caller_email
    and i.accepted_at is null
  on conflict (trip_id, user_id) do nothing;

  update public.trip_invitations
  set accepted_at = now(), accepted_user_id = caller_id
  where lower(email) = caller_email
    and accepted_at is null;

  get diagnostics accepted_count = row_count;
  return accepted_count;
end;
$$;

revoke all on function public.accept_trip_invitations() from public, anon;
grant execute on function public.accept_trip_invitations() to authenticated;

grant select, insert, update, delete on public.trip_members to authenticated;
grant select, insert, update, delete on public.trip_invitations to authenticated;

create or replace function private.user_can_access_trip_storage(parts text[])
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select (select auth.uid()) is not null and exists (
    select 1 from public.trips t
    where t.user_id::text = parts[1]
      and (t.id::text = parts[2] or t.trip_key = parts[2])
      and private.user_can_access_trip(t.id)
  );
$$;

create or replace function private.user_owns_trip_storage(parts text[])
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select (select auth.uid()) is not null and exists (
    select 1 from public.trips t
    where t.user_id = (select auth.uid())
      and t.user_id::text = parts[1]
      and (t.id::text = parts[2] or t.trip_key = parts[2])
  );
$$;

revoke all on function private.user_can_access_trip_storage(text[]) from public, anon;
revoke all on function private.user_owns_trip_storage(text[]) from public, anon;
grant execute on function private.user_can_access_trip_storage(text[]) to authenticated;
grant execute on function private.user_owns_trip_storage(text[]) to authenticated;

drop policy if exists "Trip attachments select own" on storage.objects;
drop policy if exists "Trip attachments insert own" on storage.objects;
drop policy if exists "Trip attachments update own" on storage.objects;
drop policy if exists "Trip attachments delete own" on storage.objects;

create policy "Trip members view attachments" on storage.objects
for select to authenticated
using (
  bucket_id = 'trip-attachments'
  and private.user_can_access_trip_storage(storage.foldername(name))
);

create policy "Trip members upload attachments" on storage.objects
for insert to authenticated
with check (
  bucket_id = 'trip-attachments'
  and private.user_can_access_trip_storage(storage.foldername(name))
  and (storage.foldername(name))[3] = (select auth.uid())::text
);

create policy "Uploaders update attachments" on storage.objects
for update to authenticated
using (
  bucket_id = 'trip-attachments'
  and private.user_can_access_trip_storage(storage.foldername(name))
  and ((storage.foldername(name))[3] = (select auth.uid())::text or private.user_owns_trip_storage(storage.foldername(name)))
)
with check (
  bucket_id = 'trip-attachments'
  and private.user_can_access_trip_storage(storage.foldername(name))
  and ((storage.foldername(name))[3] = (select auth.uid())::text or private.user_owns_trip_storage(storage.foldername(name)))
);

create policy "Uploaders or owners delete attachments" on storage.objects
for delete to authenticated
using (
  bucket_id = 'trip-attachments'
  and private.user_can_access_trip_storage(storage.foldername(name))
  and ((storage.foldername(name))[3] = (select auth.uid())::text or private.user_owns_trip_storage(storage.foldername(name)))
);

notify pgrst, 'reload schema';
