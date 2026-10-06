-- Osaka Travel Studio: allow authenticated users to create and initialize trips.
-- Run this once in Supabase SQL Editor after the sharing migrations.

alter table public.trips enable row level security;
alter table public.trip_data enable row level security;

grant select, insert, update, delete on table public.trips to authenticated;
grant select, insert, update, delete on table public.trip_data to authenticated;

drop policy if exists "Trip owners create trips" on public.trips;
create policy "Trip owners create trips"
on public.trips
for insert
to authenticated
with check ((select auth.uid()) = user_id);

-- Keep read access restricted to the owner or an invited trip member.
drop policy if exists "Trip members view trips" on public.trips;
create policy "Trip members view trips"
on public.trips
for select
to authenticated
using (
  (select auth.uid()) = user_id
  or private.user_can_access_trip(id)
);

-- New trips are initialized in trip_data immediately after catalog creation.
drop policy if exists "Trip members create trip data" on public.trip_data;
create policy "Trip members create trip data"
on public.trip_data
for insert
to authenticated
with check (exists (
  select 1
  from public.trips t
  where t.user_id = trip_data.user_id
    and t.trip_key = trip_data.trip_key
    and private.user_can_access_trip(t.id)
));

drop policy if exists "Trip members view trip data" on public.trip_data;
create policy "Trip members view trip data"
on public.trip_data
for select
to authenticated
using (exists (
  select 1
  from public.trips t
  where t.user_id = trip_data.user_id
    and t.trip_key = trip_data.trip_key
    and private.user_can_access_trip(t.id)
));

drop policy if exists "Trip members update trip data" on public.trip_data;
create policy "Trip members update trip data"
on public.trip_data
for update
to authenticated
using (exists (
  select 1
  from public.trips t
  where t.user_id = trip_data.user_id
    and t.trip_key = trip_data.trip_key
    and private.user_can_access_trip(t.id)
))
with check (exists (
  select 1
  from public.trips t
  where t.user_id = trip_data.user_id
    and t.trip_key = trip_data.trip_key
    and private.user_can_access_trip(t.id)
));
