-- Allow a newly inserted trip to be returned by INSERT ... RETURNING.
-- The direct owner predicate works within the same statement; the helper
-- continues to authorize invited members for existing rows.

drop policy if exists "Trip members view trips" on public.trips;

create policy "Trip members view trips"
on public.trips
for select
to authenticated
using (
  (select auth.uid()) = user_id
  or private.user_can_access_trip(id)
);
