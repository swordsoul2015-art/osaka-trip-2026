-- Fix invited users being blocked when joining trip_members through RLS.

create or replace function private.user_has_pending_trip_invite(target_trip_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select (select auth.uid()) is not null
    and coalesce((select auth.jwt() ->> 'email'), '') <> ''
    and exists (
      select 1
      from public.trip_invitations i
      where i.trip_id = target_trip_id
        and lower(i.email) = lower((select auth.jwt() ->> 'email'))
        and i.accepted_at is null
    );
$$;

revoke all on function private.user_has_pending_trip_invite(uuid) from public, anon;
grant execute on function private.user_has_pending_trip_invite(uuid) to authenticated;

drop policy if exists "Invitees join shared trips" on public.trip_members;

create policy "Invitees join shared trips" on public.trip_members
for insert to authenticated
with check (
  user_id = (select auth.uid())
  and private.user_has_pending_trip_invite(trip_id)
);

notify pgrst, 'reload schema';
