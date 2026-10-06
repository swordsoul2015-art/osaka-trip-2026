-- Follow-up hardening: use SECURITY INVOKER and consolidate RLS policies.

create index if not exists trip_invitations_invited_by_idx on public.trip_invitations(invited_by);
create index if not exists trip_invitations_accepted_user_id_idx on public.trip_invitations(accepted_user_id);

drop policy if exists "Trip collaborators view membership" on public.trip_members;
drop policy if exists "Trip owners manage membership" on public.trip_members;
drop policy if exists "Members leave shared trips" on public.trip_members;
drop policy if exists "Invitees join shared trips" on public.trip_members;
drop policy if exists "Trip owners update membership" on public.trip_members;
drop policy if exists "Trip owners or members delete membership" on public.trip_members;

create policy "Trip collaborators view membership" on public.trip_members
for select to authenticated
using (private.user_can_access_trip(trip_id));

create policy "Invitees join shared trips" on public.trip_members
for insert to authenticated
with check (
  user_id = (select auth.uid())
  and exists (
    select 1 from public.trip_invitations i
    where i.trip_id = trip_members.trip_id
      and lower(i.email) = lower(coalesce((select auth.jwt()) ->> 'email', ''))
      and i.accepted_at is null
  )
);

create policy "Trip owners update membership" on public.trip_members
for update to authenticated
using (private.user_owns_trip(trip_id))
with check (private.user_owns_trip(trip_id));

create policy "Trip owners or members delete membership" on public.trip_members
for delete to authenticated
using (private.user_owns_trip(trip_id) or user_id = (select auth.uid()));

drop policy if exists "Trip owners manage invitations" on public.trip_invitations;
drop policy if exists "Invitees view invitations" on public.trip_invitations;
drop policy if exists "Trip participants view invitations" on public.trip_invitations;
drop policy if exists "Trip owners create invitations" on public.trip_invitations;
drop policy if exists "Trip owners or invitees update invitations" on public.trip_invitations;
drop policy if exists "Trip owners delete invitations" on public.trip_invitations;

create policy "Trip participants view invitations" on public.trip_invitations
for select to authenticated
using (
  private.user_owns_trip(trip_id)
  or lower(email) = lower(coalesce((select auth.jwt()) ->> 'email', ''))
);

create policy "Trip owners create invitations" on public.trip_invitations
for insert to authenticated
with check (private.user_owns_trip(trip_id) and invited_by = (select auth.uid()));

create policy "Trip owners or invitees update invitations" on public.trip_invitations
for update to authenticated
using (
  private.user_owns_trip(trip_id)
  or (lower(email) = lower(coalesce((select auth.jwt()) ->> 'email', '')) and accepted_at is null)
)
with check (
  private.user_owns_trip(trip_id)
  or (
    lower(email) = lower(coalesce((select auth.jwt()) ->> 'email', ''))
    and accepted_user_id = (select auth.uid())
    and accepted_at is not null
  )
);

create policy "Trip owners delete invitations" on public.trip_invitations
for delete to authenticated
using (private.user_owns_trip(trip_id));

create or replace function public.accept_trip_invitations()
returns integer
language plpgsql
security invoker
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

notify pgrst, 'reload schema';
