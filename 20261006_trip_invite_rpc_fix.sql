-- Keep the public RPC as SECURITY INVOKER while isolating the required
-- privileged membership write in the non-exposed private schema.

create or replace function private.accept_trip_invitations_internal()
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

revoke all on function private.accept_trip_invitations_internal() from public, anon;
grant execute on function private.accept_trip_invitations_internal() to authenticated;

create or replace function public.accept_trip_invitations()
returns integer
language sql
security invoker
set search_path = ''
as $$
  select private.accept_trip_invitations_internal();
$$;

revoke all on function public.accept_trip_invitations() from public, anon;
grant execute on function public.accept_trip_invitations() to authenticated;

notify pgrst, 'reload schema';
