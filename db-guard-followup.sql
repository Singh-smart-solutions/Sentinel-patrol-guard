-- ============================================================
--  SENTINEL GUARD — Guard-side issue follow-ups
--  Run ONCE in Supabase -> SQL Editor. Safe to re-run.
--  Lets a guard on patrol see an open issue at a checkpoint and
--  tap "Still not fixed" to add a dated follow-up (no photo needed).
-- ============================================================

-- Record who added each follow-up (a guard on patrol, or the manager).
alter table public.issue_updates add column if not exists guard_name text;

-- Open issues at a checkpoint, for the signed-in guard's hotel.
create or replace function public.guard_open_issues(p_token text, p_checkpoint_id uuid)
returns jsonb language plpgsql security definer set search_path = public as $$
declare g public.guards; res jsonb;
begin
  select * into g from public.guards where session_token = public.sg_hash_token(p_token) and session_expires > now() and active;
  if g.id is null then return jsonb_build_object('ok', false, 'reason', 'session'); end if;
  select coalesce(jsonb_agg(jsonb_build_object(
           'id', s.id, 'note', s.note, 'severity', s.severity, 'scanned_at', s.scanned_at
         ) order by s.scanned_at desc), '[]'::jsonb)
    into res
    from public.scans s
    where s.hotel_id = g.hotel_id and s.checkpoint_id = p_checkpoint_id
      and s.status = 'issue' and coalesce(s.resolved, false) = false;
  return jsonb_build_object('ok', true, 'issues', res);
end $$;
grant execute on function public.guard_open_issues(text, uuid) to anon, authenticated;

-- Guard adds a follow-up to an existing open issue.
create or replace function public.guard_add_followup(p_token text, p_scan_id uuid, p_note text, p_photo text default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare g public.guards; sc public.scans;
begin
  select * into g from public.guards where session_token = public.sg_hash_token(p_token) and session_expires > now() and active;
  if g.id is null then return jsonb_build_object('ok', false, 'reason', 'session'); end if;
  select * into sc from public.scans where id = p_scan_id and hotel_id = g.hotel_id;
  if sc.id is null then return jsonb_build_object('ok', false, 'reason', 'notfound'); end if;
  insert into public.issue_updates(hotel_id, scan_id, note, photo_path, guard_name)
    values (g.hotel_id, sc.id, nullif(p_note, ''), nullif(p_photo, ''), g.name);
  return jsonb_build_object('ok', true);
end $$;
grant execute on function public.guard_add_followup(text, uuid, text, text) to anon, authenticated;

notify pgrst, 'reload schema';

-- Done.
