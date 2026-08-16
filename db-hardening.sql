-- ============================================================
--  SENTINEL GUARD — Phase 1.6 hardening
--  Accuracy filtering · per-checkpoint radius · offline-safe times
--  Paste into Supabase → SQL Editor → Run. Safe to re-run.
-- ============================================================

-- Per-checkpoint max acceptable GPS accuracy (metres). Indoor spots can raise this.
alter table public.checkpoints add column if not exists max_accuracy_m integer not null default 30;

-- Preserve the real scan time for scans that were queued offline and synced later.
alter table public.scans add column if not exists scanned_at timestamptz;
update public.scans set scanned_at = created_at where scanned_at is null;

-- Also record accuracy on flags (older column may be missing)
alter table public.security_flags add column if not exists accuracy integer;

-- Replace record_scan: geofence + accuracy enforced server-side; keeps offline scan time.
drop function if exists public.record_scan(text,uuid,text,text,text,double precision,double precision,integer);

create or replace function public.record_scan(
  p_token text, p_checkpoint_id uuid, p_status text, p_note text,
  p_severity text, p_lat double precision, p_lng double precision, p_acc integer,
  p_scanned_at timestamptz default null
) returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  g public.guards; ck public.checkpoints;
  dist double precision := null; thr int; maxacc int; sid uuid; wgf boolean := null;
  ts timestamptz;
begin
  ts := coalesce(p_scanned_at, now());

  select * into g from public.guards where session_token = p_token and session_expires > now() and active;
  if g.id is null then return jsonb_build_object('ok', false, 'reason', 'session'); end if;

  select * into ck from public.checkpoints where id = p_checkpoint_id and hotel_id = g.hotel_id;
  if ck.id is null then return jsonb_build_object('ok', false, 'reason', 'checkpoint'); end if;

  thr := coalesce(ck.geofence_m, 15);
  maxacc := coalesce(ck.max_accuracy_m, 30);

  if ck.lat is not null then
    -- no GPS at all -> cannot verify
    if p_lat is null then
      insert into public.security_flags(hotel_id, checkpoint_id, guard_id, guard_name, checkpoint_name, reason)
        values (g.hotel_id, ck.id, g.id, g.name, ck.name, 'no_gps');
      return jsonb_build_object('ok', false, 'reason', 'no_gps');
    end if;
    -- poor / suspicious accuracy (mock tools often report 0 / negative / absurd values)
    if p_acc is null or p_acc <= 0 or p_acc > maxacc then
      insert into public.security_flags(hotel_id, checkpoint_id, guard_id, guard_name, checkpoint_name, lat, lng, accuracy, reason)
        values (g.hotel_id, ck.id, g.id, g.name, ck.name, p_lat, p_lng, p_acc, 'accuracy');
      return jsonb_build_object('ok', false, 'reason', 'accuracy', 'accuracy', p_acc, 'max_accuracy', maxacc);
    end if;
    -- geofence distance
    dist := public.distance_m(p_lat, p_lng, ck.lat, ck.lng);
    if dist > thr then
      insert into public.security_flags(hotel_id, checkpoint_id, guard_id, guard_name, checkpoint_name, lat, lng, accuracy, distance_m, reason)
        values (g.hotel_id, ck.id, g.id, g.name, ck.name, p_lat, p_lng, p_acc, round(dist), 'geofence');
      return jsonb_build_object('ok', false, 'reason', 'geofence', 'distance', round(dist), 'threshold', thr);
    end if;
    wgf := true;
  end if;

  insert into public.scans(hotel_id, checkpoint_id, guard_id, status, note, severity, lat, lng, gps_accuracy, within_geofence, scanned_at)
    values (g.hotel_id, ck.id, g.id, coalesce(p_status,'normal'), nullif(p_note,''), nullif(p_severity,''), p_lat, p_lng, p_acc, wgf, ts)
    returning id into sid;

  return jsonb_build_object('ok', true, 'scan_id', sid, 'verified', wgf,
    'distance', case when dist is null then null else round(dist) end);
end $$;

grant execute on function public.record_scan(text,uuid,text,text,text,double precision,double precision,integer,timestamptz) to anon, authenticated;

-- Done.
