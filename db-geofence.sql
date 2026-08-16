-- ============================================================
--  SENTINEL GUARD — Geofence anti-spoofing (Phase 1.5)
--  Paste into Supabase → SQL Editor → Run. Safe to re-run.
-- ============================================================

-- Strict 15 m geofence by default
alter table public.checkpoints alter column geofence_m set default 15;

-- Log of failed / suspicious check-in attempts, for manager review
create table if not exists public.security_flags (
  id              uuid primary key default gen_random_uuid(),
  hotel_id        uuid not null references public.hotels(id) on delete cascade,
  checkpoint_id   uuid references public.checkpoints(id) on delete set null,
  guard_id        uuid references public.guards(id) on delete set null,
  guard_name      text,
  checkpoint_name text,
  lat             double precision,
  lng             double precision,
  accuracy        integer,
  distance_m      integer,
  reason          text not null default 'geofence',   -- 'geofence' | 'no_gps'
  created_at      timestamptz not null default now()
);
create index if not exists flags_hotel_time on public.security_flags(hotel_id, created_at desc);

alter table public.security_flags enable row level security;
drop policy if exists p_flags on public.security_flags;
create policy p_flags on public.security_flags for select to authenticated using (hotel_id = public.my_hotel());

-- Haversine distance in metres
create or replace function public.distance_m(lat1 double precision, lng1 double precision, lat2 double precision, lng2 double precision)
returns double precision language sql immutable set search_path = public as $$
  select 6371000 * acos( least(1, greatest(-1,
    cos(radians(lat1)) * cos(radians(lat2)) * cos(radians(lng2) - radians(lng1))
    + sin(radians(lat1)) * sin(radians(lat2))
  )) );
$$;

-- Record a scan WITH server-side geofence enforcement.
-- Returns jsonb: { ok, reason?, distance?, threshold?, scan_id?, verified? }
create or replace function public.record_scan(
  p_token text, p_checkpoint_id uuid, p_status text, p_note text,
  p_severity text, p_lat double precision, p_lng double precision, p_acc integer
) returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  g public.guards; ck public.checkpoints;
  dist double precision := null; thr int := 15; sid uuid; wgf boolean := null;
begin
  select * into g from public.guards where session_token = p_token and session_expires > now() and active;
  if g.id is null then return jsonb_build_object('ok', false, 'reason', 'session'); end if;

  select * into ck from public.checkpoints where id = p_checkpoint_id and hotel_id = g.hotel_id;
  if ck.id is null then return jsonb_build_object('ok', false, 'reason', 'checkpoint'); end if;

  if ck.lat is not null and p_lat is not null then
    dist := public.distance_m(p_lat, p_lng, ck.lat, ck.lng);
    if dist > thr then
      insert into public.security_flags(hotel_id, checkpoint_id, guard_id, guard_name, checkpoint_name, lat, lng, accuracy, distance_m, reason)
        values (g.hotel_id, ck.id, g.id, g.name, ck.name, p_lat, p_lng, p_acc, round(dist), 'geofence');
      return jsonb_build_object('ok', false, 'reason', 'geofence', 'distance', round(dist), 'threshold', thr);
    end if;
    wgf := true;
  elsif ck.lat is not null and p_lat is null then
    -- checkpoint is calibrated but the device sent no GPS -> cannot verify presence
    insert into public.security_flags(hotel_id, checkpoint_id, guard_id, guard_name, checkpoint_name, reason)
      values (g.hotel_id, ck.id, g.id, g.name, ck.name, 'no_gps');
    return jsonb_build_object('ok', false, 'reason', 'no_gps');
  end if;
  -- (if the checkpoint has no stored coords yet, the scan is allowed but marked unverified)

  insert into public.scans(hotel_id, checkpoint_id, guard_id, status, note, severity, lat, lng, gps_accuracy, within_geofence)
    values (g.hotel_id, ck.id, g.id, coalesce(p_status,'normal'), nullif(p_note,''), nullif(p_severity,''), p_lat, p_lng, p_acc, wgf)
    returning id into sid;

  return jsonb_build_object('ok', true, 'scan_id', sid, 'verified', wgf,
    'distance', case when dist is null then null else round(dist) end);
end $$;

grant execute on function public.distance_m(double precision,double precision,double precision,double precision) to anon, authenticated;
grant execute on function public.record_scan(text,uuid,text,text,text,double precision,double precision,integer) to anon, authenticated;

-- Done.
