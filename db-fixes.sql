-- ============================================================
--  SENTINEL GUARD — Security-audit fixes (run ONCE in Supabase)
--  Supabase -> SQL Editor -> New query -> paste -> Run.
--  Idempotent: safe to run more than once.
--
--  Covers:
--    SEC-01  New managers no longer bind to the first hotel
--    SEC-02  Deleting a guard/checkpoint no longer destroys scans
--    SEC-03  Guard codes must be unique (per hotel)
--    SEC-04  Guard tokens can be revoked (logout / deactivation)
-- ============================================================

-- ---------- SEC-02: preserve patrol history on delete ----------
-- Keep a copy of the names on each scan, so history stays readable
-- even after a guard or checkpoint is removed.
alter table public.scans add column if not exists cp_name    text;
alter table public.scans add column if not exists guard_name text;

update public.scans s set cp_name = c.name
  from public.checkpoints c where s.checkpoint_id = c.id and s.cp_name is null;
update public.scans s set guard_name = g.name
  from public.guards g where s.guard_id = g.id and s.guard_name is null;

-- Change the foreign keys from CASCADE (delete scans) to SET NULL (keep scans).
alter table public.scans alter column checkpoint_id drop not null;
alter table public.scans alter column guard_id      drop not null;

alter table public.scans drop constraint if exists scans_checkpoint_id_fkey;
alter table public.scans add  constraint scans_checkpoint_id_fkey
  foreign key (checkpoint_id) references public.checkpoints(id) on delete set null;

alter table public.scans drop constraint if exists scans_guard_id_fkey;
alter table public.scans add  constraint scans_guard_id_fkey
  foreign key (guard_id) references public.guards(id) on delete set null;

-- record_scan now also stores the names (so new scans keep them too).
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
    if p_lat is null then
      insert into public.security_flags(hotel_id, checkpoint_id, guard_id, guard_name, checkpoint_name, reason)
        values (g.hotel_id, ck.id, g.id, g.name, ck.name, 'no_gps');
      return jsonb_build_object('ok', false, 'reason', 'no_gps');
    end if;
    if p_acc is null or p_acc <= 0 or p_acc > maxacc then
      insert into public.security_flags(hotel_id, checkpoint_id, guard_id, guard_name, checkpoint_name, lat, lng, accuracy, reason)
        values (g.hotel_id, ck.id, g.id, g.name, ck.name, p_lat, p_lng, p_acc, 'accuracy');
      return jsonb_build_object('ok', false, 'reason', 'accuracy', 'accuracy', p_acc, 'max_accuracy', maxacc);
    end if;
    dist := public.distance_m(p_lat, p_lng, ck.lat, ck.lng);
    if dist > thr then
      insert into public.security_flags(hotel_id, checkpoint_id, guard_id, guard_name, checkpoint_name, lat, lng, accuracy, distance_m, reason)
        values (g.hotel_id, ck.id, g.id, g.name, ck.name, p_lat, p_lng, p_acc, round(dist), 'geofence');
      return jsonb_build_object('ok', false, 'reason', 'geofence', 'distance', round(dist), 'threshold', thr);
    end if;
    wgf := true;
  end if;

  insert into public.scans(hotel_id, checkpoint_id, guard_id, cp_name, guard_name, status, note, severity, lat, lng, gps_accuracy, within_geofence, scanned_at)
    values (g.hotel_id, ck.id, g.id, ck.name, g.name, coalesce(p_status,'normal'), nullif(p_note,''), nullif(p_severity,''), p_lat, p_lng, p_acc, wgf, ts)
    returning id into sid;

  return jsonb_build_object('ok', true, 'scan_id', sid, 'verified', wgf,
    'distance', case when dist is null then null else round(dist) end);
end $$;

grant execute on function public.record_scan(text,uuid,text,text,text,double precision,double precision,integer,timestamptz) to anon, authenticated;

-- ---------- SEC-01: each new manager gets their OWN hotel ----------
-- (Previously every new manager was attached to the first hotel in the table,
--  which is what caused checkpoints to land on the wrong hotel.)
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
declare h uuid;
begin
  insert into public.hotels(name)
    values (coalesce(new.raw_user_meta_data->>'hotel', 'My Hotel'))
    returning id into h;
  insert into public.profiles(id, hotel_id, name)
    values (new.id, h, coalesce(new.raw_user_meta_data->>'name', new.email));
  return new;
end $$;

-- ---------- SEC-04: revoke guard sessions ----------
-- Called by the app on "End shift" so a 12h token can't be reused after logout.
create or replace function public.guard_logout(p_token text)
returns void language plpgsql security definer set search_path = public as $$
begin
  update public.guards
     set session_token = null, session_expires = null
   where session_token = p_token;
end $$;
grant execute on function public.guard_logout(text) to anon, authenticated;

-- Also drop the active session automatically when a guard is deactivated.
create or replace function public.sg_clear_token_on_deactivate()
returns trigger language plpgsql as $$
begin
  if new.active = false and coalesce(old.active, true) = true then
    new.session_token := null;
    new.session_expires := null;
  end if;
  return new;
end $$;
drop trigger if exists trg_sg_clear_token on public.guards;
create trigger trg_sg_clear_token
  before update on public.guards
  for each row execute function public.sg_clear_token_on_deactivate();

-- ---------- SEC-03: guard codes unique per hotel ----------
-- Prevents two active guards sharing a code (which made logins ambiguous).
-- Partial index: only active guards, so retired duplicates don't block you.
create unique index if not exists guards_hotel_code_uniq
  on public.guards (hotel_id, upper(code)) where active;

-- ---------- refresh API cache ----------
notify pgrst, 'reload schema';

-- Done.
