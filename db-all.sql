-- ############################################################
--  SENTINEL GUARD — COMPLETE DATABASE SETUP  (db-all.sql)
--  Run ONCE in Supabase -> SQL Editor. Safe on new OR existing
--  projects, and safe to run more than once (idempotent).
-- ############################################################


-- ==========================================================
--  1. BASE SCHEMA
-- ==========================================================
-- ============================================================
--  SENTINEL GUARD — Phase 1 database setup
--  Paste this whole file into Supabase → SQL Editor → Run.
--  Safe to run more than once.
-- ============================================================

create extension if not exists pgcrypto;

-- ---------- TABLES ----------
create table if not exists public.hotels (
  id         uuid primary key default gen_random_uuid(),
  name       text not null default 'My Hotel',
  created_at timestamptz not null default now()
);

-- Manager accounts (Supabase Auth users linked to a hotel)
create table if not exists public.profiles (
  id         uuid primary key references auth.users(id) on delete cascade,
  hotel_id   uuid not null references public.hotels(id) on delete cascade,
  name       text,
  created_at timestamptz not null default now()
);

-- Guards (created by the manager; sign in with a PIN)
create table if not exists public.guards (
  id              uuid primary key default gen_random_uuid(),
  hotel_id        uuid not null references public.hotels(id) on delete cascade,
  name            text not null,
  phone           text,
  code            text not null,
  pin_hash        text not null,
  active          boolean not null default true,
  session_token   text,
  session_expires timestamptz,
  created_at      timestamptz not null default now()
);

create table if not exists public.checkpoints (
  id         uuid primary key default gen_random_uuid(),
  hotel_id   uuid not null references public.hotels(id) on delete cascade,
  name       text not null,
  zone       text,
  code       text not null,
  lat        double precision,
  lng        double precision,
  geofence_m integer not null default 60,
  active     boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.scans (
  id              uuid primary key default gen_random_uuid(),
  hotel_id        uuid not null references public.hotels(id) on delete cascade,
  checkpoint_id   uuid not null references public.checkpoints(id) on delete cascade,
  guard_id        uuid not null references public.guards(id) on delete cascade,
  status          text not null default 'normal' check (status in ('normal','issue')),
  note            text,
  severity        text check (severity in ('Low','Medium','High')),
  photo_path      text,
  lat             double precision,
  lng             double precision,
  gps_accuracy    integer,
  within_geofence boolean,
  resolved        boolean not null default false,
  resolved_at     timestamptz,
  created_at      timestamptz not null default now()
);
create index if not exists scans_hotel_time on public.scans(hotel_id, created_at desc);

-- ---------- HELPERS ----------
-- The hotel of the currently signed-in manager
create or replace function public.my_hotel()
returns uuid language sql stable security definer set search_path = public as $$
  select hotel_id from public.profiles where id = auth.uid();
$$;

-- SHA-256 (hex) of a guard bearer token. guards.session_token stores this
-- hash, never the raw token, so a leaked DB row cannot be replayed. The raw
-- token is returned to the client at login only; every guard RPC hashes the
-- incoming token with this helper before comparing.
create or replace function public.sg_hash_token(p_token text)
returns text language sql immutable set search_path = public, extensions as $$
  select encode(digest(coalesce(p_token, ''), 'sha256'), 'hex');
$$;
grant execute on function public.sg_hash_token(text) to anon, authenticated;

-- When a manager signs up, attach them to the (single) hotel, creating it if needed
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
declare h uuid;
begin
  select id into h from public.hotels order by created_at limit 1;
  if h is null then
    insert into public.hotels(name) values ('My Hotel') returning id into h;
  end if;
  insert into public.profiles(id, hotel_id, name)
    values (new.id, h, coalesce(new.raw_user_meta_data->>'name', new.email));
  return new;
end $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ---------- ROW LEVEL SECURITY ----------
alter table public.hotels       enable row level security;
alter table public.profiles     enable row level security;
alter table public.guards       enable row level security;
alter table public.checkpoints  enable row level security;
alter table public.scans        enable row level security;

drop policy if exists p_hotels_sel  on public.hotels;
drop policy if exists p_hotels_upd  on public.hotels;
drop policy if exists p_profiles    on public.profiles;
drop policy if exists p_guards      on public.guards;
drop policy if exists p_ck          on public.checkpoints;
drop policy if exists p_scans       on public.scans;

create policy p_hotels_sel on public.hotels     for select to authenticated using (id = public.my_hotel());
create policy p_hotels_upd on public.hotels     for update to authenticated using (id = public.my_hotel());
create policy p_profiles   on public.profiles   for select to authenticated using (id = auth.uid());
create policy p_guards     on public.guards      for all   to authenticated using (hotel_id = public.my_hotel()) with check (hotel_id = public.my_hotel());
create policy p_ck         on public.checkpoints for all   to authenticated using (hotel_id = public.my_hotel()) with check (hotel_id = public.my_hotel());
create policy p_scans      on public.scans       for all   to authenticated using (hotel_id = public.my_hotel()) with check (hotel_id = public.my_hotel());

-- ---------- GUARD-SIDE RPCs (validated by PIN / session token) ----------
-- Manager creates a guard (hashes the PIN server-side)
create or replace function public.create_guard(p_name text, p_phone text, p_code text, p_pin text)
returns public.guards language plpgsql security definer set search_path = public, extensions as $$
declare g public.guards; h uuid;
begin
  h := public.my_hotel();
  if h is null then raise exception 'not a manager'; end if;
  insert into public.guards(hotel_id, name, phone, code, pin_hash)
    values (h, p_name, nullif(p_phone,''), upper(p_code), crypt(p_pin, gen_salt('bf')))
    returning * into g;
  return g;
end $$;

-- Guard signs in with code + PIN -> returns a session token
-- (drop first so re-running the full setup is safe even after the lockout
--  migration changes this function's return type to jsonb)
drop function if exists public.guard_login(text, text);
create or replace function public.guard_login(p_code text, p_pin text)
returns table(id uuid, name text, token text)
language plpgsql security definer set search_path = public as $$
declare g public.guards; tok text;
begin
  select * into g from public.guards
    where upper(code) = upper(p_code) and active and pin_hash = crypt(p_pin, pin_hash);
  if g.id is null then return; end if;
  tok := encode(gen_random_bytes(18), 'hex');
  update public.guards set session_token = public.sg_hash_token(tok), session_expires = now() + interval '12 hours' where id = g.id;
  return query select g.id, g.name, tok;
end $$;

-- Checkpoints the guard can scan
create or replace function public.guard_checkpoints(p_token text)
returns setof public.checkpoints language plpgsql security definer set search_path = public as $$
declare g public.guards;
begin
  select * into g from public.guards where session_token = public.sg_hash_token(p_token) and session_expires > now() and active;
  if g.id is null then raise exception 'invalid session'; end if;
  return query select * from public.checkpoints where hotel_id = g.hotel_id and active order by created_at;
end $$;

-- Record a scan (patrol or issue)
create or replace function public.record_scan(
  p_token text, p_checkpoint_id uuid, p_status text, p_note text,
  p_severity text, p_lat double precision, p_lng double precision, p_acc integer
) returns uuid language plpgsql security definer set search_path = public as $$
declare g public.guards; ck public.checkpoints; sid uuid;
begin
  select * into g from public.guards where session_token = public.sg_hash_token(p_token) and session_expires > now() and active;
  if g.id is null then raise exception 'invalid session'; end if;
  select * into ck from public.checkpoints where id = p_checkpoint_id and hotel_id = g.hotel_id;
  if ck.id is null then raise exception 'unknown checkpoint'; end if;
  insert into public.scans(hotel_id, checkpoint_id, guard_id, status, note, severity, lat, lng, gps_accuracy)
    values (g.hotel_id, ck.id, g.id, coalesce(p_status,'normal'), nullif(p_note,''), nullif(p_severity,''), p_lat, p_lng, p_acc)
    returning id into sid;
  return sid;
end $$;

grant execute on function public.create_guard(text,text,text,text)                                to authenticated;
grant execute on function public.guard_login(text,text)                                           to anon, authenticated;
grant execute on function public.guard_checkpoints(text)                                          to anon, authenticated;
grant execute on function public.record_scan(text,uuid,text,text,text,double precision,double precision,integer) to anon, authenticated;

-- Done. Next: create the first manager by signing up in the app.


-- ==========================================================
--  2. GEOFENCE
-- ==========================================================
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
-- Drop first: the base schema's record_scan returns uuid, and CREATE OR REPLACE
-- cannot change a function's return type.
drop function if exists public.record_scan(text,uuid,text,text,text,double precision,double precision,integer);
create or replace function public.record_scan(
  p_token text, p_checkpoint_id uuid, p_status text, p_note text,
  p_severity text, p_lat double precision, p_lng double precision, p_acc integer
) returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  g public.guards; ck public.checkpoints;
  dist double precision := null; thr int := 15; sid uuid; wgf boolean := null;
begin
  select * into g from public.guards where session_token = public.sg_hash_token(p_token) and session_expires > now() and active;
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


-- ==========================================================
--  3. HARDENING
-- ==========================================================
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

  select * into g from public.guards where session_token = public.sg_hash_token(p_token) and session_expires > now() and active;
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


-- ==========================================================
--  4. LOGIN LOCKOUT
-- ==========================================================
-- ============================================================
--  SENTINEL GUARD — guard login hardening (lockout + jsonb)
--  Stops PIN brute-force: 5 wrong tries locks the code for 15 min.
--  Paste into Supabase → SQL Editor → Run. Safe to re-run.
-- ============================================================

alter table public.guards add column if not exists failed_attempts integer not null default 0;
alter table public.guards add column if not exists locked_until timestamptz;

-- Return type changes (table -> jsonb), so drop the old one first.
drop function if exists public.guard_login(text, text);

create or replace function public.guard_login(p_code text, p_pin text)
returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare g public.guards; tok text; wait int; fails int; n_match int; n_code int;
begin
  -- Multi-tenant safe: guard codes may repeat across hotels that share one
  -- Supabase, so authenticate on code AND PIN together (never code alone).
  select count(*) into n_match
    from public.guards
   where upper(code) = upper(p_code) and active
     and pin_hash = crypt(p_pin, pin_hash);

  if n_match = 1 then
    select * into g
      from public.guards
     where upper(code) = upper(p_code) and active
       and pin_hash = crypt(p_pin, pin_hash)
     limit 1;
    -- respect an active lockout
    if g.locked_until is not null and g.locked_until > now() then
      wait := greatest(1, ceil(extract(epoch from (g.locked_until - now())) / 60));
      return jsonb_build_object('ok', false, 'reason', 'locked', 'minutes', wait);
    end if;
    tok := encode(gen_random_bytes(18), 'hex');           -- raw 144-bit token, returned to client only
    update public.guards
       set session_token = public.sg_hash_token(tok),     -- store ONLY the SHA-256 hash, never the raw token
           session_expires = now() + interval '12 hours',
           failed_attempts = 0, locked_until = null
     where id = g.id;
    return jsonb_build_object('ok', true, 'id', g.id, 'name', g.name, 'token', tok);

  elsif n_match > 1 then
    -- Same code AND PIN in two hotels: ambiguous. Refuse rather than risk
    -- logging the guard into the wrong hotel (fail-safe, no cross-tenant login).
    return jsonb_build_object('ok', false, 'reason', 'ambiguous');
  end if;

  -- Wrong PIN or unknown code. Apply the brute-force lockout ONLY when the code
  -- maps to exactly one active guard, so a failed attempt is attributable to a
  -- single hotel and can never lock another hotel's guard (no cross-tenant DoS).
  select count(*) into n_code
    from public.guards where upper(code) = upper(p_code) and active;

  if n_code = 1 then
    select * into g from public.guards where upper(code) = upper(p_code) and active limit 1;
    if g.locked_until is not null and g.locked_until > now() then
      wait := greatest(1, ceil(extract(epoch from (g.locked_until - now())) / 60));
      return jsonb_build_object('ok', false, 'reason', 'locked', 'minutes', wait);
    end if;
    fails := coalesce(g.failed_attempts, 0) + 1;
    update public.guards
       set failed_attempts = case when fails >= 5 then 0 else fails end,
           locked_until    = case when fails >= 5 then now() + interval '15 minutes' else locked_until end
     where id = g.id;
    if fails >= 5 then
      return jsonb_build_object('ok', false, 'reason', 'locked', 'minutes', 15);
    end if;
  end if;

  -- unknown code, or a colliding code with the wrong PIN: generic answer
  return jsonb_build_object('ok', false, 'reason', 'invalid');
end $$;

grant execute on function public.guard_login(text, text) to anon, authenticated;

-- Done. Guards keep their existing PINs; new guards you add get 6-digit PINs.


-- ==========================================================
--  5. REALTIME
-- ==========================================================
-- ============================================================
--  SENTINEL GUARD — enable instant live updates (Realtime)
--  Lets the manager dashboard update the moment a guard scans
--  or reports an issue, without reloading. Safe to re-run.
--  Paste into Supabase → SQL Editor → Run.
-- ============================================================

-- Add the two activity tables to Supabase's realtime publication.
do $$
begin
  begin execute 'alter publication supabase_realtime add table public.scans'; exception when duplicate_object then null; end;
  begin execute 'alter publication supabase_realtime add table public.security_flags'; exception when duplicate_object then null; end;
end $$;

-- (Row-Level Security still applies to realtime, so each manager only
--  ever receives changes for their own hotel.)


-- ==========================================================
--  6. AUDIT/ISOLATION FIXES
-- ==========================================================
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

  select * into g from public.guards where session_token = public.sg_hash_token(p_token) and session_expires > now() and active;
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
   where session_token = public.sg_hash_token(p_token);
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


-- ==========================================================
--  7. BRANDING
-- ==========================================================
-- ============================================================
--  SENTINEL GUARD — Hotel branding (name + logo set by owner)
--  Run ONCE in Supabase -> SQL Editor. Safe to re-run.
--
--  Adds a logo to each hotel, and lets YOU (the owner) set the
--  hotel name and logo when you create the manager account —
--  the manager just logs in and sees them.
-- ============================================================

-- 1) Logo column on each hotel (a URL or a data: URI)
alter table public.hotels add column if not exists logo_url text;

-- 2) When you create a manager, read the hotel name and logo you
--    put in the account's User Metadata:
--      { "hotel": "Grand Vista Hotel", "logo": "https://.../logo.png", "name": "Manager Name" }
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
declare h uuid;
begin
  insert into public.hotels(name, logo_url)
    values (
      coalesce(new.raw_user_meta_data->>'hotel', 'My Hotel'),
      nullif(new.raw_user_meta_data->>'logo', '')
    )
    returning id into h;
  insert into public.profiles(id, hotel_id, name)
    values (new.id, h, coalesce(new.raw_user_meta_data->>'name', new.email));
  return new;
end $$;

-- 3) Refresh API cache
notify pgrst, 'reload schema';

-- Done.
--
-- To set or change a logo/name for a hotel that already exists:
--   Supabase -> Table Editor -> hotels -> edit the row ->
--   set  name  and  logo_url  (paste an image URL or a data: URI).


-- ==========================================================
--  8. RESET PIN
-- ==========================================================
-- ============================================================
--  SENTINEL GUARD — Reset a guard's PIN
--  Run ONCE in Supabase -> SQL Editor. Safe to re-run.
--  Lets a manager set a new PIN for one of their guards
--  (PINs are hashed and can't be read back, so this is how you
--   recover access if a PIN is lost).
-- ============================================================

create or replace function public.set_guard_pin(p_guard_id uuid, p_pin text)
returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  update public.guards
     set pin_hash = crypt(p_pin, gen_salt('bf')),
         failed_attempts = 0,
         locked_until = null
   where id = p_guard_id and hotel_id = public.my_hotel();
  if not found then
    raise exception 'guard not found for this hotel';
  end if;
end $$;

grant execute on function public.set_guard_pin(uuid, text) to authenticated;

notify pgrst, 'reload schema';

-- Done.


-- ==========================================================
--  9. PHOTOS
-- ==========================================================
-- ============================================================
--  SENTINEL GUARD — Photo attached to a patrol report
--  Run ONCE in Supabase -> SQL Editor. Safe to re-run.
--  Adds an optional photo to record_scan; stored (compressed,
--  client-side) as a data URI in scans.photo_path.
-- ============================================================

-- Replace record_scan with a version that also accepts a photo.
drop function if exists public.record_scan(text,uuid,text,text,text,double precision,double precision,integer,timestamptz);

create or replace function public.record_scan(
  p_token text, p_checkpoint_id uuid, p_status text, p_note text,
  p_severity text, p_lat double precision, p_lng double precision, p_acc integer,
  p_scanned_at timestamptz default null, p_photo text default null
) returns jsonb language plpgsql security definer set search_path = public, extensions as $$
declare
  g public.guards; ck public.checkpoints;
  dist double precision := null; thr int; maxacc int; sid uuid; wgf boolean := null;
  ts timestamptz;
begin
  ts := coalesce(p_scanned_at, now());

  select * into g from public.guards where session_token = public.sg_hash_token(p_token) and session_expires > now() and active;
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

  insert into public.scans(hotel_id, checkpoint_id, guard_id, cp_name, guard_name, status, note, severity, lat, lng, gps_accuracy, within_geofence, scanned_at, photo_path)
    values (g.hotel_id, ck.id, g.id, ck.name, g.name, coalesce(p_status,'normal'), nullif(p_note,''), nullif(p_severity,''), p_lat, p_lng, p_acc, wgf, ts, nullif(p_photo,''))
    returning id into sid;

  return jsonb_build_object('ok', true, 'scan_id', sid, 'verified', wgf,
    'distance', case when dist is null then null else round(dist) end);
end $$;

grant execute on function public.record_scan(text,uuid,text,text,text,double precision,double precision,integer,timestamptz,text) to anon, authenticated;

notify pgrst, 'reload schema';

-- Done.


-- ==========================================================
--  10. FOLLOW-UPS
-- ==========================================================
-- ============================================================
--  SENTINEL GUARD — Issue follow-ups
--  Run ONCE in Supabase -> SQL Editor. Safe to re-run.
--  Lets a manager add dated follow-ups to an open issue, so an
--  ongoing problem shows its first-reported date, days open, and
--  every update — in the dashboard, PDF and Excel export.
-- ============================================================

create table if not exists public.issue_updates (
  id          uuid primary key default gen_random_uuid(),
  hotel_id    uuid not null references public.hotels(id) on delete cascade,
  scan_id     uuid references public.scans(id) on delete cascade,
  note        text,
  photo_path  text,
  created_at  timestamptz not null default now()
);

alter table public.issue_updates enable row level security;

drop policy if exists p_issue_updates on public.issue_updates;
create policy p_issue_updates on public.issue_updates
  for all to authenticated
  using (hotel_id = public.my_hotel())
  with check (hotel_id = public.my_hotel());

create index if not exists issue_updates_scan on public.issue_updates(scan_id, created_at);

notify pgrst, 'reload schema';

-- Done.


-- ==========================================================
--  11. GUARD FOLLOW-UPS
-- ==========================================================
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


-- ==========================================================
--  12. SECURE SESSION TOKENS AT REST (Issue #1A)
-- ==========================================================
-- ============================================================
--  SENTINEL GUARD — Secure guard session tokens at rest (Issue #1A)
--  Run ONCE in Supabase -> SQL Editor. Safe to re-run (idempotent).
--
--  guards.session_token now stores the SHA-256 hash of the bearer
--  token, NEVER the raw token. The raw token is returned to the
--  client at login only; every guard RPC hashes the incoming token
--  (public.sg_hash_token) before comparing. PIN bcrypt is unchanged.
--
--  NOTE: the hashing helper and the updated RPCs live in the other
--  migrations (db-setup / db-lockout / db-geofence / db-hardening /
--  db-fixes / db-photo / db-guard-followup) and are all included in
--  db-all.sql. This file documents the column and safely retires any
--  legacy RAW tokens left from before the change.
-- ============================================================

-- 8) Document the column.
comment on column public.guards.session_token is
  'SHA-256 hash (hex, 64 chars) of the guard bearer session token — NOT the raw token. The raw token is returned to the client at login only and is never stored.';

-- 7) Migration: invalidate any legacy RAW tokens still stored (they are 36 hex
--    chars, from gen_random_bytes(18)). New hashes are 64 hex chars. This forces
--    those guards to log in again rather than exposing or copying raw tokens.
--    Idempotent: rows already holding a 64-char hash (or NULL) are left untouched.
update public.guards
   set session_token = null, session_expires = null
 where session_token is not null
   and length(session_token) <> 64;

notify pgrst, 'reload schema';

-- Done. Existing guard sessions were invalidated; guards simply log in again.


notify pgrst, 'reload schema';
-- All set. Your Sentinel Guard database is ready.
