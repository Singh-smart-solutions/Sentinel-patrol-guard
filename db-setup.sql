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
returns public.guards language plpgsql security definer set search_path = public as $$
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
create or replace function public.guard_login(p_code text, p_pin text)
returns table(id uuid, name text, token text)
language plpgsql security definer set search_path = public as $$
declare g public.guards; tok text;
begin
  select * into g from public.guards
    where upper(code) = upper(p_code) and active and pin_hash = crypt(p_pin, pin_hash);
  if g.id is null then return; end if;
  tok := encode(gen_random_bytes(18), 'hex');
  update public.guards set session_token = tok, session_expires = now() + interval '12 hours' where id = g.id;
  return query select g.id, g.name, tok;
end $$;

-- Checkpoints the guard can scan
create or replace function public.guard_checkpoints(p_token text)
returns setof public.checkpoints language plpgsql security definer set search_path = public as $$
declare g public.guards;
begin
  select * into g from public.guards where session_token = p_token and session_expires > now() and active;
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
  select * into g from public.guards where session_token = p_token and session_expires > now() and active;
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
