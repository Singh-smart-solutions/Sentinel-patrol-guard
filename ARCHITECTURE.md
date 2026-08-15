# Sentinel Guard — Architecture & Data Model

A secure, no-install **web app (PWA)** for hotel security patrols. Guards open a link in any
phone browser, grant camera + location, scan a checkpoint QR, and confirm "all normal" or
report an issue with a photo. Managers manage guards and checkpoints and see every patrol live.

This document describes the production tech stack, the GPS-verification and offline mechanics,
and the database schema. (The current single-file `index.html` is a front-end demo that stores
data in the browser; the schema below is what powers the real multi-hotel version.)

---

## 1. Tech stack

### Frontend (the guard/manager app)
- **React + Vite** (or **Next.js**) — responsive, mobile-first UI.
- **PWA**: web app manifest + **service worker** (via Workbox) → installable, works offline.
- **Camera QR scan**: `getUserMedia` (rear camera) + **jsQR** decoding frames on a canvas.
- **GPS**: browser **Geolocation API** (`getCurrentPosition`, high accuracy).
- **Offline queue**: **IndexedDB** stores scans/photos locally when offline; **Background Sync**
  flushes them to the API when connectivity returns.

### Backend (API + auth)
- **Supabase** (recommended — fastest path): Postgres + Auth + Storage + row-level security,
  or a **Node.js** API (Next.js API routes / Express) if you prefer to self-host.
- **Auth**: staff accounts with roles (`manager`, `guard`); managers create/disable guard logins.
- **Storage**: incident photos in **Supabase Storage** (or S3), referenced by URL in the DB.
- **Realtime** (optional): Supabase realtime so the manager dashboard updates live.

### Database
- **PostgreSQL** — relational, with **row-level security** scoping every row to its `hotel_id`
  (multi-tenant: one deployment can serve many hotels safely).

### Hosting
- **Vercel** (frontend) + **Supabase** (backend/DB/storage). Both have generous free tiers.

---

## 2. GPS location-locking (anti-cheat)

Goal: prove the guard is **physically at the checkpoint**, not scanning a printed photo from home.

1. When a QR is scanned, the app calls `getCurrentPosition` and captures
   **latitude, longitude, and accuracy (metres)** alongside the scan time.
2. Each checkpoint stores its own **lat/lng** and a **geofence radius** (e.g. 50 m).
3. The server computes the distance between the scan location and the checkpoint location
   (Haversine). If it's within the radius → `within_geofence = true`; otherwise the scan is
   **flagged** for the manager to review.
4. Accuracy is stored too — a scan with poor accuracy (e.g. ±500 m) can be treated as unverified.

> Note: GPS requires **HTTPS** (Vercel provides it) and the user granting location permission.

---

## 3. Offline fallback (PWA sync)

Hotels have dead zones (basement parking, concrete stairwells). The app must never lose a scan.

1. The **service worker** caches the app shell, so the app **opens even with no signal**.
2. A scan made offline is written to **IndexedDB** with `created_offline = true` and no `synced_at`.
   The photo is stored locally too (as a blob).
3. When the device is back on Wi-Fi/5G, **Background Sync** (or an on-reconnect flush) POSTs the
   queued scans + uploads photos to the API, and the server stamps `synced_at`.
4. The manager dashboard shows each scan's sync state, so nothing is silently missing.

---

## 4. Database schema (PostgreSQL)

```sql
-- One row per hotel (multi-tenant). Every other table scopes to hotel_id via RLS.
create table hotels (
  id           uuid primary key default gen_random_uuid(),
  name         text not null,
  timezone     text not null default 'Asia/Dubai',
  created_at   timestamptz not null default now()
);

-- Staff accounts: managers and guards. Managers create/disable guard logins.
create table users (
  id           uuid primary key default gen_random_uuid(),
  hotel_id     uuid not null references hotels(id) on delete cascade,
  name         text not null,
  phone        text,
  role         text not null check (role in ('manager','guard')),
  pin_hash     text,                       -- hashed guard PIN (never store plain)
  active       boolean not null default true,
  created_at   timestamptz not null default now()
);

-- Physical checkpoints. Each has a QR (encodes qr_token) and its own GPS position.
create table checkpoints (
  id                uuid primary key default gen_random_uuid(),
  hotel_id          uuid not null references hotels(id) on delete cascade,
  name              text not null,                 -- "Main Lobby"
  zone              text,                           -- "Front of House"
  code              text not null,                  -- "LOBBY-01" (unique per hotel)
  qr_token          text not null,                  -- random token embedded in the QR
  lat               double precision,               -- checkpoint's known location
  lng               double precision,
  geofence_radius_m integer not null default 50,
  active            boolean not null default true,
  created_at        timestamptz not null default now(),
  unique (hotel_id, code)
);

-- Optional: group scans into a patrol round.
create table patrol_rounds (
  id           uuid primary key default gen_random_uuid(),
  hotel_id     uuid not null references hotels(id) on delete cascade,
  guard_id     uuid not null references users(id),
  started_at   timestamptz not null default now(),
  ended_at     timestamptz
);

-- The core record: one row every time a guard scans a checkpoint.
create table scans (
  id               uuid primary key default gen_random_uuid(),
  hotel_id         uuid not null references hotels(id) on delete cascade,
  checkpoint_id    uuid not null references checkpoints(id),
  guard_id         uuid not null references users(id),
  round_id         uuid references patrol_rounds(id),
  scanned_at       timestamptz not null,           -- when the guard scanned (device time)
  status           text not null check (status in ('normal','issue')),
  note             text,
  lat              double precision,               -- captured GPS
  lng              double precision,
  gps_accuracy_m   integer,
  within_geofence  boolean,                         -- computed server-side
  device_id        text,
  created_offline  boolean not null default false,
  synced_at        timestamptz,                     -- null until synced from offline queue
  created_at       timestamptz not null default now()
);

-- Issue reports (photo + severity). One-to-one with an 'issue' scan.
create table incidents (
  id            uuid primary key default gen_random_uuid(),
  hotel_id      uuid not null references hotels(id) on delete cascade,
  scan_id       uuid not null references scans(id) on delete cascade,
  checkpoint_id uuid not null references checkpoints(id),
  guard_id      uuid not null references users(id),
  severity      text not null check (severity in ('low','medium','high')),
  description   text not null,
  photo_url     text,                               -- Supabase Storage / S3 URL
  resolved      boolean not null default false,
  resolved_by   uuid references users(id),
  resolved_at   timestamptz,
  created_at    timestamptz not null default now()
);

-- Helpful indexes
create index on scans (hotel_id, scanned_at desc);
create index on scans (checkpoint_id, scanned_at desc);
create index on incidents (hotel_id, resolved, created_at desc);
```

### Row-level security (essential for multi-hotel)
Every table has `hotel_id`. Enable RLS and add policies so a user can only read/write rows for
**their own hotel**, and guards can only write their own scans. Example policy sketch:

```sql
alter table scans enable row level security;
create policy scans_same_hotel on scans
  using (hotel_id = auth.jwt() ->> 'hotel_id');
```

---

## 5. Why a web app (not native)

- **Zero install**: guards open a bookmarked link in Safari/Chrome — works on any basic phone.
- **Instant updates**: fix a bug or add a feature → every guard gets it on next refresh.
- **Lower cost**: one responsive codebase vs. separate iOS + Android apps.
- Still gets camera, GPS, offline caching and "install to home screen" via PWA APIs.

---

*Sentinel Guard · Singh Smart Solutions · satnamsingh.dev*
