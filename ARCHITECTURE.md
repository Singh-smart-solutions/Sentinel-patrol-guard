# Sentinel Guard — Architecture & Data Model

A secure, no-install **web app (PWA)** for hotel security patrols. Guards open a link in any
phone browser, grant camera + location, scan a checkpoint QR, and confirm "all normal" or
report an issue with a photo. Managers manage guards and checkpoints and see every patrol live.

This document describes **what is actually built and deployed** — the single-file front end,
the two authentication models, the guard-session security design, server-side GPS verification,
the offline queue, and the Postgres schema that powers the multi-hotel backend.

---

## 1. Tech stack

### Frontend — a single self-contained file
- **`index.html`** is the entire app: vanilla JS, no build step, no framework. It bundles the
  **`qrcode`** generator, the **`jsQR`** reader, and **supabase-js** inline.
- **PWA**: `manifest.json` + **`sw.js`** service worker (network-first for the page, with an
  offline cache fallback). The cache name carries the app version (e.g. `sentinel-guard-v33`);
  bumping it on each release makes clients pick up the new build on next load.
- **Camera QR scan**: `getUserMedia` (rear camera) + **jsQR** decoding frames on a canvas.
- **GPS**: browser **Geolocation API** (`getCurrentPosition`, high accuracy).
- **Offline queue**: **IndexedDB** stores scans locally when offline and flushes them on
  reconnect (see §6).
- **`vercel.json`** rewrites `/test` → `index.html` (the real app lives at `/test`; the bare
  URL is a public demo).

### Backend — Supabase (Postgres)
- **Supabase**: Postgres + Auth + row-level security, reached directly from the browser with the
  **anon** public key. All privileged logic runs in **`SECURITY DEFINER` RPCs**, never in raw
  table writes from the client.
- **pgcrypto** for bcrypt PIN hashing (`crypt`/`gen_salt('bf')`) and SHA-256 token hashing
  (`digest(...,'sha256')`).
- **Realtime**: the manager dashboard subscribes to `scans` / `security_flags` so it updates live.

### Hosting
- **Vercel** (static front end, auto-deploys from `main`) + **Supabase** (Postgres/Auth).

---

## 2. Two authentication models

The app has **two completely separate** sign-in paths:

### Managers — Supabase Auth
- Email + password via Supabase Auth. A `profiles` row links each manager to their `hotel_id`.
- **Row-Level Security** scopes every table to `hotel_id = my_hotel()`, where `my_hotel()`
  resolves the signed-in manager's hotel from `auth.uid()`. One deployment serves many hotels
  with no cross-tenant leakage.

### Guards — custom code + PIN → opaque bearer token
Guards don't have email accounts. A manager issues each guard a **code** and a **PIN**.

1. `guard_login(code, pin)` verifies the **bcrypt** PIN and, on success, mints an **opaque
   144-bit bearer token** (`gen_random_bytes(18)`, 36 hex chars).
2. The database stores **only the SHA-256 hash** of that token in `guards.session_token`, with a
   **12-hour** `session_expires`. The raw token is returned to the browser **once**.
3. Every guard RPC takes the raw token and re-validates it server-side:
   `session_token = sha256(p_token) AND session_expires > now() AND active`. The guard's identity
   and `hotel_id` are **derived server-side from the token** — the client never supplies them.
4. **Brute-force lockout**: 5 wrong PINs lock that guard's code for 15 minutes. Lockout is applied
   only when a code maps to exactly one active guard, so it can never lock another hotel's guard.

Guard RPCs (all `SECURITY DEFINER`): `guard_checkpoints`, `record_scan`, `guard_open_issues`,
`guard_add_followup`, `guard_logout`. Manager RPCs: `create_guard` (returns only id/name/code —
never secrets), `set_guard_pin`.

> **Why not Supabase Auth for guards?** Guards share cheap phones and sign in dozens of times a
> shift with a short code + PIN; a full email/OAuth flow would be unusable on the floor. The
> custom token model keeps that UX while the hardening below keeps it safe.

---

## 3. Guard-session security

The raw token is a full credential, so the design minimises where it lives and how long it lasts:

- **Hashed at rest (#1A).** `guards.session_token` holds `SHA-256(token)`, never the raw token.
  A leaked database row cannot be replayed.
- **Secrets hidden from managers (#1B).** Column-level privileges `REVOKE SELECT` on the auth
  columns (`pin_hash`, `session_token`, `session_expires`, `failed_attempts`, `locked_until`)
  from `anon`/`authenticated`; managers can read only `id, hotel_id, name, phone, code, active,
  created_at`. The `SECURITY DEFINER` RPCs still see every column.
- **No credentials in the offline queue (#1C-A).** The IndexedDB queue stores **scan data only**.
  At flush time the token is read from the **in-memory** guard session; if there's no valid
  session, queued scans stay pending rather than being sent with a stale credential.
- **PIN reset revokes sessions (#1C-B).** `set_guard_pin` clears `session_token` and
  `session_expires` in the **same transaction** as the PIN change, so a compromised token dies
  immediately.
- **Deactivation revokes sessions.** A trigger clears the token when a guard is set `active = false`.

The live session is kept in memory and persisted in `localStorage["sg_guard"]` (`{id, name,
token}`) so a guard who reopens the app within 12 hours is restored **after** the server
re-validates the token; an expired or revoked token drops straight to the login screen.

---

## 4. GPS location-locking (anti-cheat)

Goal: prove the guard is **physically at the checkpoint**, not scanning a printed photo from home.
All of this is enforced **server-side** inside `record_scan`:

1. On scan, the app captures **latitude, longitude, accuracy (m)** and the device scan time.
2. Each checkpoint stores its own **lat/lng**, a **geofence radius** `geofence_m` (default **15 m**),
   and a **max GPS accuracy** `max_accuracy_m` (default **30 m**).
3. The server computes the **Haversine distance** (`distance_m`) between the scan and the
   checkpoint. Out of range, missing GPS, or poor/suspicious accuracy → the scan is **rejected and
   logged to `security_flags`** with a reason (`geofence` / `no_gps` / `accuracy`) for the manager.
4. `record_scan` returns JSON (`{ ok, reason?, distance?, threshold?, scan_id?, verified? }`) so
   the guard sees exactly why a check-in was refused.

> GPS requires **HTTPS** (Vercel provides it) and the guard granting location permission.

---

## 5. Photos

Issue reports can carry a photo. It is **compressed client-side** (JPEG, scaled down) and stored
**inline as a data-URI** in `scans.photo_path` — there is no separate object store to configure.
The manager dashboard and PDF report render it from that column.

---

## 6. Offline fallback

Hotels have dead zones (basement parking, concrete stairwells). The app must never lose a scan.

1. The **service worker** caches the app shell, so the app **opens even with no signal**.
2. A scan made offline is written to **IndexedDB** (database `sentinel-guard`, store `queue`).
   The queue holds **scan data only — no token, PIN, or any credential** (see §3).
3. On reconnect (the `online` event) and on app boot, `flushQueue()` submits the queued scans via
   `record_scan`, authenticating with the **current in-memory token**. Successfully synced items
   are deleted from the queue; repeated server failures are surfaced to the guard, never dropped
   silently.

> This uses an on-reconnect flush (not the Background Sync API), which keeps behaviour predictable
> across the basic browsers guards use.

---

## 7. QR codes

- **Generate**: each checkpoint has a `code`; its QR encodes `…/test?cp=<code>`. Managers print a
  **single** code, or **all codes at once** — a bulk sheet laid out **12 per A4 page** (3 across),
  each card with name/code/zone and a dashed cut-line, so 50+ checkpoints print in one job.
- **Scan**: guards point the rear camera; **jsQR** decodes the frame and the app resolves the
  checkpoint, then runs the GPS check in §4.

---

## 8. Database schema (PostgreSQL)

Core tables (all scoped to `hotel_id`, RLS enabled; the full DDL lives in `db-all.sql`):

- **`hotels`** — one row per hotel (multi-tenant root).
- **`profiles`** — manager ↔ hotel link (`id` = `auth.users.id`, `hotel_id`).
- **`guards`** — `code`, `pin_hash` (bcrypt), `session_token` (SHA-256 of the bearer token),
  `session_expires`, `failed_attempts`, `locked_until`, `active`, `hotel_id`.
- **`checkpoints`** — `name`, `zone`, `code`, `lat`, `lng`, `geofence_m` (default 15),
  `max_accuracy_m` (default 30), `active`, `hotel_id`.
- **`scans`** — `checkpoint_id`, `guard_id`, `status` (`normal`/`issue`), `note`, `severity`,
  `photo_path`, `lat`, `lng`, `gps_accuracy`, `within_geofence`, `scanned_at`, `resolved`, `hotel_id`.
- **`security_flags`** — audit of refused/suspicious check-ins (reason, distance, accuracy, where).
- **`issue_updates`** — follow-up notes/photos a guard adds to an open issue.

Privileged access is funnelled through `SECURITY DEFINER` RPCs (listed in §2); clients never
write these tables directly. Helper functions: `my_hotel()`, `sg_hash_token()`, `distance_m()`.

### Row-level security
Every table has `hotel_id` and RLS enabled. Manager-facing policies use
`hotel_id = my_hotel()`; guard access goes exclusively through the token-validated RPCs, which
derive the hotel server-side. The result: one deployment safely serves many hotels, and a guard
token is useless outside its own hotel's data.

---

## 9. Why a web app (not native)

- **Zero install**: guards open a bookmarked link in Safari/Chrome — works on any basic phone.
- **Instant updates**: push to `main` → Vercel redeploys → every guard gets it on next refresh
  (the versioned service-worker cache triggers the update).
- **Lower cost**: one responsive codebase vs. separate iOS + Android apps.
- Still gets camera, GPS, offline caching and "install to home screen" via PWA APIs.

---

*Sentinel Guard · Singh Smart Solutions · satnamsingh.dev*
