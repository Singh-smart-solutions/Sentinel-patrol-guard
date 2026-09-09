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
