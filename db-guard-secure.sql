-- ============================================================
--  SENTINEL GUARD — Protect guard auth secrets from managers (Issue #1B)
--  Run ONCE in Supabase -> SQL Editor. Safe to re-run (idempotent).
--
--  Managers may read/manage normal guard info, but the database must
--  NEVER hand them the authentication/security columns:
--     pin_hash, session_token, session_expires, failed_attempts, locked_until
--
--  Enforcement is column-level: the authenticated role's table-wide SELECT
--  on public.guards is removed and replaced with SELECT on ONLY the safe
--  columns. RLS is unchanged (still filters rows to the manager's hotel),
--  and the SECURITY DEFINER auth functions (which run as the table owner)
--  keep full internal access to every column. anon gets no direct SELECT
--  at all — guards reach data only through the definer RPCs.
--
--  (create_guard was also changed to return jsonb with only id/name/code,
--   so the RPC response can never carry pin_hash or session_token — see
--   db-setup.sql.)
-- ============================================================

-- Remove any table-wide SELECT the roles may have (Supabase grants it by default).
revoke select on public.guards from anon;
revoke select on public.guards from authenticated;

-- Give managers SELECT on ONLY the non-sensitive columns.
grant select (id, hotel_id, name, phone, code, active, created_at)
  on public.guards to authenticated;

-- INSERT / UPDATE / DELETE privileges are intentionally left as-is so existing
-- manager guard management (e.g. removing a guard) keeps working under RLS.
-- Column-level privileges also block a manager from returning secret columns
-- via UPDATE ... RETURNING / DELETE ... RETURNING.

comment on column public.guards.pin_hash        is 'AUTH SECRET — bcrypt PIN hash. Not selectable by anon/authenticated; auth RPCs only.';
comment on column public.guards.session_token   is 'AUTH SECRET — SHA-256 of the bearer token (see Issue #1A). Not selectable by anon/authenticated; auth RPCs only.';
comment on column public.guards.session_expires is 'AUTH internal — session expiry. Not selectable by anon/authenticated; auth RPCs only.';
comment on column public.guards.failed_attempts is 'AUTH internal — lockout counter. Not selectable by anon/authenticated; auth RPCs only.';
comment on column public.guards.locked_until    is 'AUTH internal — lockout timestamp. Not selectable by anon/authenticated; auth RPCs only.';

notify pgrst, 'reload schema';

-- Done. Managers can read id/name/phone/code/active/created_at only.
