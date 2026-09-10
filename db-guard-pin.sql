-- ============================================================
--  SENTINEL GUARD — Reset a guard's PIN (Issue #1C-B)
--  Run ONCE in Supabase -> SQL Editor. Safe to re-run.
--  Lets a manager set a new PIN for one of their guards
--  (PINs are hashed and can't be read back, so this is how you
--   recover access if a PIN is lost).
--
--  A PIN reset now ALSO revokes the guard's current session in the
--  SAME transaction: session_token and session_expires are cleared, so
--  any bearer token issued before the reset (e.g. a compromised one)
--  stops working immediately. The guard must sign in again with the new
--  PIN to obtain a fresh token. Hotel isolation is enforced via
--  my_hotel(); the function returns void so no PIN/session secret leaks.
-- ============================================================

-- Drop first so this migration also upgrades an OLDER set_guard_pin whose
-- parameter was named differently: CREATE OR REPLACE cannot rename an existing
-- function's input parameters and would fail with "cannot change name of input
-- parameter". Dropping by signature and recreating avoids that.
drop function if exists public.set_guard_pin(uuid, text);
create or replace function public.set_guard_pin(p_guard_id uuid, p_pin text)
returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  update public.guards
     set pin_hash        = crypt(p_pin, gen_salt('bf')),
         session_token   = null,   -- Issue #1C-B: revoke any active bearer token
         session_expires = null,   -- Issue #1C-B: and its expiry
         failed_attempts = 0,
         locked_until    = null
   where id = p_guard_id and hotel_id = public.my_hotel();
  if not found then
    raise exception 'guard not found for this hotel';
  end if;
end $$;

grant execute on function public.set_guard_pin(uuid, text) to authenticated;

notify pgrst, 'reload schema';

-- Done.
