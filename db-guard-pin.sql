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
