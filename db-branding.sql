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
