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
declare g public.guards; tok text; wait int; fails int;
begin
  select * into g from public.guards where upper(code) = upper(p_code) and active order by created_at limit 1;
  -- unknown code: same generic answer, no hint about what was wrong
  if g.id is null then
    return jsonb_build_object('ok', false, 'reason', 'invalid');
  end if;

  -- currently locked?
  if g.locked_until is not null and g.locked_until > now() then
    wait := greatest(1, ceil(extract(epoch from (g.locked_until - now())) / 60));
    return jsonb_build_object('ok', false, 'reason', 'locked', 'minutes', wait);
  end if;

  -- correct PIN
  if g.pin_hash = crypt(p_pin, g.pin_hash) then
    tok := encode(gen_random_bytes(18), 'hex');
    update public.guards
       set session_token = tok, session_expires = now() + interval '12 hours',
           failed_attempts = 0, locked_until = null
     where id = g.id;
    return jsonb_build_object('ok', true, 'id', g.id, 'name', g.name, 'token', tok);
  end if;

  -- wrong PIN: count the failure, lock after 5
  fails := coalesce(g.failed_attempts, 0) + 1;
  update public.guards
     set failed_attempts = case when fails >= 5 then 0 else fails end,
         locked_until    = case when fails >= 5 then now() + interval '15 minutes' else locked_until end
   where id = g.id;
  if fails >= 5 then
    return jsonb_build_object('ok', false, 'reason', 'locked', 'minutes', 15);
  end if;
  return jsonb_build_object('ok', false, 'reason', 'invalid');
end $$;

grant execute on function public.guard_login(text, text) to anon, authenticated;

-- Done. Guards keep their existing PINs; new guards you add get 6-digit PINs.
