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
