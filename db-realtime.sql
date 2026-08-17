-- ============================================================
--  SENTINEL GUARD — enable instant live updates (Realtime)
--  Lets the manager dashboard update the moment a guard scans
--  or reports an issue, without reloading. Safe to re-run.
--  Paste into Supabase → SQL Editor → Run.
-- ============================================================

-- Add the two activity tables to Supabase's realtime publication.
do $$
begin
  begin execute 'alter publication supabase_realtime add table public.scans'; exception when duplicate_object then null; end;
  begin execute 'alter publication supabase_realtime add table public.security_flags'; exception when duplicate_object then null; end;
end $$;

-- (Row-Level Security still applies to realtime, so each manager only
--  ever receives changes for their own hotel.)
