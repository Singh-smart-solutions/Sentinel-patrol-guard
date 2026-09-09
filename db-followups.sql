-- ============================================================
--  SENTINEL GUARD — Issue follow-ups
--  Run ONCE in Supabase -> SQL Editor. Safe to re-run.
--  Lets a manager add dated follow-ups to an open issue, so an
--  ongoing problem shows its first-reported date, days open, and
--  every update — in the dashboard, PDF and Excel export.
-- ============================================================

create table if not exists public.issue_updates (
  id          uuid primary key default gen_random_uuid(),
  hotel_id    uuid not null references public.hotels(id) on delete cascade,
  scan_id     uuid references public.scans(id) on delete cascade,
  note        text,
  photo_path  text,
  created_at  timestamptz not null default now()
);

alter table public.issue_updates enable row level security;

drop policy if exists p_issue_updates on public.issue_updates;
create policy p_issue_updates on public.issue_updates
  for all to authenticated
  using (hotel_id = public.my_hotel())
  with check (hotel_id = public.my_hotel());

create index if not exists issue_updates_scan on public.issue_updates(scan_id, created_at);

notify pgrst, 'reload schema';

-- Done.
