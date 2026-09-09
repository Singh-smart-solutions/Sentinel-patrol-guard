-- ============================================================
--  SENTINEL GUARD — Diagnose GPS / geofence enforcement
--  Read-only. Run in Supabase -> SQL Editor and share the output.
-- ============================================================

-- 1) Are your checkpoints GPS-calibrated, and what radius?
--    gps_set = false  => the app can't check distance, so it accepts
--    every scan and creates NO security flags for that checkpoint.
select
  name,
  zone,
  (lat is not null) as gps_set,
  lat, lng,
  coalesce(geofence_m, 15)    as radius_m,
  coalesce(max_accuracy_m, 30) as max_gps_error_m,
  active
from public.checkpoints
order by created_at;

-- 2) The last 15 scans — were they GPS-verified? (within_geofence = true
--    means the guard was confirmed on-site; null means the checkpoint had
--    no GPS set, so it wasn't checked.)
select
  s.scanned_at,
  c.name  as checkpoint,
  g.name  as guard,
  s.status,
  s.within_geofence,
  s.gps_accuracy,
  s.lat, s.lng
from public.scans s
left join public.checkpoints c on c.id = s.checkpoint_id
left join public.guards      g on g.id = s.guard_id
order by s.scanned_at desc nulls last
limit 15;

-- 3) The last 10 security flags (out-of-range / no-GPS attempts)
select created_at, checkpoint_name, guard_name, reason, distance_m
from public.security_flags
order by created_at desc
limit 10;
