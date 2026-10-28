# Sentinel Guard — Hotel Security Patrol

A single-file web app for hotel security patrols.

- **Guards** sign in with a PIN, scan checkpoint QR codes (camera), confirm "all normal" or report an issue with a photo.
- **Managers** add/remove guards, generate & print checkpoint QR codes — one at a time or **all at once** (12 per A4 page, with cut lines) — and see every patrol and issue report live.

Self-contained `index.html` (QR generator + reader bundled). Deploy as a static site — no build step.
