# K.K.C Dairy — दूध डायरी

Milk centre daily ledger. Admin records per-person morning/night milk volumes; each person logs in with a **personal code** and sees only their own diary. Recipients (buyers) and suppliers (givers) both have diaries, each with their own ₹/L rate.

## How it works
- **Login** — admin enters a personal code (3 seeded admins). A recipient/supplier enters their diary code.
- **Daily entry** — admin picks a person, date, morning litres, night litres, and **must** choose Paid/Unpaid (red/green). Amount = litres × role rate, frozen at entry time.
- **Ledger** — month view: total litres, total amount, paid, and balance due (green = fully paid, red = due).
- **Rates** — admin sets ₹/L for recipients and suppliers; changeable anytime.

## Tech
- Single-file front-end (`index.html`) — no build step, no external JS.
- Supabase backend: tables + RPC functions only (**no Edge Functions**). Auth via personal codes (hashed+salted).
- Hindi-primary UI with English toggle.

## Files
- `index.html` — the app (login, admin panel, person diary).
- `supabase/schema.sql` — full schema (tables, RLS, RPC functions, 3 seeded admins).

## Setup (Supabase dashboard)
1. Create a Supabase project.
2. Open **SQL Editor** and paste the entire contents of `supabase/schema.sql`. Run it.
3. In `index.html`, set `SB_URL` and `SB_KEY` (the publishable anon key) near the top of the `<script>`.
4. Host `index.html` on any static host (GitHub Pages / Netlify).
5. Add people as admin; give each their generated personal code (shown once on creation).

## Admin & personal codes
- Codes are stored **hashed+salted** in the DB. Plaintext codes are shown **once** when a person is created.
- The 3 seed admins in `schema.sql` have pre-generated codes (stored hashed). If you lose them, re-seed or add new admins.

## Security notes
- All data access goes through RPC functions that verify a session token server-side. Direct table access is revoked for the anon role.
- RLS is enabled on all tables.
