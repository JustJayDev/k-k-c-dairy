-- ============================================================
-- K.K.C Dairy — Milk Centre Ledger schema
-- Stack: tables + RPC functions only (NO Edge Functions)
-- Auth: personal codes (hashed+salted) -> session token.
--       Every RPC validates the token server-side.
-- ============================================================

-- ---------- 1. PEOPLE (recipients + suppliers) ----------
create table if not exists public.people (
  id            uuid primary key default gen_random_uuid(),
  name          text not null,
  role          text not null check (role in ('recipient','supplier')),
  code_hash     text not null,
  code_salt     text not null,
  session_token text,
  created_at    timestamptz not null default now()
);

-- ---------- 2. ADMINS (3 seeded) ----------
create table if not exists public.admins (
  id            uuid primary key default gen_random_uuid(),
  name          text not null,
  code_hash     text not null,
  code_salt     text not null,
  session_token text,
  created_at    timestamptz not null default now()
);

-- Seed the 3 admins (codes stored hashed; plaintext NOT in DB)
-- Idempotent: unique on name so reruns never create duplicates.
create unique index if not exists admins_name_uidx on public.admins(name);
delete from public.admins a using public.admins b
 where a.id > b.id and a.name = b.name;
insert into public.admins (name, code_hash, code_salt) values
  ('JustJayDev', '27b478e24196582c9c2753d921d1ddbc76c4bd8367548991d7fc82e243c8e0e9', 'd77b5cd6aaabc700'),
  ('Owner',      '80c116e82210b316ec10fa80fe1ada4c25c4d4511596eeda51f922186b7f5751', '72b61e470b8ff3d5'),
  ('Worker',     '231dbadbded3599c5a7c5696e822ec3aecf6da95b58e927274d09838f654511a', '3db0dacee9c97cea')
on conflict (name) do nothing;

-- ---------- 3. SETTINGS (single row, id=1) ----------
create table if not exists public.settings (
  id            int primary key check (id = 1),
  recipient_rate numeric not null default 0,
  supplier_rate   numeric not null default 0,
  updated_at    timestamptz not null default now()
);
insert into public.settings (id) values (1) on conflict do nothing;

-- ---------- 4. ENTRIES (daily deliveries) ----------
create table if not exists public.entries (
  id          uuid primary key default gen_random_uuid(),
  person_id   uuid not null references public.people(id) on delete cascade,
  entry_date  date not null,
  morning     numeric(6,2) not null default 0,   -- morning litres
  night       numeric(6,2) not null default 0,   -- night litres
  amount      numeric(10,2) not null default 0,  -- frozen at entry time (litres * role rate)
  paid        boolean not null,                  -- REQUIRED: red=false / green=true
  recorded_by text,
  created_at  timestamptz not null default now(),
  unique (person_id, entry_date)
);

-- ---------- 5. RLS: lock everything down, expose via RPC only ----------
alter table public.people   enable row level security;
alter table public.admins    enable row level security;
alter table public.settings  enable row level security;
alter table public.entries   enable row level security;

-- No direct SELECT/INSERT/UPDATE on any table for anon role.
-- All access goes through the RPC functions below.
revoke all on public.people, public.admins, public.settings, public.entries from anon;

-- ============================================================
-- HELPERS
-- ============================================================
create or replace function public.gen_token() returns text language sql as $$
  select encode(gen_random_bytes(24), 'hex')
$$;

create or replace function public.hash_code(code text, salt text) returns text language sql as $$
  select encode(digest(code || salt, 'sha256'), 'hex')
$$;

-- ============================================================
-- AUTH RPCs
-- ============================================================

-- Login as admin. Returns admin profile + fresh session token.
create or replace function public.login_admin(p_code text)
returns table (id uuid, name text, token text)
language plpgsql security definer as $$
declare v_adm public.admins;
begin
  select * into v_adm from public.admins
   where code_hash = public.hash_code(p_code, code_salt);
  if v_adm.id is null then
    raise exception 'AUTH_FAILED';
  end if;
  -- rotate token
  update public.admins set session_token = public.gen_token()
   where id = v_adm.id
   returning session_token into v_adm.session_token;
  return query select v_adm.id, v_adm.name, v_adm.session_token;
end $$;

-- Login as a person (recipient/supplier). Returns profile + token.
create or replace function public.login_person(p_code text)
returns table (id uuid, name text, role text, token text)
language plpgsql security definer as $$
declare v_ppl public.people;
begin
  select * into v_ppl from public.people
   where code_hash = public.hash_code(p_code, code_salt);
  if v_ppl.id is null then
    raise exception 'AUTH_FAILED';
  end if;
  update public.people set session_token = public.gen_token()
   where id = v_ppl.id
   returning session_token into v_ppl.session_token;
  return query select v_ppl.id, v_ppl.name, v_ppl.role, v_ppl.session_token;
end $$;

-- Verify a person token -> person id, or null
create or replace function public.who_person(p_token text)
returns uuid language sql security definer stable as $$
  select id from public.people where session_token = p_token
$$;

-- Verify an admin token -> admin id, or null
create or replace function public.who_admin(p_token text)
returns uuid language sql security definer stable as $$
  select id from public.admins where session_token = p_token
$$;

-- ============================================================
-- ADMIN RPCs (all require valid admin token)
-- ============================================================

-- Create a person. Generates a fresh 8-char code server-side,
-- stores only the hash, returns the plaintext code ONCE.
create or replace function public.admin_create_person(
  p_token text, p_name text, p_role text
) returns table (id uuid, name text, role text, code text)
language plpgsql security definer as $$
declare
  v_aid uuid := public.who_admin(p_token);
  v_pid uuid;
  v_code text;
  v_salt text;
begin
  if v_aid is null then raise exception 'ADMIN_REQUIRED'; end if;
  if p_name is null or btrim(p_name) = '' then raise exception 'NAME_REQUIRED'; end if;
  if p_role not in ('recipient','supplier') then raise exception 'BAD_ROLE'; end if;

  v_code  := upper(substr(md5(gen_random_uuid()::text), 1, 8));
  v_salt := encode(gen_random_bytes(8), 'hex');

  insert into public.people (name, role, code_hash, code_salt)
  values (btrim(p_name), p_role, public.hash_code(v_code, v_salt), v_salt)
  returning id into v_pid;

  return query select v_pid, btrim(p_name), p_role, v_code;
end $$;

-- Set rates (₹/L for recipients and suppliers)
create or replace function public.admin_set_rates(
  p_token text, p_recipient numeric, p_supplier numeric
) returns table (recipient_rate numeric, supplier_rate numeric, updated_at timestamptz)
language plpgsql security definer as $$
declare v_aid uuid := public.who_admin(p_token);
begin
  if v_aid is null then raise exception 'ADMIN_REQUIRED'; end if;
  if p_recipient is null or p_supplier is null or p_recipient < 0 or p_supplier < 0
  then raise exception 'BAD_RATE'; end if;
  update public.settings set
    recipient_rate = p_recipient,
    supplier_rate  = p_supplier,
    updated_at = now()
  where id = 1;
  return query select recipient_rate, supplier_rate, updated_at from public.settings where id = 1;
end $$;

-- Add a daily entry. `p_paid` is REQUIRED (no default).
-- Amount = (morning+night) x role rate, frozen now.
create or replace function public.admin_add_entry(
  p_token text, p_person_id uuid, p_date date,
  p_morning numeric, p_night numeric, p_paid boolean
) returns table (id uuid, person_id uuid, entry_date date, morning numeric, night numeric, amount numeric, paid boolean)
language plpgsql security definer as $$
declare
  v_aid uuid := public.who_admin(p_token);
  v_rate numeric;
  v_role text;
  v_amount numeric;
begin
  if v_aid is null then raise exception 'ADMIN_REQUIRED'; end if;
  if p_person_id is null then raise exception 'PERSON_REQUIRED'; end if;
  if p_date is null then raise exception 'DATE_REQUIRED'; end if;
  if p_paid is null then raise exception 'PAID_REQUIRED'; end if;
  if p_morning is null or p_night is null or p_morning < 0 or p_night < 0
  then raise exception 'BAD_QUANTITY'; end if;
  select role into v_role from public.people where id = p_person_id;
  if v_role is null then raise exception 'PERSON_NOT_FOUND'; end if;
  select case when v_role = 'recipient' then recipient_rate else supplier_rate end
    into v_rate from public.settings where id = 1;
  v_amount := coalesce(p_morning,0) + coalesce(p_night,0);
  v_amount := round(v_amount * v_rate, 2);
  return query
  insert into public.entries (person_id, entry_date, morning, night, amount, paid, recorded_by)
  values (p_person_id, p_date, coalesce(p_morning,0), coalesce(p_night,0), v_amount, p_paid,
          (select name from public.admins where id = v_aid))
  returning id, person_id, entry_date, morning, night, amount, paid;
end $$;

-- Update an entry (admin)
create or replace function public.admin_update_entry(
  p_token text, p_entry_id uuid, p_morning numeric, p_night numeric, p_paid boolean
) returns table (id uuid, person_id uuid, entry_date date, morning numeric, night numeric, amount numeric, paid boolean)
language plpgsql security definer as $$
declare
  v_aid uuid := public.who_admin(p_token);
  v_person uuid;
  v_role text;
  v_rate numeric;
  v_amount numeric;
begin
  if v_aid is null then raise exception 'ADMIN_REQUIRED'; end if;
  if p_entry_id is null then raise exception 'ENTRY_REQUIRED'; end if;
  if p_paid is null then raise exception 'PAID_REQUIRED'; end if;

  select person_id into v_person from public.entries where id = p_entry_id;
  if v_person is null then raise exception 'ENTRY_NOT_FOUND'; end if;

  select role into v_role from public.people where id = v_person;
  select case when v_role = 'recipient' then recipient_rate else supplier_rate end
    into v_rate from public.settings where id = 1;

  v_amount := round((coalesce(p_morning,0) + coalesce(p_night,0)) * v_rate, 2);

  return query
  update public.entries set
    morning = coalesce(p_morning,0),
    night  = coalesce(p_night,0),
    amount = v_amount,
    paid   = p_paid,
    recorded_by = (select name from public.admins where id = v_aid)
  where id = p_entry_id
  returning id, person_id, entry_date, morning, night, amount, paid;
end $$;

-- Delete an entry (admin)
create or replace function public.admin_delete_entry(p_token text, p_entry_id uuid)
returns text language plpgsql security definer as $$
declare v_aid uuid := public.who_admin(p_token);
begin
  if v_aid is null then raise exception 'ADMIN_REQUIRED'; end if;
  delete from public.entries where id = p_entry_id;
  return 'ok';
end $$;

-- Get all people (admin)
create or replace function public.admin_get_people(p_token text)
returns table (id uuid, name text, role text)
language sql security definer stable as $$
  select p.id, p.name, p.role from public.people p
   where public.who_admin(p_token) is not null
   order by p.name
$$;

-- Get all entries (admin), with person name + role joined
create or replace function public.admin_get_entries(p_token text)
returns table (id uuid, person_id uuid, person_name text, role text, entry_date date,
              morning numeric, night numeric, amount numeric, paid boolean, recorded_by text)
language sql security definer stable as $$
  select e.id, e.person_id, p.name, p.role, e.entry_date,
         e.morning, e.night, e.amount, e.paid, e.recorded_by
    from public.entries e
    join public.people p on p.id = e.person_id
   where public.who_admin(p_token) is not null
   order by e.entry_date desc, p.name
$$;

-- Get current rates (admin)
create or replace function public.admin_get_settings(p_token text)
returns table (recipient_rate numeric, supplier_rate numeric, updated_at timestamptz)
language sql security definer stable as $$
  select recipient_rate, supplier_rate, updated_at from public.settings
   where public.who_admin(p_token) is not null
$$;

-- ============================================================
-- PERSON RPCs (their own diary only)
-- ============================================================

-- Person sees ONLY their own entries
create or replace function public.person_get_diary(p_token text)
returns table (id uuid, name text, role text, entry_date date, morning numeric, night numeric,
              amount numeric, paid boolean)
language sql security definer stable as $$
  select p.id, p.name, p.role,
         e.entry_date, e.morning, e.night, e.amount, e.paid
    from public.people p
    left join public.entries e on e.person_id = p.id
   where p.session_token = p_token
   order by e.entry_date desc
$$;

-- Hardening: helper functions are internal-only. Revoke execute for anon
-- so they can't be called directly through PostgREST (only used inside
-- security-definer RPCs above).
revoke execute on function public.gen_token() from anon;
revoke execute on function public.hash_code(text, text) from anon;
revoke execute on function public.who_admin(text) from anon;
revoke execute on function public.who_person(text) from anon;

-- Person sees the rates (so they can understand their totals)
create or replace function public.person_get_rates(p_token text)
returns table (recipient_rate numeric, supplier_rate numeric)
language sql security definer stable as $$
  select s.recipient_rate, s.supplier_rate from public.settings s
   where exists (select 1 from public.people p
                  where p.session_token = p_token)
$$;

-- ============================================================
-- DONE
-- ============================================================
