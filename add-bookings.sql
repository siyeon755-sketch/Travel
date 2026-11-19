-- 예약 정보(항공·기차·숙소·기타) 테이블 추가
-- Supabase 대시보드 → SQL Editor에 붙여넣고 Run 한 번만 하면 됩니다.
-- RLS 정책은 schema.sql의 기존 패턴(is_trip_member 기반)을 그대로 따릅니다.

create table if not exists public.bookings (
  id uuid primary key default gen_random_uuid(),
  trip_id uuid not null references public.trips(id) on delete cascade,
  kind text not null check (kind in ('항공','기차','숙소','기타')),
  title text not null default '',
  from_text text not null default '',
  to_text text not null default '',
  address text not null default '',
  start_at timestamptz,
  end_at timestamptz,
  memo text not null default '',
  lat double precision,
  lng double precision,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now()
);

create index if not exists idx_bookings_trip on public.bookings(trip_id);

-- ------------------------------------------------------------
-- RLS 활성화
-- ------------------------------------------------------------

alter table public.bookings enable row level security;

-- ------------------------------------------------------------
-- RLS 정책: 여행 멤버만 읽기/쓰기 가능
-- ------------------------------------------------------------

drop policy if exists bookings_select on public.bookings;
create policy bookings_select on public.bookings
  for select to authenticated using (public.is_trip_member(trip_id));

drop policy if exists bookings_insert on public.bookings;
create policy bookings_insert on public.bookings
  for insert to authenticated with check (public.is_trip_member(trip_id));

drop policy if exists bookings_update on public.bookings;
create policy bookings_update on public.bookings
  for update to authenticated
  using (public.is_trip_member(trip_id))
  with check (public.is_trip_member(trip_id));

drop policy if exists bookings_delete on public.bookings;
create policy bookings_delete on public.bookings
  for delete to authenticated using (public.is_trip_member(trip_id));

-- grants.sql과 같은 패턴으로 이 테이블의 접근 권한을 엽니다.
-- (grants.sql은 실행 시점에 있던 테이블에만 적용되므로, 나중에 만든
--  bookings 테이블은 여기서 따로 열어 줘야 합니다.)
grant select, insert, update, delete on public.bookings to anon, authenticated;
