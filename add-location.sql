-- 장소 위치(좌표) 저장용 컬럼 추가
-- Supabase 대시보드 → SQL Editor에 붙여넣고 Run 한 번만 하면 됩니다.
alter table public.saved_places add column if not exists lat double precision;
alter table public.saved_places add column if not exists lng double precision;
alter table public.saved_places add column if not exists address text not null default '';
alter table public.saved_places add column if not exists matched_name text not null default '';
