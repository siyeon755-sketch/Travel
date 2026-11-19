-- 일정 순서 저장용 컬럼 추가
-- Supabase 대시보드 → SQL Editor에 붙여넣고 Run 한 번만 하면 됩니다.
-- 동선 추천의 "이 순서로 일정 정렬"을 누르면 이 컬럼에 순서가 저장됩니다.
-- 컬럼이 없어도 앱은 기존처럼 추가한 순서대로 일정을 보여 줍니다.
alter table public.plan_items add column if not exists sort_order int;
