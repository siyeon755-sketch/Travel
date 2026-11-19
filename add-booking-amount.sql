-- 예약 금액·정산 연결용 컬럼 추가
-- Supabase 대시보드 → SQL Editor에 붙여넣고 Run 한 번만 하면 됩니다.
-- amount: 예약 폼에서 입력한 금액(원). 정산에 지출로 추가할 때 쓰입니다.
-- expense_id: "정산에 지출로 추가"로 만든 지출(expenses)의 id.
--   값이 있으면 이미 정산에 넣은 예약이라 버튼이 비활성화됩니다.
-- 컬럼이 없어도 앱은 금액 없이 기존처럼 동작합니다.
alter table public.bookings add column if not exists amount integer;
alter table public.bookings add column if not exists expense_id uuid;
