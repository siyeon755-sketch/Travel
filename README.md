# 여행·모임 정산 도구 (공개 버전)

여러 사용자가 회원가입해서 함께 여행 계획을 짜고 정산까지 할 수 있는 웹앱입니다.
정적 SPA(`index.html`) 1개 파일 + Supabase(인증/DB) 구조라서, 정적 호스팅 어디에나 올릴 수 있습니다.

## 파일 구성

| 파일 | 설명 |
| --- | --- |
| `index.html` | 앱 전체 (화면 + 로직). 이 파일 하나만 배포하면 됩니다. |
| `schema.sql` | Supabase DB 스키마, RLS 정책, 초대 참여 함수, 트리거 |
| `supabase/functions/extract-places/index.ts` | 링크 수집함 자동 추출용 Edge Function |
| `EDGE-FUNCTION.md` | 위 Edge Function 배포 방법 |
| `README.md` | 이 문서 |

## 설정 방법

### 1단계: Supabase 프로젝트 만들기

1. [supabase.com](https://supabase.com) 에서 프로젝트를 생성합니다. (무료 플랜 가능)
2. 대시보드 **SQL Editor** 를 열고, `schema.sql` 의 내용 전체를 붙여넣어 실행합니다.
3. 대시보드 **Authentication > Providers > Email** 에서 이메일 로그인이 켜져 있는지 확인합니다.
   - 테스트 단계에서는 **Authentication > Settings** 에서 "Confirm email"을 꺼 두면
     회원가입 즉시 로그인할 수 있어 편합니다. (운영 시에는 켜는 것을 권장)

### 2단계: URL / 키 연결

1. Supabase 대시보드 **Project Settings > API** 에서
   `Project URL` 과 `anon public` 키를 복사합니다.
2. `index.html` 상단 스크립트의 설정 상수를 교체합니다.

```js
const SUPABASE_URL = 'YOUR_SUPABASE_URL';        // ← Project URL 로 교체
const SUPABASE_ANON_KEY = 'YOUR_SUPABASE_ANON_KEY';  // ← anon public 키로 교체
```

> anon 키는 브라우저에 노출되는 공개 키입니다. 데이터 보호는 `schema.sql` 의
> RLS 정책이 담당하므로(여행 멤버만 접근 가능), anon 키를 넣는 것이 정상적인 사용법입니다.

### 3단계: 배포

`index.html` 을 정적 호스팅에 올리면 끝입니다. 예:

- GitHub Pages, Netlify, Vercel, Cloudflare Pages 등에 파일 업로드
- 또는 아무 웹서버의 루트에 `index.html` 배치

초대 링크는 `https://(배포 주소)/?invite=초대코드` 형태이며,
링크를 받은 사람이 로그인하면 자동으로 해당 여행에 참여합니다.

### 4단계 (선택): 링크 수집함 자동 추출 켜기

장소 보관함의 "링크 수집함"(유튜브·인스타그램·블로그 링크에서 장소 후보 자동 추출)을
쓰려면 Edge Function 배포가 필요합니다. 방법은 `EDGE-FUNCTION.md` 를 보세요.
배포하지 않으면 링크 수집함만 동작하지 않고, 나머지 기능은 그대로 쓸 수 있습니다.

> 후보 추출은 규칙 기반이라 완벽하지 않습니다. 후보는 바로 저장되지 않고,
> 사용자가 확인하고 고른 것만 장소 보관함에 들어갑니다.

## 주요 기능

- 이메일 회원가입/로그인 (Supabase Auth)
- 여행 만들기, 날짜별 일정(예상 비용 합산), 장소 보관함(카테고리), 준비물 체크리스트
- 링크 수집함: 링크를 붙여넣으면 게시물에서 장소 후보를 뽑아 주고, 골라서 보관함에 저장
- 정산: 지출을 구간(예: 숙소 박별)으로 나눠 구간마다 참여자를 다르게 지정 가능,
  다중 결제자 상계 후 최소 송금 목록 자동 계산, 결과 텍스트 복사
- 초대 링크로 동행자 참여 (같이 보고 편집 가능)
