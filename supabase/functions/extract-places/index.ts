// ============================================================
// extract-places — 링크 수집함 자동 추출 (Supabase Edge Function)
//
// POST { url } 을 받아 게시물을 서버에서 읽고, 제목과 장소 후보를
// 뽑아 돌려줍니다. (브라우저는 CORS 때문에 외부 페이지를 직접
// 읽을 수 없어서 서버에서 가져옵니다.)
//
// 후보 추출은 Gemini AI가 1순위입니다 (환경변수 GEMINI_API_KEY가
// 등록돼 있을 때). 키가 없거나 AI 호출이 실패하면 규칙 기반으로
// 폴백합니다. 어느 경로로 뽑았는지는 응답의 method("ai"|"rules")로
// 구분합니다. AI를 못 쓴 이유는 ai_status("ok"|"no_key"|"error"|
// "timeout"|"bad_response")와 ai_error(짧은 원인, 최대 200자)로
// 함께 돌려주니, method가 "rules"로 나올 때 원인을 바로 확인할 수
// 있습니다. (API 키 값 자체는 응답·로그 어디에도 남기지 않습니다.)
//
// 반환: { ok: true, title, candidates: [{ name, likely, category? }],
//         source, method, ai_status, ai_error? }
//       { ok: false, reason }
//   likely=true인 후보만 화면에서 기본 체크된다.
//
// 장소 검색 모드: POST { action: "find-places", queries: string[] } 로
// 오면 링크 추출 대신 장소 이름으로 실제 위치를 검색해
// { ok: true, candidates: [{ name, name_en?, name_ko?, address, lat, lng,
// source }] } 를 돌려준다. name_en은 후보 이름의 영어 표기, name_ko는
// 한국어 표기로, 후보를 돌려주기 전에 Gemini 배치 번역으로 한 번에
// 붙인다(번역 실패 시 두 필드 없이 기존과 동일하게 반환). 중국 장소는 OpenStreetMap에 없는 경우가 많아(예: 상하이
// 데모레스 호텔은 중국명 黛茂诗酒店으로만 존재) Baidu 지도 공개 웹
// 검색을 서버에서 호출한다. 이 경로는 아래 SSRF 허용 목록 검사를
// 타지 않지만, 호출 대상이 코드에 고정된 map.baidu.com 주소 하나뿐
// 이라 임의 URL fetch가 아니다 (findPlaces 주석 참고).
//
// 이름 해석 모드: POST { action: "resolve-place", name, city? } 로
// 오면 한글 이름만으로 중국 장소를 찾는다. Gemini가 현지(중국어)
// 정식 이름·중국어 주소를 제안하고, 그 제안을 Baidu 검색으로 실측
// 검증해 일치하는 POI만 { ok: true, resolved, candidates } 로
// 돌려준다. candidates에도 find-places와 같은 name_en(영어 표기)과
// name_ko(한국어 표기)가 붙는다. 제안이 없거나 검증에 실패하면 후보를 만들지 않고
// { ok: false, reason } 을 돌려준다 (지어낸 핀 금지).
//
// 인증: Verify JWT 기본값(켜짐) 유지 전제. 로그인한 사용자만
// 호출할 수 있고, 이 함수 안에서 별도 JWT 검사는 하지 않습니다.
//
// 보안 (SSRF 방지): 사용자가 넣은 URL을 서버가 그대로 가져오면
// 내부/사설 주소로 요청을 보내는 공격이 가능하므로, 가져올 수 있는
// 사이트를 허용 목록(ALLOWED_HOSTS)으로 제한합니다. 리다이렉트는
// 자동 추종하지 않고 매 이동마다 같은 검사를 다시 적용합니다.
// ============================================================

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const BROWSER_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

// 인스타그램 전용 UA: 일반 브라우저 UA로는 로그인 벽/체크포인트
// 페이지만 돌아오지만, 링크 미리보기 크롤러 UA로는 og 메타와
// 임베드 페이지(캡션 전문)를 로그인 없이 받을 수 있다.
const CRAWLER_UA =
  "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)";

// === EXTRACT LOGIC START ===
// 아래 구간은 순수 JS(타입 표기 없음)입니다. Node 테스트에서 그대로
// 추출해 실행할 수 있게 유지하세요.

function decodeEntities(s) {
  return String(s ?? "")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#0?39;|&apos;/gi, "'")
    .replace(/&#(\d+);/g, (_, n) => String.fromCodePoint(Number(n)))
    .replace(/&#x([0-9a-f]+);/gi, (_, h) =>
      String.fromCodePoint(parseInt(h, 16)));
}

function metaContent(html, key) {
  // <meta property="og:title" content="..."> / 순서가 반대인 경우 모두 대응
  const patterns = [
    new RegExp(
      `<meta[^>]+(?:property|name)=["']${key}["'][^>]+content=["']([^"']*)["']`,
      "i",
    ),
    new RegExp(
      `<meta[^>]+content=["']([^"']*)["'][^>]+(?:property|name)=["']${key}["']`,
      "i",
    ),
  ];
  for (const re of patterns) {
    const m = html.match(re);
    if (m) return decodeEntities(m[1]).trim();
  }
  return "";
}

function htmlToText(html) {
  return decodeEntities(
    String(html ?? "")
      .replace(/<script[\s\S]*?<\/script>/gi, " ")
      .replace(/<style[\s\S]*?<\/style>/gi, " ")
      .replace(/<!--[\s\S]*?-->/g, " ")
      .replace(/<(br|\/p|\/div|\/li|\/h\d|\/tr|\/section|\/article)[^>]*>/gi, "\n")
      .replace(/<[^>]+>/g, " "),
  )
    .replace(/[ \t ]+/g, " ")
    .replace(/\n\s*\n+/g, "\n")
    .trim();
}

// 장소가 아닌 일반어 (단독 토큰일 때 제외)
const PLACE_STOPWORDS = new Set([
  "여행", "추천", "맛집", "후기", "코스", "일정", "브이로그", "여행기",
  "상하이", "상해", "중국", "베이징", "서울", "한국", "일본", "도쿄",
  "오사카", "방콕", "다낭", "홍콩", "대만", "타이베이", "광저우", "선전",
  "관광", "명소", "카페", "식당", "호텔", "숙소", "쇼핑", "디저트",
  "음료", "음식", "메뉴", "가격", "위치", "주소", "영업시간", "정보",
  "정리", "리스트", "총정리", "가이드", "꿀팁", "방법", "시간", "예약",
  "투어", "자유여행", "가족여행", "신혼여행", "데이트", "주말", "당일치기",
  "핫플", "핫플레이스", "인생샷", "포토존", "네이버 블로그", "블로그",
  "인스타그램", "유튜브", "영상", "사진", "댓글", "공감", "이웃", "링크",
  "출처", "광고", "협찬", "체험단", "내돈내산", "솔직후기", "현지인",
  "로컬", "베스트", "인기", "유명", "예쁜", "맛있는", "멋진", "좋은",
  "찐맛집", "뷰맛집", "가볼만한곳", "여행추천", "맛집추천", "상하이여행",
  "중국여행", "상하이맛집", "해외여행", "먹방", "쇼핑리스트", "기념품",
  "구매후기", "방문후기", "이용후기", "숙박후기", "탑승후기", "매장 내부",
  "카페 메뉴", "구매샷", "매장명", "영업시간", "커피", "칵테일", "메뉴판",
  "요즘", "인스타", "공구", "동결건조", "루프탑", "루프탑바", "이날",
  "해피아워",
  // 인스타그램 캡션/해시태그에서 흔한 일반어
  "저장", "공유", "일상", "모음집", "재방문", "다녀온", "진짜", "너무",
  "너무너무", "세번동안", "두번이상", "맛집들", "좋아요", "팔로우",
  "프로필", "여행스타그램", "먹스타그램", "카페스타그램", "여행에미치다",
  "fyp", "reels", "viral", "foryou", "foryoupage", "explore",
  "travel", "foodie", "instatravel", "instagood", "daily",
  // 도시 이름 단독은 장소가 아니다 (한자/영문 표기 포함)
  "上海", "北京", "广州", "深圳", "成都", "重庆", "西安", "杭州",
  "南京", "苏州", "武汉", "天津", "长沙", "厦门", "香港", "台北",
  "东京", "大阪", "京都", "首尔", "曼谷", "河内", "岘港",
  "shanghai", "beijing", "seoul", "tokyo", "osaka", "bangkok",
  "hanoi", "danang", "hongkong", "taipei",
]);

// 해시태그에 이 조각이 포함되면 장소명이 아니라고 본다
// (예: 상하이맛집, 상하이여행, 카페추천, 일상기록 등)
const HASHTAG_GENERIC_PARTS = [
  "맛집", "여행", "추천", "일상", "공유", "저장", "브이로그", "스타그램",
  "투어", "코스", "일정", "후기", "정보", "꿀팁", "핫플", "데이트",
  "먹방", "쇼핑", "모음", "재방문", "다녀온", "가볼만한", "핫플레이스",
  "먹스타", "기록", "소개", "총정리", "리스트",
];

// 라틴 문자만으로 된 해시태그 중 일반어 (대문자로 시작해도 제외)
const EN_GENERIC_TAGS = new Set([
  "travel", "foodie", "cafe", "hotel", "trip", "daily", "love",
  "happy", "photo", "video", "reels", "viral", "explore", "instagood",
  "beautiful", "wanderlust", "food", "foodporn", "yummy", "delicious",
  "breakfast", "lunch", "dinner", "coffee", "dessert", "shopping",
  "fashion", "ootd", "selfie", "nature", "sunset", "beach", "summer",
]);

// 도시 이름 단독 (해시태그 판정용, 한자 표기)
const CJK_CITY_NAMES = new Set([
  "上海", "北京", "广州", "深圳", "成都", "重庆", "西安", "杭州",
  "南京", "苏州", "武汉", "天津", "长沙", "厦门", "香港", "台北",
  "东京", "大阪", "京都", "首尔", "曼谷", "河内", "岘港",
]);

// 중국어 접미사 중 상호/시설 이름일 가능성이 특히 높은 것
const STRONG_CJK_SUFFIXES = new Set([
  "博物馆", "美术馆", "图书馆", "古镇", "夜市", "市场", "广场", "中心",
  "商场", "商城", "大厦", "酒店", "餐厅", "咖啡", "书店", "公园", "店",
]);

// 한국어 장소 접미사 규칙에서 제외할 일반어
const KOR_SUFFIX_EXCLUDES = new Set([
  "회사", "행사", "감사", "식사", "역사", "기사", "주사", "검사",
  "의사", "판사", "변호사", "형사", "민사", "상사", "지사",
]);

const CJK_SUFFIXES = [
  "博物馆", "美术馆", "图书馆", "古镇", "夜市", "市场", "广场", "中心",
  "商场", "商城", "大厦", "酒店", "餐厅", "咖啡", "书店", "公园",
  "店", "城", "路", "街", "站", "馆", "园", "塔", "寺", "湖", "桥",
  "岛", "山", "湾", "港", "江", "河",
];

function cleanCandidate(raw) {
  let s = String(raw ?? "")
    .replace(/^\[[^\]]{1,24}\]\s*/, "") // [중국/상해] 같은 머리표 제거
    .replace(/^[^가-힣A-Za-z0-9一-鿿]+/, "") // 앞쪽 기호/이모지 제거
    .replace(/[^가-힣A-Za-z0-9一-鿿]+$/, "") // 뒤쪽 기호 제거
    .replace(/\s+/g, " ")
    .trim();
  // 문장형 꼬리 제거
  s = s.replace(/(입니다|이에요|예요|했어요|같아요|네요|예정|추천해요|추천합니다)\.?$/, "").trim();
  // "~ 위치", "~ 후기" 같은 꼬리표 제거
  s = s.replace(/\s+(위치|후기)$/, "").trim();
  return s;
}

function isValidCandidate(s) {
  if (!s) return false;
  const len = [...s].length;
  if (len < 2 || len > 25) return false;
  if (PLACE_STOPWORDS.has(s) || PLACE_STOPWORDS.has(s.toLowerCase())) {
    return false;
  }
  if (/https?:\/\//.test(s) || s.includes("@")) return false;
  if (/^\d+$/.test(s)) return false; // 숫자만
  if (/^\d{1,4}[.\-/년월일\s]*$/.test(s)) return false; // 날짜만
  if (/\d:\d/.test(s)) return false; // 시각(10:00 등) 포함
  if (/[0-9]/.test(s) && !/[一-鿿]/.test(s)) return false; // 숫자 섞인 토큰(가격 등)
  // camelCase 영문 식별자(페이지 설정값 등 코드 잡음) 제외
  if (/^[A-Za-z]+$/.test(s) && /[a-z][A-Z]/.test(s)) return false;
  // 한국어 문장처럼 보이는 것 제외 (조사/어미로 끝나는 긴 구)
  if (
    /(입니다|합니다|했어요|같아요|이에요|예요|어요|해요|세요|있어요|돼요|네요|거예요|니다)\.?$/
      .test(s) && len > 6
  ) {
    return false;
  }
  return true;
}

// 해시태그는 장소 고유명사 패턴에 강하게 맞을 때만 남긴다.
// (인스타그램에서 해시태그는 일반어 잡음의 주범이라 엄격히 거른다)
const KOR_HASHTAG_SUFFIX_RE =
  /(?:박물관|미술관|백화점|공원|시장|광장|타워|거리|랜드|월드|센터|대교|호수|사원|성당|궁전|역|몰|루|사|항|섬|산)$/;

// 어떤 경우에도 해시태그 후보가 될 수 없는 일반어인가
function isHardBlockedHashtag(t) {
  if (!t) return true;
  if (PLACE_STOPWORDS.has(t) || PLACE_STOPWORDS.has(t.toLowerCase())) {
    return true;
  }
  if (KOR_SUFFIX_EXCLUDES.has(t)) return true;
  for (const part of HASHTAG_GENERIC_PARTS) {
    if (t.includes(part)) return true;
  }
  if (/[0-9]/.test(t) && !/[一-鿿]/.test(t)) return true; // 숫자 섞인 태그
  return false;
}

function isPlaceLikeHashtag(tag) {
  const t = String(tag ?? "").trim();
  if (isHardBlockedHashtag(t)) return false;
  // 한자 포함: 도시명 단독이 아니고 중국어 장소 접미사로 끝날 때만
  if (/[一-鿿]/.test(t)) {
    if (CJK_CITY_NAMES.has(t)) return false;
    return [...t].length >= 3 && CJK_SUFFIXES.some((suf) => t.endsWith(suf));
  }
  // 한국어: 장소 접미사로 끝나고 3자 이상일 때만
  if (/[가-힣]/.test(t)) {
    return [...t].length >= 3 && KOR_HASHTAG_SUFFIX_RE.test(t);
  }
  // 라틴 문자만: 대문자로 시작하는 고유명사형만 (Flair, Saturnbird 등).
  // 전부 소문자인 태그(shanghai, fyp, reels 등)는 일반 태그라 제외.
  if (/^[A-Z][A-Za-z]{3,}$/.test(t)) {
    return !EN_GENERIC_TAGS.has(t.toLowerCase());
  }
  return false;
}

// 패턴에는 안 걸리지만 본문(해시태그를 뺀 캡션)에도 등장하는 해시태그는
// 작성자가 본문에서 이름으로 쓴 고유명사일 가능성이 있다 (예: #예원,
// #미샹프라다롱자이). 일반어 차단은 그대로 적용하고, 점수는 최하위로
// 매겨 likely:false 로만 허용한다.
function isBodyMentionedHashtag(tag, bodyFlat) {
  const t = String(tag ?? "").trim();
  if (isHardBlockedHashtag(t)) return false;
  if (!/[가-힣一-鿿]/.test(t)) return false; // 한국어/한자 태그만
  if (/[一-鿿]/.test(t) && CJK_CITY_NAMES.has(t)) return false;
  if ([...t].length < 2) return false;
  return bodyFlat.includes(t);
}

// 제목/설명/본문에서 장소 후보를 규칙 기반으로 추출.
// 반환: [{ name, likely }] (점수 높은 순)
//   likely: 위치 태그·표시 줄·따옴표/병기·명확한 상호 패턴처럼
//           장소일 가능성이 높은 후보에 true. 화면에서 기본 체크용.
// options:
//   source: "instagram" 이면 인스타그램 모드. 캡션 일반어가 워낙 많아
//           제목 토큰/단어 빈도 규칙을 끄고 해시태그를 엄격히 거른다.
//   username / excludeNames: 계정명과 그 파편을 후보에서 제외한다.
function extractCandidates(title, description, bodyText, options = {}) {
  const igMode = options.source === "instagram";
  const usernameKey = String(options.username ?? "")
    .replace(/\s+/g, "")
    .toLowerCase();
  const excludeKeys = new Set(
    (options.excludeNames ?? []).map((n) =>
      String(n).replace(/\s+/g, "").toLowerCase()
    ),
  );

  const scores = new Map(); // 정규화 키 -> { name, score, order, likely }
  let order = 0;
  const add = (raw, score, likely = false) => {
    const name = cleanCandidate(raw);
    if (!isValidCandidate(name)) return;
    const key = name.replace(/\s+/g, "").toLowerCase();
    if (igMode) {
      // "Instagram의 ~님" 같은 계정 표기 자체는 장소가 아니다
      if (/instagram/i.test(name)) return;
      if (excludeKeys.has(key)) return;
      // 계정명 본인(imsosozip)이나 그 파편(soso, soso님) 제외
      if (usernameKey) {
        const base = key.replace(/님$/, "");
        if (key === usernameKey) return;
        if (base.length >= 3 && usernameKey.includes(base)) return;
        if (key.length >= 3 && usernameKey.includes(key)) return;
      }
    }
    const prev = scores.get(key);
    if (prev) {
      if (score > prev.score) prev.score = score;
      if (likely) prev.likely = true;
    } else {
      scores.set(key, { name, score, order: order++, likely: !!likely });
    }
  };

  const titleText = String(title ?? "");
  const descText = String(description ?? "");
  const body = String(bodyText ?? "").slice(0, 30000);

  // 1) 따옴표/꺾쇠 안 이름
  //    인스타그램 제목("Instagram의 ~님 : ...")은 계정 표기라 건너뛴다.
  const quoteRe = /["“”「『]([^"“”」』\n]{2,25})["“”」』]/g;
  const quoteTexts = igMode
    ? [[descText, 55], [body, 45]]
    : [[titleText, 70], [descText, 55], [body, 45]];
  for (const [text, sc] of quoteTexts) {
    for (const m of text.matchAll(quoteRe)) {
      // 인스타그램에서 따옴표 구간은 캡션 첫 문장인 경우가 많아,
      // 일반어 조각이 섞인 문구는 likely에서 내린다
      const likelyQuote = !igMode ||
        !HASHTAG_GENERIC_PARTS.some((p) => m[1].includes(p));
      add(m[1], sc, likelyQuote);
    }
  }

  // 2) 한국어 이름 + (중국어) 병기 패턴: 새턴버드(三顿半) → 둘 다 후보
  const parenRe =
    /([가-힣A-Za-z0-9][가-힣A-Za-z0-9&·\s]{0,18}?)\s*[\(（]([一-鿿·\s]{2,20})[\)）]/g;
  for (const text of [titleText, descText, body]) {
    for (const m of text.matchAll(parenRe)) {
      add(m[1], 60, true);
      add(m[2].replace(/\s+/g, ""), 40, true);
    }
  }

  // 3) 제목/설명을 구분자로 나눈 토큰 (괄호 병기는 2번 규칙이 따로 처리)
  //    인스타그램 제목/설명은 계정명·좋아요 수 같은 잡음뿐이라 제외.
  if (!igMode) {
    const delimRe = /\s*[|·•\/>»—–:,\-]\s*/;
    for (const [text, sc] of [[titleText, 50], [descText, 35]]) {
      for (const tok of text.split(delimRe)) {
        if (/[\(\)（）]/.test(tok)) continue;
        add(tok, sc, sc >= 50);
      }
    }
  }

  // 3-1) 표시 줄: 📍/🏩 마커가 붙은 줄, "위치: ~" 라벨 줄.
  //      인스타그램 캡션에서 장소 신호가 가장 강한 형태다.
  const bodyLines = body.split("\n");
  for (let i = 0; i < bodyLines.length; i++) {
    const t = bodyLines[i].trim();
    if (!t) continue;
    const labelM = t.match(/^(?:위치|주소|장소)\s*[:：]\s*(.{2,30})$/);
    if (labelM) {
      add(labelM[1], 90, true);
      continue;
    }
    const emoM = t.match(/^(?:📍|📌|🏩|🚩)\s*(.{2,30})$/);
    if (emoM) {
      add(emoM[1], 90, true);
      continue;
    }
    // 마커만 있는 줄이면 다음 줄이 장소인 경우가 많다
    if (/^(?:📍|📌|🏩|🚩)+$/.test(t)) {
      for (let j = i + 1; j < bodyLines.length; j++) {
        const nt = bodyLines[j].trim();
        if (nt) {
          add(nt, 90, true);
          break;
        }
      }
    }
  }

  // 4) 해시태그. 인스타그램에서는 고유명사 패턴에 강하게 맞을 때만.
  //    패턴에 안 걸려도 본문에 이름으로 등장하면 최하위 점수로 허용.
  const bodyFlat = igMode
    ? body.replace(/#[^\s#]+/g, " ").replace(/\s+/g, "")
    : "";
  const hashRe = /#([^\s#]{2,20})/g;
  for (const text of [descText, body]) {
    for (const m of text.matchAll(hashRe)) {
      if (igMode) {
        if (isPlaceLikeHashtag(m[1])) add(m[1], 45, false);
        else if (isBodyMentionedHashtag(m[1], bodyFlat)) add(m[1], 15, false);
      } else {
        add(m[1], 30, false);
      }
    }
  }

  // 5) 중국어 지점/장소 패턴: 한자 연속 + 장소 접미사.
  //    상호·시설 접미사(店·广场·中心 등)로 끝나면 likely.
  const cjkRunRe = /[一-鿿]{2,16}/g;
  for (const text of [titleText, descText, body]) {
    for (const m of text.matchAll(cjkRunRe)) {
      const run = m[0];
      for (const suf of CJK_SUFFIXES) {
        if (run.endsWith(suf)) {
          add(run.slice(-12), 38, STRONG_CJK_SUFFIXES.has(suf));
          break;
        }
      }
    }
  }

  // 6) 한국어 장소 접미사로 끝나는 단어 (정안사, 우캉루, ~역, ~공원 등)
  const korSuffixRe = /[가-힣]{2,10}?(?:박물관|미술관|백화점|공원|시장|광장|타워|거리|역|사|루|몰)/g;
  for (const text of [titleText, descText, body]) {
    for (const m of text.matchAll(korSuffixRe)) {
      if (!KOR_SUFFIX_EXCLUDES.has(m[0])) add(m[0], 25, false);
    }
  }

  // 7) 제목형 줄: "1. 이름", "매장명 : 이름" 같은 형태 (인스타그램 제외)
  if (!igMode) {
    for (const line of bodyLines) {
      const t = line.trim();
      if (!t || [...t].length > 40) continue;
      const label = t.match(/^[^:：]{1,10}[:：]\s*(.{2,25})$/);
      if (label && !/[\(\)（）]/.test(label[1])) add(label[1], 20, false);
      const numbered = t.match(/^\d{1,2}[.)]\s*(.{2,25})$/);
      if (numbered && !/(다|요|네요)[.!?。]?\s*$/.test(numbered[1])) {
        add(numbered[1], 18, false);
      }
    }
  }

  // 8) 단어 빈도: 제목 단어 + 본문/설명에서 2번 이상 반복되는 단어.
  //    인스타그램 캡션에서는 일반어 잡음의 주범이라 끈다.
  if (!igMode) {
    const badEnding =
      /(은|는|이|가|을|를|의|에|와|과|로|으로|에서|부터|까지|처럼|보다|다|요|함|음|임|데|고|까|죠|네|며|서|한|인|적|것|때|수|등|중|도|야|게|쯤|던)$/;
    const wordCounts = new Map();
    const tokenize = (text) =>
      String(text ?? "")
        .split(/[^\w가-힣一-鿿]+/)
        .map((w) => w.trim())
        .filter(Boolean);
    for (const w of tokenize(titleText)) {
      if ([...w].length < 2 || [...w].length > 10) continue;
      if (badEnding.test(w)) continue;
      add(w, 30, false);
    }
    for (const w of tokenize(descText + " " + body)) {
      if (/[一-鿿]/.test(w)) continue; // 한자는 5번 규칙이 담당
      wordCounts.set(w, (wordCounts.get(w) ?? 0) + 1);
    }
    for (const [w, cnt] of wordCounts) {
      if (cnt < 2) continue;
      if ([...w].length < 2 || [...w].length > 10) continue;
      if (badEnding.test(w)) continue;
      add(w, cnt >= 3 ? 28 : 22, false);
    }
  }

  let results = [...scores.values()]
    .sort((a, b) => b.score - a.score || a.order - b.order);
  if (igMode) {
    // 부분 문자열 관계인 중복 후보 정리 (디즈니랜드 vs 상하이디즈니랜드).
    // 점수가 같으면 더 긴(구체적인) 이름을 남긴다.
    const keyOf = (v) => v.name.replace(/\s+/g, "").toLowerCase();
    const byPref = [...results].sort((a, b) =>
      b.score - a.score || keyOf(b).length - keyOf(a).length ||
      a.order - b.order
    );
    const keptKeys = [];
    const drop = new Set();
    for (const v of byPref) {
      const k = keyOf(v);
      if (keptKeys.some((u) => u.includes(k) || k.includes(u))) {
        drop.add(v);
      } else {
        keptKeys.push(k);
      }
    }
    results = results.filter((v) => !drop.has(v));
  }
  return results
    .slice(0, igMode ? 12 : 20)
    .map((v) => ({ name: v.name, likely: !!v.likely }));
}

// === 제목 안전망: 제목의 대표 장소 ===
// AI가 게시물의 주제인 장소를 건너뛰는 경우가 있다. 특히 제목에
// 대문짝만하게 있는 식당을 빼먹는 사례가 실측으로 확인됐다
// (제목 "상하이 디안뉴 훠궈 인민광장점, …" 인데 후보는 주변 역·
// 거리뿐). 그래서 제목 첫 절에서 대표 장소를 규칙으로 뽑아 두고,
// AI 후보에 비슷한 이름이 없을 때만 finalizeCandidates가 병합하는
// 결정적 안전망으로 쓴다. 글당 최대 1개만 만든다.

// 제목 앞머리에 붙는 도시/지역 접두 (공백으로 이어질 때만 제거한다.
// "상하이타워"처럼 붙어 있는 고유명사는 건드리지 않는다)
const TITLE_CITY_PREFIXES = [
  "상하이", "상해", "베이징", "북경", "광저우", "선전", "심천",
  "청두", "성도", "충칭", "중경", "시안", "서안", "항저우", "항주",
  "난징", "남경", "쑤저우", "소주", "우한", "무한", "샤먼", "하문",
  "창사", "장사", "톈진", "천진", "홍콩", "마카오",
  "도쿄", "오사카", "교토", "후쿠오카", "삿포로", "나고야",
  "서울", "부산", "제주", "인천", "대구", "광주", "대전", "울산",
  "방콕", "치앙마이", "다낭", "하노이", "호치민", "나트랑",
  "타이베이", "가오슝", "타이중",
  "중국", "일본", "대만", "태국", "베트남", "한국",
].sort((a, b) => b.length - a.length);

// 장소 접미사: 끝에 붙으면 장소로 인정 (기존 규칙의 접미사 집합 확장)
const TITLE_PLACE_SUFFIXES = [
  "박물관", "미술관", "백화점", "공원", "시장", "광장", "타워",
  "거리", "역", "사", "루", "몰", "랜드", "월드", "센터", "대교",
  "호수", "사원", "성당", "궁전", "항", "섬", "산",
  "점", "식당", "훠궈", "카페", "호텔", "로",
];

// 장소 접미사: 이름 중간에 있어도 장소로 인정하는 강한 것들만
// ("로", "사" 같은 약한 접미사는 "브이로그" 같은 일반어를 통과시켜
// 버리므로 포함 판정에서는 뺀다)
const TITLE_STRONG_SUFFIXES = [
  "박물관", "미술관", "백화점", "공원", "시장", "광장", "타워",
  "거리", "역", "몰", "센터",
  "점", "식당", "훠궈", "카페", "호텔",
];

// 이런 일반어가 섞인 구는 장소 이름이 아니다 (제목 낚시문구 차단)
const TITLE_GENERIC_PHRASES = [
  "추천", "후기", "브이로그", "여행", "코스", "일정", "투어",
  "총정리", "리스트", "모음", "기록", "소개", "가이드", "꿀팁",
];

// 제목 안전망 후보의 카테고리를 이름 키워드로 추정한다.
// (앱 카테고리 체계와 같은 값을 돌려준다)
function guessTitleCandidateCategory(name) {
  const checks = [
    ["식사", ["훠궈", "식당", "레스토랑", "음식점", "맛집", "밥집", "국수", "라멘", "스시", "초밥"]],
    ["카페", ["카페", "커피"]],
    ["음료", ["밀크티", "버블티", "음료", "주스", "찻집"]],
    ["디저트", ["디저트", "베이커리", "빵집", "제과", "아이스크림", "케이크"]],
    ["숙소", ["호텔", "숙소", "민박", "게스트하우스", "료칸"]],
    ["교통", ["역", "공항", "터미널", "정류장"]],
    ["쇼핑", ["백화점", "몰", "상점", "아울렛", "면세점"]],
    ["관광", ["박물관", "미술관", "공원", "시장", "테마파크", "수족관", "동물원"]],
    ["명소", ["타워", "전망대", "랜드마크", "대교", "궁전", "성당", "사원"]],
  ];
  for (const [cat, kws] of checks) {
    if (kws.some((k) => name.includes(k))) return cat;
  }
  return "기타";
}

// 제목에서 대표 장소 후보를 뽑는다. 없으면 null.
//   1) 첫 절만 취한다 (쉼표·가운뎃점·대시·세로줄 앞부분)
//   2) 도시/지역 접두를 벗긴다
//   3) 장소 접미사로 끝나거나 강한 접미사를 포함할 때만 인정한다
function titleSafetyNetCandidate(rawTitle) {
  const title = String(rawTitle ?? "").trim();
  if (!title) return null;
  let head = cleanCandidate(title.split(/[,，·•|—–―-]/)[0]);
  for (let i = 0; i < 2 && head; i++) {
    const city = TITLE_CITY_PREFIXES.find((c) => head.startsWith(c + " "));
    if (!city) break;
    head = head.slice(city.length).trim();
  }
  if (!head) return null;
  if (TITLE_GENERIC_PHRASES.some((w) => head.includes(w))) return null;
  if (!isValidCandidate(head)) return null;
  const placeLike = TITLE_PLACE_SUFFIXES.some((s) => head.endsWith(s)) ||
    TITLE_STRONG_SUFFIXES.some((s) => head.includes(s));
  if (!placeLike) return null;
  return {
    name: head,
    likely: true,
    category: guessTitleCandidateCategory(head),
  };
}

// === SSRF 방지: 허용 사이트 제한 ===
// 읽을 수 있는 호스트는 아래 목록뿐이다. 목록에 없으면 가져오지 않는다.
const ALLOWED_HOSTS = new Set([
  "youtube.com",
  "www.youtube.com",
  "m.youtube.com",
  "music.youtube.com",
  "youtu.be",
  "instagram.com",
  "www.instagram.com",
  "blog.naver.com",
  "m.blog.naver.com",
]);

const UNSUPPORTED_SITE_REASON =
  "지원하지 않는 사이트예요. 유튜브·인스타그램·네이버 블로그 링크만 읽을 수 있어요.";

function isIpLiteralHost(hostname) {
  if (!hostname) return true;
  if (hostname.startsWith("[")) return true; // IPv6 리터럴 ([::1] 등)
  // IPv4 리터럴. URL 파서가 2130706433, 0x7f000001 같은 우회 표기도
  // 127.0.0.1 형태의 점표기로 정규화해 주므로 이 검사로 함께 걸러진다.
  // (localhost, 127.0.0.1, 169.254.169.254, 사설/예약 대역 전부 포함)
  if (/^\d{1,3}(\.\d{1,3}){3}\.?$/.test(hostname)) return true;
  return false;
}

// fetch 대상 URL 검사. 통과하면 { ok: true, url }, 아니면
// { ok: false, reason } 을 돌려준다. 처음 주소뿐 아니라 리다이렉트로
// 도착한 주소에도 매번 이 검사를 적용해야 한다.
function validateFetchUrl(raw) {
  let url;
  try {
    url = raw instanceof URL ? raw : new URL(String(raw));
  } catch {
    return { ok: false, reason: UNSUPPORTED_SITE_REASON };
  }
  // http/https 만 허용
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { ok: false, reason: UNSUPPORTED_SITE_REASON };
  }
  // 주소에 사용자정보(user:pass@)가 있으면 거부
  if (url.username || url.password) {
    return { ok: false, reason: UNSUPPORTED_SITE_REASON };
  }
  // 포트 지정 거부. 기본 포트(80/443)는 URL 파서가 자동으로 비워
  // 주므로, 포트가 남아 있으면 비표준 포트를 지정한 것이다.
  if (url.port) {
    return { ok: false, reason: UNSUPPORTED_SITE_REASON };
  }
  const host = url.hostname.toLowerCase();
  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    isIpLiteralHost(host)
  ) {
    return { ok: false, reason: UNSUPPORTED_SITE_REASON };
  }
  if (!ALLOWED_HOSTS.has(host)) {
    return { ok: false, reason: UNSUPPORTED_SITE_REASON };
  }
  return { ok: true, url };
}

// === EXTRACT LOGIC END ===

// 허용 목록 검사에서 막힌 경우를 구분하기 위한 에러.
// 핸들러에서 이 에러는 "지원하지 않는 사이트" 안내로 그대로 돌려준다.
class BlockedUrlError extends Error {}

const MAX_REDIRECTS = 5;
const MAX_BODY_BYTES = 2 * 1024 * 1024; // 응답 크기 상한 2MB

async function readBodyWithCap(
  res: Response,
  maxBytes: number,
): Promise<string> {
  const declared = Number(res.headers.get("content-length") ?? 0);
  if (declared > maxBytes) {
    throw new Error("페이지가 너무 커서 읽기를 중단했어요.");
  }
  if (!res.body) {
    const text = await res.text();
    if (text.length > maxBytes) {
      throw new Error("페이지가 너무 커서 읽기를 중단했어요.");
    }
    return text;
  }
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      total += value.byteLength;
      if (total > maxBytes) {
        try {
          await reader.cancel();
        } catch { /* 무시 */ }
        throw new Error("페이지가 너무 커서 읽기를 중단했어요.");
      }
      chunks.push(value);
    }
  }
  const buf = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    buf.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8").decode(buf);
}

// SSRF 방지 fetch:
// - 처음 주소와 리다이렉트로 도착하는 주소 모두 validateFetchUrl로
//   검사한 뒤에만 요청한다 (허용 목록 밖이면 BlockedUrlError).
// - 리다이렉트는 자동 추종(redirect: "follow")을 쓰지 않고 최대
//   MAX_REDIRECTS회까지 직접 따라간다.
// - 전체 시간(timeoutMs)과 응답 크기(MAX_BODY_BYTES)에 상한이 있다.
async function fetchText(
  rawUrl: string,
  timeoutMs = 10000,
  userAgent: string = BROWSER_UA,
): Promise<string> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    let current = rawUrl;
    for (let hop = 0; ; hop++) {
      const gate = validateFetchUrl(current);
      if (!gate.ok) throw new BlockedUrlError(gate.reason);
      const res = await fetch(gate.url.toString(), {
        headers: {
          "User-Agent": userAgent,
          "Accept-Language": "ko-KR,ko;q=0.9,en;q=0.5",
          Accept: "text/html,application/xhtml+xml",
        },
        redirect: "manual",
        signal: ctrl.signal,
      });
      if ([301, 302, 303, 307, 308].includes(res.status)) {
        const location = res.headers.get("location");
        try {
          await res.body?.cancel();
        } catch { /* 무시 */ }
        if (!location) throw new Error(`HTTP ${res.status}`);
        if (hop >= MAX_REDIRECTS) {
          throw new Error("리다이렉트가 너무 많아요.");
        }
        current = new URL(location, gate.url).toString();
        continue;
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await readBodyWithCap(res, MAX_BODY_BYTES);
    }
  } finally {
    clearTimeout(timer);
  }
}

type PlaceCandidate = {
  name: string;
  likely?: boolean;
  category?: string;
};

// AI 추출 시도 결과 구분. "ok"면 AI가 후보를 뽑은 것이고, 나머지는
// 규칙 기반으로 폴백한 이유다.
type AiStatus = "ok" | "no_key" | "error" | "timeout" | "bad_response";

type ExtractResult =
  | {
    ok: true;
    title: string;
    candidates: PlaceCandidate[];
    source: string;
    source_detail?: string;
    method: "ai" | "rules";
    ai_status: AiStatus;
    ai_error?: string;
  }
  | { ok: false; reason: string };

// === Gemini AI 추출 ===
// 환경변수 GEMINI_API_KEY(Supabase Secrets에 등록)가 있으면 AI로
// 후보를 뽑고, 없거나 실패하면 호출부가 규칙 기반으로 폴백한다.
// Gemini 엔드포인트는 코드에 고정된 주소라, 사용자 URL에 적용되는
// SSRF 허용 목록 검사와는 별개로 둔다.

// 기본 모델. gemini-2.0-flash는 2026-06-01 종료돼 404가 나므로
// 현행 모델을 쓴다. 환경변수 GEMINI_MODEL(Supabase Secrets)이
// 있으면 그 값을 우선해, 다음 교체 때는 코드 수정 없이 바꿀 수 있다.
const GEMINI_DEFAULT_MODEL = "gemini-3.8-flash";

function geminiModel(): string {
  try {
    return Deno.env.get("GEMINI_MODEL")?.trim() || GEMINI_DEFAULT_MODEL;
  } catch {
    return GEMINI_DEFAULT_MODEL;
  }
}

function geminiEndpoint(): string {
  return `https://generativelanguage.googleapis.com/v1beta/models/${geminiModel()}:generateContent`;
}
const GEMINI_TIMEOUT_MS = 20000;
// 일시 오류(HTTP 503·429)나 타임아웃이면 잠깐 쉬고 1회만 재시도한다.
// 그래도 실패하면 호출부가 규칙 기반으로 폴백하고, ai_status/ai_error에는
// 마지막 시도의 원인이 기록된다.
const GEMINI_RETRY_DELAY_MS = 1500;
const GEMINI_MAX_ATTEMPTS = 2;
const AI_TEXT_LIMIT = 6000; // AI에 보낼 본문 최대 길이
const AI_MAX_CANDIDATES = 15;

// 앱의 saved_places 카테고리 체계
const PLACE_CATEGORIES = [
  "음료", "식사", "디저트", "카페", "쇼핑", "관광", "명소", "숙소",
  "교통", "기타",
];

// AI가 자유롭게 적은 카테고리 추측을 위 체계로 정규화한다.
const CATEGORY_ALIASES: [string, string][] = [
  ["식사", "식사"], ["맛집", "식사"], ["음식", "식사"], ["식당", "식사"],
  ["레스토랑", "식사"], ["restaurant", "식사"],
  ["카페", "카페"], ["커피", "카페"], ["cafe", "카페"], ["coffee", "카페"],
  ["음료", "음료"], ["밀크티", "음료"], ["버블티", "음료"], ["주스", "음료"],
  ["음료수", "음료"], ["drink", "음료"],
  ["디저트", "디저트"], ["베이커리", "디저트"], ["빵", "디저트"],
  ["아이스크림", "디저트"], ["dessert", "디저트"], ["bakery", "디저트"],
  ["쇼핑", "쇼핑"], ["상점", "쇼핑"], ["가게", "쇼핑"], ["몰", "쇼핑"],
  ["마켓", "쇼핑"], ["shopping", "쇼핑"], ["store", "쇼핑"], ["shop", "쇼핑"],
  ["숙소", "숙소"], ["호텔", "숙소"], ["hotel", "숙소"],
  ["교통", "교통"], ["역", "교통"], ["공항", "교통"], ["터미널", "교통"],
  ["station", "교통"],
  ["명소", "명소"], ["랜드마크", "명소"], ["타워", "명소"],
  ["landmark", "명소"],
  ["관광", "관광"], ["관광지", "관광"], ["박물관", "관광"],
  ["미술관", "관광"], ["공원", "관광"], ["시장", "관광"],
  ["attraction", "관광"],
];

function normalizeCategory(guess: unknown): string {
  if (typeof guess !== "string") return "기타";
  const g = guess.trim();
  if (!g) return "기타";
  if (PLACE_CATEGORIES.includes(g)) return g;
  const lower = g.toLowerCase();
  for (const [key, value] of CATEGORY_ALIASES) {
    if (lower.includes(key.toLowerCase())) return value;
  }
  return "기타";
}

function geminiApiKey(): string {
  try {
    return Deno.env.get("GEMINI_API_KEY") ?? "";
  } catch {
    return "";
  }
}

// AI가 돌려준 이름 정리. 규칙 기반 cleanCandidate와 달리
// "새턴버드(三顿半)" 같은 병기 괄호는 깨지 않고 유지한다.
function cleanAiName(raw: string): string {
  return String(raw ?? "")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/^[^가-힣A-Za-z0-9一-鿿]+/, "")
    .replace(/[^가-힣A-Za-z0-9一-鿿)）]+$/, "")
    .trim();
}

const AI_PROMPT_PREFIX =
  `너는 여행 게시물에서 장소만 골라내는 추출기다.
아래 여행 게시물 텍스트에서 실제로 방문할 수 있는 장소 이름(식당·카페·상점·관광지·호텔·랜드마크·역·시장 등)만 뽑아라.
결제 브랜드(유니온페이·네이버페이·페이북 등), 플랫폼·앱 이름, 사람 이름, 계정명, 일반 명사, 장소가 아닌 해시태그는 제외해라.
지점명이 있으면 지점까지 포함해라(예: 찰리타운 정안 캐리센터점).
제목(텍스트 첫 줄)에 나온 장소는 반드시 포함해라. 제목에 있는 장소가 그 게시물의 주제인 경우가 많다.
외국 장소 이름을 한국어로 음역한 표기(예: 디안뉴 훠궈 인민광장점)도 실제 장소 이름으로 보고 포함해라.
중국어 이름에 한국어/영어 병기가 있으면 "한국어명(중국어명)"처럼 함께 적어라.
category_guess는 다음 중 하나로 골라라: 음료, 식사, 디저트, 카페, 쇼핑, 관광, 명소, 숙소, 교통, 기타.
설명 없이 JSON 배열만 출력해라. 형식: [{"name": "장소 이름", "category_guess": "식사"}]
장소가 없으면 빈 배열 []을 출력해라. 최대 15개까지만 뽑아라.

[게시물 텍스트]
`;

// AI 추출 시도 결과. 실패 시 status로 원인을 구분하고, error에는
// 짧은 원인(최대 200자)을 실어 응답의 ai_error와 함수 로그로 남긴다.
type AiOutcome =
  | { status: "ok"; candidates: PlaceCandidate[] }
  | { status: Exclude<AiStatus, "ok">; error?: string };

// 외부에서 온 문자열(오류 메시지 등)에 API 키가 섞여 있어도
// 응답·로그에 그대로 나가지 않게 가린다.
function scrubApiKey(text: string, apiKey: string): string {
  if (!apiKey) return text;
  return text.split(apiKey).join("***");
}

// AI 추출 실패 원인을 함수 로그에 남긴다 (Supabase 대시보드의
// Edge Function 로그에서 확인 가능). 키 값은 절대 포함하지 않는다.
function logAiFailure(status: AiStatus, error?: string): void {
  console.error(
    `[extract-places] ai_status=${status}${error ? ` ai_error=${error}` : ""}`,
  );
}

// 1회 시도 결과. httpStatus는 재시도 여부 판단에만 쓰고,
// 바깥으로 내보내는 AiOutcome에는 포함하지 않는다.
type AiAttemptOutcome = AiOutcome & { httpStatus?: number };

// Gemini에 본문을 보내 장소 후보를 받는다. 키가 없으면 바로
// no_key를 돌려주고, 일시 오류(503·429·타임아웃)면 1회 재시도한다.
// 끝내 실패하면 status로 원인을 구분해 돌려주고, 호출부가
// 규칙 기반으로 폴백한다.
async function extractPlacesWithAi(
  text: string,
): Promise<AiOutcome> {
  const apiKey = geminiApiKey();
  if (!apiKey) {
    logAiFailure("no_key", "GEMINI_API_KEY not set");
    return { status: "no_key" };
  }
  const clipped = String(text ?? "").slice(0, AI_TEXT_LIMIT).trim();
  if (!clipped) {
    logAiFailure("error", "empty_text");
    return { status: "error", error: "empty_text" };
  }

  let lastOutcome: AiOutcome = { status: "error", error: "not_attempted" };
  for (let attempt = 1; attempt <= GEMINI_MAX_ATTEMPTS; attempt++) {
    const outcome = await attemptExtractPlacesWithAi(clipped, apiKey);
    if (outcome.status === "ok") return outcome;
    const { httpStatus, ...rest } = outcome;
    lastOutcome = rest;
    const retryable = outcome.status === "timeout" || httpStatus === 503 ||
      httpStatus === 429;
    if (!retryable || attempt >= GEMINI_MAX_ATTEMPTS) break;
    await new Promise((resolve) =>
      setTimeout(resolve, GEMINI_RETRY_DELAY_MS)
    );
  }
  return lastOutcome;
}

// 실제 Gemini 호출 1회. 타임아웃은 시도마다 새로 건다.
async function attemptExtractPlacesWithAi(
  clipped: string,
  apiKey: string,
): Promise<AiAttemptOutcome> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), GEMINI_TIMEOUT_MS);
  try {
    const res = await fetch(geminiEndpoint(), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-goog-api-key": apiKey,
      },
      body: JSON.stringify({
        contents: [{
          parts: [{ text: AI_PROMPT_PREFIX + clipped }],
        }],
        generationConfig: {
          responseMimeType: "application/json",
          // Gemini 3 계열: temperature는 지정하지 않고, 추출 작업이라
          // 깊은 추론이 필요 없어 thinking level을 LOW로 둔다.
          thinkingConfig: { thinkingLevel: "LOW" },
          maxOutputTokens: 1024,
        },
      }),
      signal: ctrl.signal,
    });
    if (!res.ok) {
      // Gemini 오류 본문에서 핵심 메시지만 뽑아 원인으로 남긴다.
      let detail = "";
      try {
        const errText = await res.text();
        try {
          const errJson = JSON.parse(errText);
          detail = String(
            errJson?.error?.message ?? errJson?.error?.status ?? "",
          );
        } catch {
          detail = errText;
        }
      } catch {
        // 오류 본문조차 못 읽으면 상태 코드만으로 충분하다
      }
      const aiError = scrubApiKey(
        `HTTP ${res.status}${detail ? `: ${detail}` : ""}`,
        apiKey,
      ).slice(0, 200);
      logAiFailure("error", aiError);
      return { status: "error", error: aiError, httpStatus: res.status };
    }
    let data: {
      candidates?: { content?: { parts?: { text?: unknown }[] } }[];
    };
    try {
      data = await res.json();
    } catch {
      logAiFailure("bad_response", "response_not_json");
      return { status: "bad_response", error: "response_not_json" };
    }
    const parts = data?.candidates?.[0]?.content?.parts;
    if (!Array.isArray(parts)) {
      logAiFailure("bad_response", "no_content_parts");
      return { status: "bad_response", error: "no_content_parts" };
    }
    const textOut = parts
      .map((p: { text?: unknown }) =>
        typeof p?.text === "string" ? p.text : ""
      )
      .join("")
      .trim();
    if (!textOut) {
      logAiFailure("bad_response", "empty_model_output");
      return { status: "bad_response", error: "empty_model_output" };
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(textOut);
    } catch {
      logAiFailure("bad_response", "model_output_not_json");
      return { status: "bad_response", error: "model_output_not_json" };
    }
    if (!Array.isArray(parsed)) {
      logAiFailure("bad_response", "model_output_not_array");
      return { status: "bad_response", error: "model_output_not_array" };
    }
    const out: PlaceCandidate[] = [];
    const seen = new Set<string>();
    for (const item of parsed) {
      const rawName = typeof item === "string"
        ? item
        : (item as { name?: unknown })?.name;
      if (typeof rawName !== "string") continue;
      const name = cleanAiName(rawName);
      if (!isValidCandidate(name)) continue;
      const key = name.replace(/\s+/g, "").toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({
        name,
        likely: true,
        category: normalizeCategory(
          (item as { category_guess?: unknown })?.category_guess,
        ),
      });
      if (out.length >= AI_MAX_CANDIDATES) break;
    }
    return { status: "ok", candidates: out };
  } catch (e) {
    // 타임아웃(AbortController 중단)과 그 밖의 네트워크 오류를 구분한다.
    const aborted = ctrl.signal.aborted ||
      (e instanceof Error && e.name === "AbortError");
    if (aborted) {
      const aiError = `timeout_after_${GEMINI_TIMEOUT_MS}ms`;
      logAiFailure("timeout", aiError);
      return { status: "timeout", error: aiError };
    }
    const aiError = scrubApiKey(
      e instanceof Error ? e.message : String(e),
      apiKey,
    ).slice(0, 200);
    logAiFailure("error", aiError);
    return { status: "error", error: aiError };
  } finally {
    clearTimeout(timer);
  }
}

// 후보 확정: AI가 성공하면 AI 결과를 쓰고, 위치 태그처럼 신호가
// 확실한 pinned 이름은 AI 결과와 무관하게 맨 앞에 likely로 유지한다.
// AI를 못 쓰면 rules() 콜백의 규칙 기반 결과를 그대로 쓴다
// (규칙 경로에서 pinned 병합은 콜백 쪽이 담당한다).
async function finalizeCandidates(opts: {
  aiText: string;
  rules: () => PlaceCandidate[];
  pinned?: string[];
  limit: number;
  title?: string;
}): Promise<{
  candidates: PlaceCandidate[];
  method: "ai" | "rules";
  aiStatus: AiStatus;
  aiError?: string;
}> {
  const ai = await extractPlacesWithAi(opts.aiText);
  if (ai.status === "ok") {
    const merged: PlaceCandidate[] = [];
    const seen = new Set<string>();
    for (const raw of opts.pinned ?? []) {
      const name = cleanCandidate(raw);
      if (!isValidCandidate(name)) continue;
      const key = name.replace(/\s+/g, "").toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      merged.push({ name, likely: true });
    }
    // 제목 안전망: 제목의 대표 장소를 AI가 빼먹었으면 규칙 후보를
    // likely로 병합한다. 이미 병합된 후보나 AI 후보와 이름이 겹치면
    // (포함 관계) 중복이라 보고 넣지 않는다.
    const safety = titleSafetyNetCandidate(opts.title);
    if (safety) {
      const sKey = safety.name.replace(/\s+/g, "").toLowerCase();
      const overlaps = (name: string) => {
        const k = name.replace(/\s+/g, "").toLowerCase();
        return k.includes(sKey) || sKey.includes(k);
      };
      if (
        !merged.some((c) => overlaps(c.name)) &&
        !ai.candidates.some((c) => overlaps(c.name))
      ) {
        merged.push(safety);
        seen.add(sKey);
      }
    }
    for (const c of ai.candidates) {
      const key = c.name.replace(/\s+/g, "").toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      merged.push(c);
    }
    return {
      candidates: merged.slice(0, opts.limit),
      method: "ai",
      aiStatus: "ok",
    };
  }
  return {
    candidates: opts.rules().slice(0, opts.limit),
    method: "rules",
    aiStatus: ai.status,
    ...(ai.error ? { aiError: ai.error } : {}),
  };
}

async function extractNaverBlog(url: URL): Promise<ExtractResult> {
  // blog.naver.com/{blogId}/{logNo} 또는 PostView 주소를 blogId/logNo로 변환
  let blogId = "";
  let logNo = "";
  if (url.pathname.includes("PostView")) {
    blogId = url.searchParams.get("blogId") ?? "";
    logNo = url.searchParams.get("logNo") ?? "";
  } else {
    const parts = url.pathname.split("/").filter(Boolean);
    if (parts.length >= 2) [blogId, logNo] = parts;
  }
  if (!blogId || !logNo || !/^\d+$/.test(logNo)) {
    return {
      ok: false,
      reason: "네이버 블로그 글 주소가 아니에요. 글 하나를 연 주소를 넣어 주세요.",
    };
  }
  // 원본 주소는 프레임셋 껍데기뿐이라 PostView 본문 문서를 직접 가져온다
  const postViewUrl =
    `https://blog.naver.com/PostView.naver?blogId=${blogId}&logNo=${logNo}`;
  const html = await fetchText(postViewUrl);

  let title = metaContent(html, "og:title")
    .replace(/\s*:\s*네이버 블로그\s*$/, "")
    .trim();
  if (!title) {
    const m = html.match(/se-title-text[^>]*>([\s\S]*?)<\/div>/);
    if (m) title = htmlToText(m[1]).trim();
  }
  const description = metaContent(html, "og:description");

  // 본문 추출: 스마트에디터는 문단(se-text-paragraph)만 뽑는 게 가장 깨끗하다.
  // (통째로 태그를 벗기면 data-* 속성의 JSON 설정값이 텍스트로 새어 나온다)
  const paras = [
    ...html.matchAll(
      /<p class="se-text-paragraph[^"]*"[^>]*>([\s\S]*?)<\/p>/g,
    ),
  ]
    .map((m) => htmlToText(m[1]).trim())
    .filter(Boolean);
  let bodyText = paras.join("\n");
  if (bodyText.length < 50) {
    // 폴백: 본문 영역을 잘라내 태그 제거 (구에디터 등)
    let bodyHtml = html;
    const startMarkers = ["se-main-container", 'id="postViewArea"', "postViewArea"];
    for (const marker of startMarkers) {
      const idx = html.indexOf(marker);
      if (idx >= 0) {
        bodyHtml = html.slice(idx, idx + 400000);
        break;
      }
    }
    bodyText = htmlToText(bodyHtml);
  }
  if (bodyText.length < 50 && !title) {
    return {
      ok: false,
      reason: "블로그 본문을 읽지 못했어요. 비공개 글이거나 주소가 잘못됐을 수 있어요.",
    };
  }
  const { candidates, method, aiStatus, aiError } = await finalizeCandidates({
    aiText: [title, description, bodyText].filter(Boolean).join("\n"),
    rules: () => extractCandidates(title, description, bodyText),
    limit: 20,
    title,
  });
  return {
    ok: true,
    title,
    candidates,
    source: "naver_blog",
    method,
    ai_status: aiStatus,
    ...(aiError ? { ai_error: aiError } : {}),
  };
}

async function extractYouTube(url: URL): Promise<ExtractResult> {
  const original = url.toString();
  let title = "";
  let description = "";
  try {
    const oembed = await fetchText(
      `https://www.youtube.com/oembed?url=${encodeURIComponent(original)}&format=json`,
      8000,
    );
    const json = JSON.parse(oembed);
    title = String(json.title ?? "");
  } catch {
    // oEmbed 실패 시 페이지 메타로 폴백
  }
  try {
    const html = await fetchText(original, 10000);
    if (!title) title = metaContent(html, "og:title");
    description = metaContent(html, "og:description");
  } catch {
    // 메타를 못 읽어도 제목만으로 후보 추출 시도
  }
  if (!title) {
    return {
      ok: false,
      reason: "유튜브 영상 제목을 읽지 못했어요. 삭제됐거나 비공개 영상일 수 있어요.",
    };
  }
  const { candidates, method, aiStatus, aiError } = await finalizeCandidates({
    aiText: [title, description].filter(Boolean).join("\n"),
    rules: () => extractCandidates(title, description, description),
    limit: 20,
    title,
  });
  return {
    ok: true,
    title,
    candidates,
    source: "youtube",
    method,
    ai_status: aiStatus,
    ...(aiError ? { ai_error: aiError } : {}),
  };
}

// 인스타그램 URL에서 게시물 종류와 숏코드를 뽑는다.
// /reel/{code}/, /reels/{code}/, /p/{code}/, /tv/{code}/ 와
// /{username}/reel/{code}/ 형태를 모두 인식한다.
function parseInstagramTarget(
  url: URL,
): { seg: string; code: string } | null {
  const m = url.pathname.match(/\/(reel|reels|p|tv)\/([A-Za-z0-9_-]+)/);
  if (!m) return null;
  return { seg: m[1] === "reels" ? "reel" : m[1], code: m[2] };
}

// 임베드 페이지 HTML에서 캡션 전문, 계정명, 위치 태그를 뽑는다.
// 임베드에는 og 메타가 없고, 캡션은 class="Caption" div 안에
// 계정명 링크 + 캡션 텍스트 형태로 들어 있다.
function parseInstagramEmbed(
  html: string,
): { username: string; caption: string; locations: string[] } {
  let username = "";
  let caption = "";
  const capIdx = html.indexOf('class="Caption"');
  if (capIdx >= 0) {
    // Caption div의 여는 태그 끝부터, 댓글 영역(CaptionComments) 앞까지
    const tagEnd = html.indexOf(">", capIdx);
    let seg = html.slice(tagEnd + 1, tagEnd + 20001);
    const cut = seg.indexOf('class="CaptionComments"');
    if (cut >= 0) {
      const lt = seg.lastIndexOf("<", cut);
      seg = seg.slice(0, lt >= 0 ? lt : cut);
    }
    const userM = seg.match(/class="CaptionUsername"[^>]*>([^<]+)</);
    if (userM) username = decodeEntities(userM[1]).trim();
    caption = htmlToText(seg).trim();
    // 캡션 텍스트 맨 앞에 붙은 계정명 제거
    if (username && caption.startsWith(username)) {
      caption = caption.slice(username.length).trim();
    }
  }
  const locations: string[] = [];
  for (
    const m of html.matchAll(
      /href="[^"]*\/explore\/locations\/[^"]*"[^>]*>([^<]{1,60})</g,
    )
  ) {
    const name = decodeEntities(m[1]).trim();
    if (name && !locations.includes(name)) locations.push(name);
  }
  return { username, caption, locations };
}

async function extractInstagram(url: URL): Promise<ExtractResult> {
  // 1) 원본 페이지 og 시도. 크롤러 UA로만 og 메타가 돌아오는 경우가
  //    많아 CRAWLER_UA를 쓴다. og:description 안 따옴표 구간이 캡션인데,
  //    잘려서 오는 경우가 많다.
  let ogTitle = "";
  let ogDescription = "";
  let ogCaption = "";
  try {
    const html = await fetchText(url.toString(), 10000, CRAWLER_UA);
    ogTitle = metaContent(html, "og:title");
    ogDescription = metaContent(html, "og:description");
    const cap = ogDescription.match(/["“]([^"”]{10,})["”]/);
    if (cap) ogCaption = cap[1].trim();
  } catch (e) {
    // 허용 목록 밖으로 리다이렉트된 경우는 폴백으로 삼키지 않고
    // 핸들러가 "지원하지 않는 사이트"로 안내하게 그대로 던진다
    if (e instanceof BlockedUrlError) throw e;
    // 그 외 원본이 막히면 임베드로 폴백
  }

  // 2) 임베드 페이지 시도. 로그인 없이 열리는 경우가 많고 캡션 전문과
  //    위치 태그가 들어 있다. 임베드 URL은 코드가 instagram.com으로
  //    구성하므로 허용 목록 검사를 그대로 통과한다.
  let embedCaption = "";
  let embedUsername = "";
  let locations: string[] = [];
  const target = parseInstagramTarget(url);
  if (target) {
    try {
      const embedUrl =
        `https://www.instagram.com/${target.seg}/${target.code}/embed/captioned/`;
      const html = await fetchText(embedUrl, 10000, CRAWLER_UA);
      const parsed = parseInstagramEmbed(html);
      embedCaption = parsed.caption;
      embedUsername = parsed.username;
      locations = parsed.locations;
    } catch (e) {
      if (e instanceof BlockedUrlError) throw e;
      // 임베드까지 막히면 og 결과로 폴백
    }
  }

  // og 캡션이 빈약하면(없거나 임베드 전문보다 짧으면) 임베드를 쓴다.
  const useEmbed = embedCaption.length > ogCaption.length;
  const caption = useEmbed ? embedCaption : ogCaption;
  const genericTitle = !ogTitle || ogTitle.trim() === "Instagram";

  if (!caption && genericTitle && locations.length === 0) {
    return {
      ok: false,
      reason:
        "인스타그램이 로그인 벽으로 막아서 게시물 내용을 읽지 못했어요. 장소는 아래에서 직접 입력해 주세요.",
    };
  }

  const title = !genericTitle
    ? ogTitle
    : embedUsername
    ? `인스타그램 게시물 (@${embedUsername})`
    : "인스타그램 게시물";
  // 제목의 "Instagram의 ~님" 표기에서 표시 이름을 뽑아 계정 파편
  // 제외 목록에 넣는다 (예: "soso님", "soso")
  const excludeNames: string[] = [];
  const dispM = ogTitle.match(/Instagram의\s+(.+?)님/);
  if (dispM) {
    excludeNames.push(dispM[1].trim(), `${dispM[1].trim()}님`);
  }
  if (embedUsername) excludeNames.push(embedUsername);
  const { candidates, method, aiStatus, aiError } = await finalizeCandidates({
    aiText: [
      caption,
      locations.length ? `위치 태그: ${locations.join(", ")}` : "",
    ].filter(Boolean).join("\n"),
    // 위치 태그는 AI 경로에서는 pinned으로 맨 앞에 유지되고,
    // 규칙 경로에서는 아래 콜백이 기존처럼 병합한다.
    pinned: locations,
    title: ogTitle,
    rules: () => {
      const list = extractCandidates(ogTitle, ogDescription, caption, {
        source: "instagram",
        username: embedUsername,
        excludeNames,
      });
      // 위치 태그는 실제 장소일 가능성이 가장 높아 맨 앞에 두고 likely로 표시
      for (const loc of [...locations].reverse()) {
        const name = cleanCandidate(loc);
        if (!isValidCandidate(name)) continue;
        const key = name.replace(/\s+/g, "").toLowerCase();
        const existing = list.find(
          (c) => c.name.replace(/\s+/g, "").toLowerCase() === key,
        );
        if (existing) {
          existing.likely = true;
        } else {
          list.unshift({ name, likely: true });
        }
      }
      return list;
    },
    limit: 12,
  });
  return {
    ok: true,
    title,
    candidates,
    source: "instagram",
    source_detail: useEmbed ? "embed" : "og",
    method,
    ai_status: aiStatus,
    ...(aiError ? { ai_error: aiError } : {}),
  };
}

async function extractGeneric(url: URL): Promise<ExtractResult> {
  const html = await fetchText(url.toString());
  const title = metaContent(html, "og:title");
  const description = metaContent(html, "og:description");
  const bodyText = htmlToText(html);

  if (!title && bodyText.length < 100) {
    return {
      ok: false,
      reason:
        "페이지 내용을 읽지 못했어요. 로그인 벽이 있거나 주소가 잘못됐을 수 있어요.",
    };
  }
  const { candidates, method, aiStatus, aiError } = await finalizeCandidates({
    aiText: [title, description, bodyText].filter(Boolean).join("\n"),
    rules: () => extractCandidates(title, description, bodyText),
    limit: 20,
    title,
  });
  return {
    ok: true,
    title: title || url.hostname,
    candidates,
    source: "web",
    method,
    ai_status: aiStatus,
    ...(aiError ? { ai_error: aiError } : {}),
  };
}

// === 장소 검색 (find-places): Baidu 지도 공개 웹 검색 ===
// 중국 장소는 OpenStreetMap(Nominatim) 커버리지가 얇아 없는 경우가
// 많고, 고덕지도(Amap)는 개발자 키 없이는 서버에서 조회할 수 없어,
// 프로토타입에서 검증된 Baidu 공개 웹 검색(map.baidu.com/?qt=s)을
// 쓴다. Baidu는 좌표를 자체 메르카토르 격자(BD-09MC)로 돌려주므로
// BD-09MC → BD-09 → GCJ-02 → WGS-84 로 변환해 저장 좌표 체계
// (WGS-84)로 맞춘다. 변환 상수·공식은 gcoord 라이브러리(MIT)를
// 따르고, 상하이 랜드마크 기준으로 실측과 대조 검증돼 있다.
//
// SSRF 관련: 이 검색이 호출하는 주소는 코드에 고정된
// https://map.baidu.com/ 하나뿐이고, 사용자 입력(검색어)은 wd 쿼리
// 파라미터로만 들어간다. 사용자가 준 URL을 가져오는 것이 아니므로
// 링크 추출 경로의 ALLOWED_HOSTS 검사는 적용하지 않는다.

const MC_BAND = [12890594.86, 8362377.87, 5591021, 3481989.83, 1678043.12, 0];
const MC_TO_LL: number[][] = [
  [1.410526172116255e-8, 0.00000898305509648872, -1.9939833816331, 200.9824383106796, -187.2403703815547, 91.6087516669843, -23.38765649603339, 2.57121317296198, -0.03801003308653, 17337981.2],
  [-7.435856389565537e-9, 0.000008983055097726239, -0.78625201886289, 96.32687599759846, -1.85204757529826, -59.36935905485877, 47.40033549296737, -16.50741931063887, 2.28786674699375, 10260144.86],
  [-3.030883460898826e-8, 0.00000898305509983578, 0.30071316287616, 59.74293618442277, 7.357984074871, -25.38371002664745, 13.45380521110908, -3.29883767235584, 0.32710905363475, 6856817.37],
  [-1.981981304930552e-8, 0.000008983055099779535, 0.03278182852591, 40.31678527705744, 0.65659298677277, -4.44255534477492, 0.85341911805263, 0.12923347998204, -0.04625736007561, 4482777.06],
  [3.09191371068437e-9, 0.000008983055096812155, 0.00006995724062, 23.10934304144901, -0.00023663490511, -0.6321817810242, -0.00663494467273, 0.03430082397953, -0.00466043876332, 2555164.4],
  [2.890871144776878e-9, 0.000008983055095805407, -3.068298e-8, 7.47137025468032, -0.00000353937994, -0.02145144861037, -0.00001234426596, 0.00010322952773, -0.00000323890364, 826088.5],
];

function bd09McToBd09(x: number, y: number): { lng: number; lat: number } {
  let f: number[] = MC_TO_LL[MC_TO_LL.length - 1] ?? [];
  for (let i = 0; i < MC_BAND.length; i++) {
    const band = MC_BAND[i];
    const row = MC_TO_LL[i];
    if (band !== undefined && row !== undefined && Math.abs(y) >= band) {
      f = row;
      break;
    }
  }
  const [c0 = 0, c1 = 0, c2 = 0, c3 = 0, c4 = 0, c5 = 0, c6 = 0, c7 = 0, c8 = 0, c9 = 1] = f;
  const cc = Math.abs(y) / c9;
  let xt = c0 + c1 * Math.abs(x);
  let yt = c2 + c3 * cc + c4 * cc ** 2 + c5 * cc ** 3 + c6 * cc ** 4 + c7 * cc ** 5 + c8 * cc ** 6;
  xt *= x < 0 ? -1 : 1;
  yt *= y < 0 ? -1 : 1;
  return { lng: xt, lat: yt };
}

function bd09ToGcj02(lon: number, lat: number): { lng: number; lat: number } {
  const factor = (Math.PI * 3000.0) / 180.0;
  const x = lon - 0.0065;
  const y = lat - 0.006;
  const z = Math.sqrt(x * x + y * y) - 0.00002 * Math.sin(y * factor);
  const theta = Math.atan2(y, x) - 0.000003 * Math.cos(x * factor);
  return { lng: z * Math.cos(theta), lat: z * Math.sin(theta) };
}

const GCJ_A = 6378245;
const GCJ_EE = 0.006693421622965823;

function gcjTransformLat(x: number, y: number): number {
  let ret = -100 + 2 * x + 3 * y + 0.2 * y * y + 0.1 * x * y + 0.2 * Math.sqrt(Math.abs(x));
  ret += ((20 * Math.sin(6 * x * Math.PI) + 20 * Math.sin(2 * x * Math.PI)) * 2) / 3;
  ret += ((20 * Math.sin(y * Math.PI) + 40 * Math.sin((y / 3) * Math.PI)) * 2) / 3;
  ret += ((160 * Math.sin((y / 12) * Math.PI) + 320 * Math.sin((y * Math.PI) / 30)) * 2) / 3;
  return ret;
}

function gcjTransformLon(x: number, y: number): number {
  let ret = 300 + x + 2 * y + 0.1 * x * x + 0.1 * x * y + 0.1 * Math.sqrt(Math.abs(x));
  ret += ((20 * Math.sin(6 * x * Math.PI) + 20 * Math.sin(2 * x * Math.PI)) * 2) / 3;
  ret += ((20 * Math.sin(x * Math.PI) + 40 * Math.sin((x / 3) * Math.PI)) * 2) / 3;
  ret += ((150 * Math.sin((x / 12) * Math.PI) + 300 * Math.sin((x / 30) * Math.PI)) * 2) / 3;
  return ret;
}

function gcjDelta(lon: number, lat: number): { dLon: number; dLat: number } {
  let dLon = gcjTransformLon(lon - 105, lat - 35);
  let dLat = gcjTransformLat(lon - 105, lat - 35);
  const radLat = (lat / 180) * Math.PI;
  let magic = Math.sin(radLat);
  magic = 1 - GCJ_EE * magic * magic;
  const sqrtMagic = Math.sqrt(magic);
  dLon = (dLon * 180) / ((GCJ_A / sqrtMagic) * Math.cos(radLat) * Math.PI);
  dLat = (dLat * 180) / (((GCJ_A * (1 - GCJ_EE)) / (magic * sqrtMagic)) * Math.PI);
  return { dLon, dLat };
}

function gcj02ToWgs84(lon: number, lat: number): { lng: number; lat: number } {
  let wgsLon = lon;
  let wgsLat = lat;
  for (let i = 0; i < 10; i++) {
    const { dLon, dLat } = gcjDelta(wgsLon, wgsLat);
    const dx = wgsLon + dLon - lon;
    const dy = wgsLat + dLat - lat;
    if (Math.abs(dx) <= 1e-6 && Math.abs(dy) <= 1e-6) break;
    wgsLon -= dx;
    wgsLat -= dy;
  }
  return { lng: wgsLon, lat: wgsLat };
}

/** Baidu Mercator point (meters, as returned by map.baidu.com) → WGS-84. */
function baiduMcToWgs84(x: number, y: number): { lng: number; lat: number } {
  const bd = bd09McToBd09(x, y);
  const gcj = bd09ToGcj02(bd.lng, bd.lat);
  return gcj02ToWgs84(gcj.lng, gcj.lat);
}

type FindPlaceCandidate = {
  name: string;
  // 후보 이름의 영어 표기. addEnglishNames가 배치 번역으로 붙이며,
  // 번역에 실패하면 필드 자체가 없다.
  name_en?: string;
  // 후보 이름의 한국어 표기. name_en과 같은 배치 번역으로 붙이며,
  // 번역에 실패하거나 한국어 표기가 비어 오면 필드 자체가 없다.
  name_ko?: string;
  address: string;
  lat: number;
  lng: number;
  source: "baidu";
};

// Baidu 공개 웹 검색 1회. 실패하면 빈 배열을 돌려준다(호출부가
// 후보 없음으로 처리).
async function baiduPlaceSearch(query: string): Promise<FindPlaceCandidate[]> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  try {
    const url =
      `https://map.baidu.com/?qt=s&c=1&rn=10&ie=utf-8&wd=` +
      encodeURIComponent(query);
    const res = await fetch(url, {
      signal: controller.signal,
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
        Referer: "https://map.baidu.com/",
        Accept: "application/json",
      },
    });
    if (!res.ok) return [];
    const data = (await res.json()) as { content?: unknown };
    const rows = Array.isArray(data.content) ? data.content : [];
    const out: FindPlaceCandidate[] = [];
    for (const r of rows) {
      if (!r || typeof r !== "object") continue;
      const row = r as { name?: unknown; addr?: unknown; x?: unknown; y?: unknown };
      const name = typeof row.name === "string" ? row.name.trim() : "";
      const x = Number(row.x);
      const y = Number(row.y);
      if (!name || !Number.isFinite(x) || !Number.isFinite(y) || x === 0 || y === 0) continue;
      // Baidu's x/y are Mercator meters × 100.
      const { lng, lat } = baiduMcToWgs84(x / 100, y / 100);
      const addr = typeof row.addr === "string" ? row.addr.trim() : "";
      out.push({ name, address: addr || name, lat, lng, source: "baidu" });
    }
    return out;
  } catch {
    return [];
  } finally {
    clearTimeout(timer);
  }
}

// find-places 본체: 쿼리를 최대 4개까지 순서대로 검색하고, 같은
// 이름+좌표 후보는 한 번만 남긴다.
async function findPlaces(queries: string[]): Promise<FindPlaceCandidate[]> {
  const seen = new Set<string>();
  const out: FindPlaceCandidate[] = [];
  for (const q of queries.slice(0, 4)) {
    const hits = await baiduPlaceSearch(q);
    for (const h of hits) {
      const key = `${h.name}|${h.lat.toFixed(5)}|${h.lng.toFixed(5)}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(h);
    }
  }
  return out;
}

// === 후보 이름 번역 (name_en·name_ko): Gemini 배치 번역 ===
// find-places·resolve-place 후보는 중국어 이름만으로 돌아와서,
// 중국어를 못 읽는 사용자는 후보가 맞는지 판단할 수 없다. 그래서
// 후보를 반환하기 전에 이름 목록 전체를 Gemini 한 번의 호출로
// 번역해 영어 표기(name_en)와 한국어 표기(name_ko)를 함께 붙인다
// (후보별 호출 금지).
// 번역은 부가 정보일 뿐이라, 키가 없거나 호출이 실패하거나 응답
// 형식이 깨지면 두 필드 없이 기존 후보를 그대로 돌려준다 — 번역
// 때문에 장소 검색 자체가 실패하면 안 된다. 한 이름에서 한쪽
// 표기만 오면 온 쪽만 붙인다.

const NAME_TRANSLATION_PROMPT_PREFIX =
  `너는 중국 장소 이름을 영어와 한국어로 번역하는 번역기다.
아래 JSON 배열의 장소 이름(중국어)을 각각 영어와 한국어로 번역해라.
- 브랜드·체인 이름은 널리 쓰이는 공식 영어 표기를 써라 (예: 黛茂诗酒店 → Demores Hotel, 华夏银行 → Huaxia Bank).
- 지점 괄호 안의 지명·역 이름도 번역해 괄호째 유지해라 (예: (上海豫园老西门地铁站店) → (Shanghai Yu Garden Laoximen Metro Station)).
- 한국어는 한국어로 읽을 수 있는 표기로 써라. 브랜드는 한국어 통용 표기가 있으면 그걸, 없으면 음역해라 (예: 黛茂诗酒店 → 데모레스 호텔, 点都德 → 디엔도더). 지점 괄호 안의 지명·역 이름도 번역하거나 음역해 괄호째 유지해라 (예: (上海豫园老西门地铁站店) → (상하이 위위안 라오시먼역점), (中海环宇荟店) → (중하이환위후이점)).
- 입력과 같은 순서·같은 개수로, 각 이름마다 {"en": "영어 표기", "ko": "한국어 표기"} 객체 하나씩을 담은 JSON 배열 하나만 출력해라. 설명은 붙이지 마라.

[장소 이름 목록]
`;

// 한자가 들어간 이름만 번역 대상이다. 이미 영어(라틴 문자) 위주인
// 이름은 번역 없이 그 자체가 name_en이 된다.
function nameNeedsTranslation(name: string): boolean {
  return /[一-鿿]/.test(name);
}

// 이름 하나의 번역 결과 쌍. 한쪽 표기가 비어 오면 그쪽은 빈
// 문자열이고, 호출부는 빈 쪽 필드를 붙이지 않는다.
type NameTranslation = { en: string; ko: string };

// 번역 시도 결과. 실패 시 status로 원인을 구분하고, error에는
// 짧은 원인(최대 200자)을 실어 함수 로그로만 남긴다(응답에는
// 싣지 않는다 — 번역 실패는 조용히 name_en·name_ko 없음으로
// 처리한다).
type NameTranslationOutcome =
  | { status: "ok"; names: NameTranslation[] }
  | { status: Exclude<AiStatus, "ok">; error?: string };

// 1회 시도 결과. httpStatus는 재시도 여부 판단에만 쓴다.
type NameTranslationAttemptOutcome = NameTranslationOutcome & {
  httpStatus?: number;
};

// 이름 목록 번역 1회 시도. 타임아웃은 시도마다 새로 건다.
async function attemptTranslateNames(
  names: string[],
  apiKey: string,
): Promise<NameTranslationAttemptOutcome> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), GEMINI_TIMEOUT_MS);
  try {
    const res = await fetch(geminiEndpoint(), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-goog-api-key": apiKey,
      },
      body: JSON.stringify({
        contents: [{
          parts: [{
            text: NAME_TRANSLATION_PROMPT_PREFIX + JSON.stringify(names),
          }],
        }],
        generationConfig: {
          responseMimeType: "application/json",
          // 번역 작업이라 깊은 추론이 필요 없어 LOW로 둔다.
          thinkingConfig: { thinkingLevel: "LOW" },
          maxOutputTokens: 2048,
        },
      }),
      signal: ctrl.signal,
    });
    if (!res.ok) {
      // Gemini 오류 본문에서 핵심 메시지만 뽑아 원인으로 남긴다.
      let detail = "";
      try {
        const errText = await res.text();
        try {
          const errJson = JSON.parse(errText);
          detail = String(
            errJson?.error?.message ?? errJson?.error?.status ?? "",
          );
        } catch {
          detail = errText;
        }
      } catch {
        // 오류 본문조차 못 읽으면 상태 코드만으로 충분하다
      }
      const aiError = scrubApiKey(
        `HTTP ${res.status}${detail ? `: ${detail}` : ""}`,
        apiKey,
      ).slice(0, 200);
      logAiFailure("error", aiError);
      return { status: "error", error: aiError, httpStatus: res.status };
    }
    let data: {
      candidates?: { content?: { parts?: { text?: unknown }[] } }[];
    };
    try {
      data = await res.json();
    } catch {
      logAiFailure("bad_response", "response_not_json");
      return { status: "bad_response", error: "response_not_json" };
    }
    const parts = data?.candidates?.[0]?.content?.parts;
    if (!Array.isArray(parts)) {
      logAiFailure("bad_response", "no_content_parts");
      return { status: "bad_response", error: "no_content_parts" };
    }
    const textOut = parts
      .map((p: { text?: unknown }) =>
        typeof p?.text === "string" ? p.text : ""
      )
      .join("")
      .trim();
    if (!textOut) {
      logAiFailure("bad_response", "empty_model_output");
      return { status: "bad_response", error: "empty_model_output" };
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(textOut);
    } catch {
      logAiFailure("bad_response", "model_output_not_json");
      return { status: "bad_response", error: "model_output_not_json" };
    }
    // 입력과 같은 순서·같은 개수여야 대조가 안전하다. 배열 자체가
    // 어긋나거나 원소가 객체도 문자열도 아니면 형식 깨짐으로 보고
    // 전체를 버린다. 원소 안에서는 한쪽 표기가 비거나 빠져도
    // 온 쪽만 살린다(빈 문자열로 둔다).
    if (!Array.isArray(parsed) || parsed.length !== names.length) {
      logAiFailure("bad_response", "translation_shape_mismatch");
      return { status: "bad_response", error: "translation_shape_mismatch" };
    }
    const cleanField = (v: unknown): string =>
      typeof v === "string" ? v.replace(/\s+/g, " ").trim() : "";
    const out: NameTranslation[] = [];
    for (const item of parsed as unknown[]) {
      // 문자열만 온 원소는 영어 표기로만 온 것으로 본다.
      if (typeof item === "string") {
        out.push({ en: cleanField(item), ko: "" });
        continue;
      }
      if (!item || typeof item !== "object" || Array.isArray(item)) {
        logAiFailure("bad_response", "translation_shape_mismatch");
        return {
          status: "bad_response",
          error: "translation_shape_mismatch",
        };
      }
      const obj = item as { en?: unknown; ko?: unknown };
      out.push({ en: cleanField(obj.en), ko: cleanField(obj.ko) });
    }
    return { status: "ok", names: out };
  } catch (e) {
    // 타임아웃(AbortController 중단)과 그 밖의 네트워크 오류를 구분한다.
    const aborted = ctrl.signal.aborted ||
      (e instanceof Error && e.name === "AbortError");
    if (aborted) {
      const aiError = `timeout_after_${GEMINI_TIMEOUT_MS}ms`;
      logAiFailure("timeout", aiError);
      return { status: "timeout", error: aiError };
    }
    const aiError = scrubApiKey(
      e instanceof Error ? e.message : String(e),
      apiKey,
    ).slice(0, 200);
    logAiFailure("error", aiError);
    return { status: "error", error: aiError };
  } finally {
    clearTimeout(timer);
  }
}

// 이름 목록을 한 번의 호출로 번역한다. 일시 오류(503·429·
// 타임아웃)면 기존 정책대로 1회 재시도한다. 끝내 실패하면
// null을 돌려주고, 호출부는 name_en·name_ko 없이 후보를 반환한다.
async function translateNames(
  names: string[],
): Promise<NameTranslation[] | null> {
  const apiKey = geminiApiKey();
  if (!apiKey) {
    logAiFailure("no_key", "GEMINI_API_KEY not set");
    return null;
  }
  for (let attempt = 1; attempt <= GEMINI_MAX_ATTEMPTS; attempt++) {
    const outcome = await attemptTranslateNames(names, apiKey);
    if (outcome.status === "ok") return outcome.names;
    const retryable = outcome.status === "timeout" ||
      outcome.httpStatus === 503 || outcome.httpStatus === 429;
    if (!retryable || attempt >= GEMINI_MAX_ATTEMPTS) break;
    await new Promise((resolve) =>
      setTimeout(resolve, GEMINI_RETRY_DELAY_MS)
    );
  }
  return null;
}

// 후보 배열에 name_en과 name_ko를 붙여 돌려준다. 같은 이름은
// 한 번만 번역 목록에 넣는다. 번역이 필요 없는(이미 영어 위주인)
// 이름은 그 자체가 name_en이 된다(name_ko는 붙이지 않는다).
// 번역 호출이 실패하면 후보를 손대지 않고 그대로 돌려주고,
// 한 이름에서 한쪽 표기만 오면 온 쪽 필드만 붙인다.
async function addEnglishNames(
  candidates: FindPlaceCandidate[],
): Promise<FindPlaceCandidate[]> {
  if (candidates.length === 0) return candidates;
  const uniqueNames: string[] = [];
  const seenNames = new Set<string>();
  for (const c of candidates) {
    if (!nameNeedsTranslation(c.name) || seenNames.has(c.name)) continue;
    seenNames.add(c.name);
    uniqueNames.push(c.name);
  }
  if (uniqueNames.length === 0) {
    return candidates.map((c) => ({ ...c, name_en: c.name }));
  }
  const translated = await translateNames(uniqueNames);
  if (!translated) return candidates;
  const byName = new Map<string, NameTranslation>(
    uniqueNames.map((n, i) => [n, translated[i] ?? { en: "", ko: "" }]),
  );
  return candidates.map((c) => {
    if (!nameNeedsTranslation(c.name)) return { ...c, name_en: c.name };
    const t = byName.get(c.name);
    if (!t) return { ...c };
    const out: FindPlaceCandidate = { ...c };
    if (t.en) out.name_en = t.en;
    if (t.ko) out.name_ko = t.ko;
    return out;
  });
}

// === 이름 해석 (resolve-place): 한글 이름 → 현지 이름 제안 + 실측 검증 ===
// 한글 이름(예: "데모레스 호텔")은 Baidu·OSM 어디에도 그 표기
// 그대로는 없어서 직접 검색이 안 된다. 그래서 2단계로 찾는다.
//   1단계: Gemini가 현지(중국어) 정식 이름·중국어 주소·영어 이름을
//          제안한다. 먼저 Google Search 그라운딩을 붙여 시도하고,
//          실패하면(원인 무관) 그라운딩 없이 다시 시도한다.
//   2단계: 제안을 Baidu 검색으로 조회해, 이름 핵심이나 주소의
//          도로명+번지가 실제로 일치하는 POI만 후보로 인정한다.
// 검증되지 않은 제안으로는 후보를 만들지 않는다.

// === RESOLVE CORE START ===
// 아래 구간은 순수 JS(타입 표기 없음)입니다. Node 테스트에서 그대로
// 추출해 실행할 수 있게 유지하세요.

// 현지 이름의 핵심 부분: 지점 안내 괄호 앞부분만 남긴다.
// 예: "黛茂诗酒店(上海豫园老西门地铁站店)" → "黛茂诗酒店"
function corePlaceName(name) {
  return String(name ?? "")
    .split(/[（(]/)[0]
    .replace(/\s+/g, "")
    .trim();
}

// 중국어 주소에서 도로명+번지 토큰을 뽑는다.
// 예: "上海市黄浦区中华路1465号" → "中华路1465号"
// 도로 접미사+번지 위치를 먼저 찾고, 접미사 바로 앞의 한자를
// 거슬러 올라가 도로명만 잡는다(행정구역 접두사가 딸려 오면
// POI 주소 표기와 어긋나 대조가 실패하기 때문). 경계 글자
// (市·区·县·镇·乡·省)에서는 거슬러 올라가기를 멈춘다.
// 도로 접미사가 없으면 번지 토큰만이라도 돌려준다.
function addressRoadToken(address) {
  const s = String(address ?? "").replace(/\s+/g, "");
  const m = s.match(/(路|街|大道|巷|弄|胡同)(\d+(?:-\d+)?号)/);
  if (m && m.index !== undefined) {
    const BOUNDARY = "市区县镇乡省";
    let start = m.index;
    let count = 0;
    while (start > 0 && count < 4) {
      const ch = s[start - 1];
      if (!/[一-鿿]/.test(ch) || BOUNDARY.includes(ch)) break;
      start--;
      count++;
    }
    return s.slice(start, m.index) + m[1] + m[2];
  }
  const n = s.match(/(\d+(?:-\d+)?号)/);
  return n ? n[1] : "";
}

// Gemini가 돌려준 텍스트에서 제안 JSON을 꺼낸다. 순수 JSON,
// 코드펜스, 설명 문장에 섞인 JSON을 모두 허용한다.
// JSON은 읽혔지만 현지 이름이 비어 있으면(null 등) "모름"으로 보고
// null을 돌려주고, JSON 자체를 못 읽어도 null을 돌려준다
// (둘의 구분은 호출부가 텍스트에 객체가 있었는지로 판단한다).
function parseResolveSuggestionText(text) {
  const raw = String(text ?? "").trim();
  if (!raw) return null;
  let parsed = null;
  try {
    parsed = JSON.parse(raw);
  } catch { /* 아래 폴백으로 */ }
  if (!parsed || typeof parsed !== "object") {
    const start = raw.indexOf("{");
    const end = raw.lastIndexOf("}");
    if (start >= 0 && end > start) {
      try {
        parsed = JSON.parse(raw.slice(start, end + 1));
      } catch {
        parsed = null;
      }
    }
  }
  if (!parsed || typeof parsed !== "object") return null;
  const clean = (v) =>
    typeof v === "string" && v.trim() &&
      v.trim().toLowerCase() !== "null"
      ? v.trim()
      : "";
  const local = clean(parsed.local_name);
  if (!local) return null;
  return {
    local_name: local,
    address: clean(parsed.address),
    english_name: clean(parsed.english_name),
  };
}

// Baidu POI가 Gemini 제안과 같은 장소인지 판정한다.
// 이름: POI 이름의 핵심에 제안 현지명의 핵심이 들어 있거나 그 반대.
// 주소: POI 주소에 제안 주소의 도로명+번지 토큰이 들어 있으면 일치.
function poiMatchesSuggestion(poi, suggestion) {
  if (!poi || !suggestion) return false;
  const poiCore = corePlaceName(poi.name);
  const sugCore = corePlaceName(suggestion.local_name);
  if (sugCore.length >= 2 && poiCore) {
    if (poiCore.includes(sugCore) || sugCore.includes(poiCore)) return true;
  }
  const token = addressRoadToken(suggestion.address);
  if (token) {
    const poiAddr = String(poi.address ?? "").replace(/\s+/g, "");
    if (poiAddr.includes(token)) return true;
  }
  return false;
}

// resolve-place 본체. suggest(name, city)는 Gemini 제안 함수,
// search(query)는 Baidu 검색 함수로 주입받는다(테스트에서 스텁 교체).
// city는 Baidu 쿼리용으로 정규화된 도시명(중국어 표기)을 받는다.
async function resolvePlaceCore(name, city, suggest, search) {
  const outcome = await suggest(name, city);
  if (!outcome || outcome.status !== "ok") {
    const status = outcome?.status ?? "error";
    const reason = status === "no_key"
      ? "AI 이름 찾기가 설정돼 있지 않아요."
      : status === "timeout"
      ? "AI 이름 찾기가 시간 초과로 실패했어요."
      : "AI 이름 찾기에 실패했어요.";
    // 진단용으로 추출 경로와 같은 형식(ai_status/ai_error)을 함께
    // 실어 보낸다. error는 제안 단계에서 이미 키 값을 지우고
    // 200자로 줄인 문자열이다.
    return {
      ok: false,
      reason,
      ai_status: status,
      ...(outcome?.error ? { ai_error: outcome.error } : {}),
    };
  }
  const sug = outcome.suggestion;
  if (!sug || !sug.local_name) {
    return { ok: false, reason: "이 이름으로는 현지 이름을 찾지 못했어요." };
  }
  const queries = [];
  queries.push(city ? `${sug.local_name} ${city}` : sug.local_name);
  if (sug.address) queries.push(sug.address);
  const seen = new Set();
  const candidates = [];
  for (const q of queries) {
    const hits = (await search(q)) ?? [];
    for (const h of hits) {
      if (!poiMatchesSuggestion(h, sug)) continue;
      const key = `${h.name}|${Number(h.lat).toFixed(5)}|${Number(h.lng).toFixed(5)}`;
      if (seen.has(key)) continue;
      seen.add(key);
      candidates.push(h);
    }
  }
  if (candidates.length === 0) {
    return {
      ok: false,
      reason: "제안받은 현지 이름으로 실제 장소를 확인하지 못했어요.",
    };
  }
  return {
    ok: true,
    resolved: {
      local_name: sug.local_name,
      address: sug.address ?? "",
      english_name: sug.english_name ?? "",
    },
    candidates,
  };
}

// === RESOLVE CORE END ===

// Baidu 쿼리에 붙일 도시명: 한글 도시명은 중국어 표기로 바꾼다.
// (Baidu는 한글 쿼리에 결과를 주지 않는 경우가 많다.)
const RESOLVE_CITY_MAP: Record<string, string> = {
  "상하이": "上海",
  "상해": "上海",
  "베이징": "北京",
  "북경": "北京",
  "광저우": "广州",
  "선전": "深圳",
  "심천": "深圳",
  "청두": "成都",
  "성도": "成都",
  "충칭": "重庆",
  "중경": "重庆",
  "시안": "西安",
  "서안": "西安",
  "항저우": "杭州",
  "항주": "杭州",
  "난징": "南京",
  "남경": "南京",
  "쑤저우": "苏州",
  "소주": "苏州",
  "우한": "武汉",
  "무한": "武汉",
  "샤먼": "厦门",
  "하문": "厦门",
  "창사": "长沙",
  "장사": "长沙",
  "톈진": "天津",
  "천진": "天津",
  "홍콩": "香港",
};

function baiduCityName(city?: string): string | undefined {
  const c = String(city ?? "").trim();
  if (!c) return undefined;
  return RESOLVE_CITY_MAP[c] ?? c;
}

type PlaceSuggestion = {
  local_name: string;
  address: string;
  english_name: string;
};

type SuggestOutcome =
  | { status: "ok"; suggestion: PlaceSuggestion | null }
  | { status: Exclude<AiStatus, "ok">; error?: string };

// 1회 시도 결과. httpStatus/toolError는 재시도와 그라운딩 폴백
// 판단에만 쓰고, 바깥으로 내보내는 SuggestOutcome에는 포함하지 않는다.
type SuggestAttemptOutcome = SuggestOutcome & {
  httpStatus?: number;
  toolError?: boolean;
};

function buildResolvePrompt(name: string, city?: string): string {
  return `너는 중국 현지 장소 이름을 찾는 도우미다.
한국어로 된 장소 이름이 주어지면, 그 장소의 중국 현지 정식 이름(간체자), 중국어 주소, 영어 이름을 찾아라.
실제로 존재하는 장소라고 확신할 때만 답해라. 확신이 없으면 지어내지 말고 모든 필드를 null로 답해라.
설명 없이 JSON 객체 하나만 출력해라. 형식: {"local_name": "黛茂诗酒店", "address": "上海市黄浦区中华路1465号", "english_name": "Demores Hotel"}
모르면: {"local_name": null, "address": null, "english_name": null}

[찾을 장소]
이름: ${name}${city ? `\n도시: ${city}` : ""}`;
}

// Gemini 제안 호출 1회. 타임아웃은 시도마다 새로 건다.
// useGrounding이면 Google Search 그라운딩 도구를 붙인다. 그라운딩
// 사용 시에는 JSON 응답 강제(responseMimeType)를 걸지 않는다.
// 그라운딩과 함께 쓰면 API가 거부할 수 있어, 프롬프트로만 JSON을
// 요구하고 파싱 쪽(parseResolveSuggestionText)에서 관대하게 읽는다.
async function attemptResolveSuggestion(
  name: string,
  city: string | undefined,
  apiKey: string,
  useGrounding: boolean,
): Promise<SuggestAttemptOutcome> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), GEMINI_TIMEOUT_MS);
  try {
    const requestBody: Record<string, unknown> = {
      contents: [{ parts: [{ text: buildResolvePrompt(name, city) }] }],
      generationConfig: {
        // 추출 작업이라 깊은 추론이 필요 없어 LOW로 둔다.
        thinkingConfig: { thinkingLevel: "LOW" },
        maxOutputTokens: 512,
        ...(useGrounding ? {} : { responseMimeType: "application/json" }),
      },
    };
    if (useGrounding) {
      requestBody.tools = [{ google_search: {} }];
    }
    const res = await fetch(geminiEndpoint(), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-goog-api-key": apiKey,
      },
      body: JSON.stringify(requestBody),
      signal: ctrl.signal,
    });
    if (!res.ok) {
      // Gemini 오류 본문에서 핵심 메시지만 뽑아 원인으로 남긴다.
      let detail = "";
      try {
        const errText = await res.text();
        try {
          const errJson = JSON.parse(errText);
          detail = String(
            errJson?.error?.message ?? errJson?.error?.status ?? "",
          );
        } catch {
          detail = errText;
        }
      } catch {
        // 오류 본문조차 못 읽으면 상태 코드만으로 충분하다
      }
      const aiError = scrubApiKey(
        `HTTP ${res.status}${detail ? `: ${detail}` : ""}`,
        apiKey,
      ).slice(0, 200);
      logAiFailure("error", aiError);
      // 그라운딩 도구 자체가 거부된 경우(400 등)는 호출부가 그라운딩
      // 없이 다시 시도할 수 있게 표시해 둔다.
      const toolError = useGrounding &&
        (res.status === 400 || /tool|grounding|google_search/i.test(detail));
      return {
        status: "error",
        error: aiError,
        httpStatus: res.status,
        toolError,
      };
    }
    let data: {
      candidates?: { content?: { parts?: { text?: unknown }[] } }[];
    };
    try {
      data = await res.json();
    } catch {
      logAiFailure("bad_response", "response_not_json");
      return { status: "bad_response", error: "response_not_json" };
    }
    const parts = data?.candidates?.[0]?.content?.parts;
    if (!Array.isArray(parts)) {
      logAiFailure("bad_response", "no_content_parts");
      return { status: "bad_response", error: "no_content_parts" };
    }
    const textOut = parts
      .map((p: { text?: unknown }) =>
        typeof p?.text === "string" ? p.text : ""
      )
      .join("")
      .trim();
    if (!textOut) {
      logAiFailure("bad_response", "empty_model_output");
      return { status: "bad_response", error: "empty_model_output" };
    }
    const parsed = parseResolveSuggestionText(textOut) as
      | PlaceSuggestion
      | null;
    if (parsed) return { status: "ok", suggestion: parsed };
    // JSON 객체는 있는데 현지 이름이 비어 있으면 "모름"이다.
    if (/\{[\s\S]*\}/.test(textOut)) {
      return { status: "ok", suggestion: null };
    }
    logAiFailure("bad_response", "model_output_not_json");
    return { status: "bad_response", error: "model_output_not_json" };
  } catch (e) {
    // 타임아웃(AbortController 중단)과 그 밖의 네트워크 오류를 구분한다.
    const aborted = ctrl.signal.aborted ||
      (e instanceof Error && e.name === "AbortError");
    if (aborted) {
      const aiError = `timeout_after_${GEMINI_TIMEOUT_MS}ms`;
      logAiFailure("timeout", aiError);
      return { status: "timeout", error: aiError };
    }
    const aiError = scrubApiKey(
      e instanceof Error ? e.message : String(e),
      apiKey,
    ).slice(0, 200);
    logAiFailure("error", aiError);
    return { status: "error", error: aiError };
  } finally {
    clearTimeout(timer);
  }
}

// 제안 호출에 기존 타임아웃/재시도 정책을 적용한다.
// 일시 오류(503·429·타임아웃)면 잠깐 쉬고 1회만 재시도한다.
// 도구 오류는 같은 방식으로 재시도해도 반복되므로 바로 돌려줘서
// 호출부가 그라운딩 없는 방식으로 넘어가게 한다.
async function attemptResolveWithRetry(
  name: string,
  city: string | undefined,
  apiKey: string,
  useGrounding: boolean,
): Promise<SuggestAttemptOutcome> {
  let lastOutcome: SuggestAttemptOutcome = {
    status: "error",
    error: "not_attempted",
  };
  for (let attempt = 1; attempt <= GEMINI_MAX_ATTEMPTS; attempt++) {
    const outcome = await attemptResolveSuggestion(
      name,
      city,
      apiKey,
      useGrounding,
    );
    if (outcome.status === "ok") return outcome;
    lastOutcome = outcome;
    if (outcome.toolError) return outcome;
    const retryable = outcome.status === "timeout" ||
      outcome.httpStatus === 503 || outcome.httpStatus === 429;
    if (!retryable || attempt >= GEMINI_MAX_ATTEMPTS) break;
    await new Promise((resolve) =>
      setTimeout(resolve, GEMINI_RETRY_DELAY_MS)
    );
  }
  return lastOutcome;
}

// Gemini에게 현지 이름 제안을 받는다. 먼저 Google Search
// 그라운딩으로 시도하고, 결과가 ok가 아니면(도구 거부·과부하·
// 응답 파싱 실패 등 원인을 가리지 않고) 그라운딩 없이 한 번 더
// 시도한다. 각 방식 안에서는 기존 재시도 정책이 그대로 적용되고,
// 최종 결과는 마지막 시도(그라운딩 없는 시도)의 outcome이다.
async function suggestPlaceLocalName(
  name: string,
  city?: string,
): Promise<SuggestOutcome> {
  const apiKey = geminiApiKey();
  if (!apiKey) {
    logAiFailure("no_key", "GEMINI_API_KEY not set");
    return { status: "no_key" };
  }
  let outcome = await attemptResolveWithRetry(name, city, apiKey, true);
  if (outcome.status !== "ok") {
    outcome = await attemptResolveWithRetry(name, city, apiKey, false);
  }
  if (outcome.status === "ok") return outcome;
  const { httpStatus, toolError, ...rest } = outcome;
  return rest;
}

// resolve-place 본체: Gemini 제안을 Baidu 실측으로 검증한다.
// 도시명은 Baidu 쿼리에 쓸 수 있게 중국어 표기로 정규화해서
// 코어에 넘긴다(Gemini 프롬프트에도 그대로 쓰인다).
// 검증된 후보에는 find-places와 마찬가지로 영어 이름(name_en)과
// 한국어 이름(name_ko)을 배치 번역으로 붙여 돌려준다(번역 실패
// 시 두 필드 없이 반환).
async function resolvePlace(name: string, city?: string) {
  const queryCity = baiduCityName(city);
  const result = await resolvePlaceCore(
    name,
    queryCity,
    suggestPlaceLocalName,
    baiduPlaceSearch,
  ) as { ok: boolean; candidates?: FindPlaceCandidate[] };
  if (result.ok && Array.isArray(result.candidates)) {
    result.candidates = await addEnglishNames(result.candidates);
  }
  return result;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }
  if (req.method !== "POST") {
    return jsonResponse({ ok: false, reason: "POST 요청만 지원합니다." }, 405);
  }

  let body: {
    url?: unknown;
    action?: unknown;
    queries?: unknown;
    name?: unknown;
    city?: unknown;
  };
  try {
    body = await req.json();
  } catch {
    return jsonResponse({ ok: false, reason: "올바른 링크 주소를 넣어 주세요." }, 400);
  }

  // 장소 검색 모드: action이 "find-places"면 링크 추출이 아니라
  // 장소 이름 검색으로 동작한다. 이 경로는 사용자가 준 URL을
  // 가져오는 게 아니라 코드에 고정된 Baidu 주소만 호출하므로,
  // 아래 SSRF 허용 목록 검사를 적용하지 않는다.
  if (body?.action === "find-places") {
    const queries = (Array.isArray(body.queries) ? body.queries : [])
      .filter((q): q is string => typeof q === "string")
      .map((q) => q.trim())
      .filter(Boolean)
      .slice(0, 4);
    if (queries.length === 0) {
      return jsonResponse(
        { ok: false, reason: "검색할 장소 이름(queries)이 필요합니다." },
        400,
      );
    }
    const found = await findPlaces(queries);
    // 돌려주기 전에 영어 이름(name_en)과 한국어 이름(name_ko)을
    // 배치 번역으로 붙인다. 번역 실패 시에는 두 필드 없이 기존과
    // 동일하게 반환된다.
    const candidates = await addEnglishNames(found);
    return jsonResponse({ ok: true, candidates });
  }

  // 이름 해석 모드: action이 "resolve-place"면 한글 이름만으로
  // 중국 장소를 찾는다. Gemini가 현지 이름을 제안하고 Baidu
  // 실측으로 검증된 후보만 돌려주므로, 이 경로도 사용자가 준
  // URL을 가져오지 않아 SSRF 허용 목록 검사를 적용하지 않는다.
  if (body?.action === "resolve-place") {
    const name = typeof body.name === "string" ? body.name.trim() : "";
    if (!name) {
      return jsonResponse(
        { ok: false, reason: "찾을 장소 이름(name)이 필요합니다." },
        400,
      );
    }
    const city = typeof body.city === "string" ? body.city.trim() : "";
    const result = await resolvePlace(name, city || undefined);
    return jsonResponse(result);
  }

  let url: URL;
  try {
    if (!body?.url || typeof body.url !== "string") {
      return jsonResponse({ ok: false, reason: "url이 필요합니다." }, 400);
    }
    url = new URL(body.url.trim());
  } catch {
    return jsonResponse({ ok: false, reason: "올바른 링크 주소를 넣어 주세요." }, 400);
  }

  // SSRF 방지: 허용 목록에 있는 사이트만 읽는다. 여기서 막히면
  // 어떤 fetch도 일어나지 않는다.
  const gate = validateFetchUrl(url);
  if (!gate.ok) {
    return jsonResponse({ ok: false, reason: gate.reason });
  }

  try {
    let result: ExtractResult;
    if (/(^|\.)blog\.naver\.com$/.test(url.hostname)) {
      result = await extractNaverBlog(url);
    } else if (
      /(^|\.)youtube\.com$/.test(url.hostname) || url.hostname === "youtu.be"
    ) {
      result = await extractYouTube(url);
    } else if (/(^|\.)instagram\.com$/.test(url.hostname)) {
      result = await extractInstagram(url);
    } else {
      result = await extractGeneric(url);
    }
    return jsonResponse(result);
  } catch (e) {
    // 리다이렉트 등으로 허용 목록 밖 주소에 닿은 경우: 가져오기 실패가
    // 아니라 "지원하지 않는 사이트" 안내로 솔직히 돌려준다.
    if (e instanceof BlockedUrlError) {
      return jsonResponse({ ok: false, reason: e.message });
    }
    const msg = e instanceof Error ? e.message : String(e);
    return jsonResponse({
      ok: false,
      reason: `페이지를 가져오지 못했어요 (${msg}). 잠시 후 다시 시도하거나 장소를 직접 입력해 주세요.`,
    });
  }
});
