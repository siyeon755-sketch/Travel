// ============================================================
// extract-places — 링크 수집함 자동 추출 (Supabase Edge Function)
//
// POST { url } 을 받아 게시물을 서버에서 읽고, 제목과 장소 후보를
// 규칙 기반으로 뽑아 돌려줍니다. (브라우저는 CORS 때문에 외부
// 페이지를 직접 읽을 수 없어서 서버에서 가져옵니다.)
//
// 반환: { ok: true, title, candidates: [{ name, likely }], source }
//       { ok: false, reason }
//   likely=true인 후보만 화면에서 기본 체크된다.
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

type ExtractResult =
  | {
    ok: true;
    title: string;
    candidates: { name: string; likely?: boolean }[];
    source: string;
    source_detail?: string;
  }
  | { ok: false; reason: string };

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
  return {
    ok: true,
    title,
    candidates: extractCandidates(title, description, bodyText),
    source: "naver_blog",
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
  return {
    ok: true,
    title,
    candidates: extractCandidates(title, description, description),
    source: "youtube",
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
  const candidates = extractCandidates(ogTitle, ogDescription, caption, {
    source: "instagram",
    username: embedUsername,
    excludeNames,
  });
  // 위치 태그는 실제 장소일 가능성이 가장 높아 맨 앞에 두고 likely로 표시
  for (const loc of [...locations].reverse()) {
    const name = cleanCandidate(loc);
    if (!isValidCandidate(name)) continue;
    const key = name.replace(/\s+/g, "").toLowerCase();
    const existing = candidates.find(
      (c) => c.name.replace(/\s+/g, "").toLowerCase() === key,
    );
    if (existing) {
      existing.likely = true;
    } else {
      candidates.unshift({ name, likely: true });
    }
  }
  return {
    ok: true,
    title,
    candidates: candidates.slice(0, 12),
    source: "instagram",
    source_detail: useEmbed ? "embed" : "og",
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
  return {
    ok: true,
    title: title || url.hostname,
    candidates: extractCandidates(title, description, bodyText),
    source: "web",
  };
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

  let url: URL;
  try {
    const body = await req.json();
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
