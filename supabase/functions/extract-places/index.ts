// ============================================================
// extract-places — 링크 수집함 자동 추출 (Supabase Edge Function)
//
// POST { url } 을 받아 게시물을 서버에서 읽고, 제목과 장소 후보를
// 규칙 기반으로 뽑아 돌려줍니다. (브라우저는 CORS 때문에 외부
// 페이지를 직접 읽을 수 없어서 서버에서 가져옵니다.)
//
// 반환: { ok: true, title, candidates: [{ name }], source }
//       { ok: false, reason }
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
  if (PLACE_STOPWORDS.has(s)) return false;
  if (/https?:\/\//.test(s) || s.includes("@")) return false;
  if (/^\d+$/.test(s)) return false; // 숫자만
  if (/^\d{1,4}[.\-/년월일\s]*$/.test(s)) return false; // 날짜만
  if (/\d:\d/.test(s)) return false; // 시각(10:00 등) 포함
  if (/[0-9]/.test(s) && !/[一-鿿]/.test(s)) return false; // 숫자 섞인 토큰(가격 등)
  // camelCase 영문 식별자(페이지 설정값 등 코드 잡음) 제외
  if (/^[A-Za-z]+$/.test(s) && /[a-z][A-Z]/.test(s)) return false;
  // 한국어 문장처럼 보이는 것 제외 (조사/어미로 끝나는 긴 구)
  if (/(입니다|합니다|했어요|같아요|이에요|예요|네요|거예요)\.?$/.test(s) && len > 6) {
    return false;
  }
  return true;
}

// 제목/설명/본문에서 장소 후보를 규칙 기반으로 추출.
// 반환: [{ name }] (점수 높은 순, 최대 20개)
function extractCandidates(title, description, bodyText) {
  const scores = new Map(); // 정규화 키 -> { name, score, order }
  let order = 0;
  const add = (raw, score) => {
    const name = cleanCandidate(raw);
    if (!isValidCandidate(name)) return;
    const key = name.replace(/\s+/g, "").toLowerCase();
    const prev = scores.get(key);
    if (prev) {
      if (score > prev.score) prev.score = score;
    } else {
      scores.set(key, { name, score, order: order++ });
    }
  };

  const titleText = String(title ?? "");
  const descText = String(description ?? "");
  const body = String(bodyText ?? "").slice(0, 30000);

  // 1) 따옴표/꺾쇠 안 이름
  const quoteRe = /["“”「『]([^"“”」』\n]{2,25})["“”」』]/g;
  for (const [text, sc] of [[titleText, 70], [descText, 55], [body, 45]]) {
    for (const m of text.matchAll(quoteRe)) add(m[1], sc);
  }

  // 2) 한국어 이름 + (중국어) 병기 패턴: 새턴버드(三顿半) → 둘 다 후보
  const parenRe =
    /([가-힣A-Za-z0-9][가-힣A-Za-z0-9&·\s]{0,18}?)\s*[\(（]([一-鿿·\s]{2,20})[\)）]/g;
  for (const text of [titleText, descText, body]) {
    for (const m of text.matchAll(parenRe)) {
      add(m[1], 60);
      add(m[2].replace(/\s+/g, ""), 40);
    }
  }

  // 3) 제목/설명을 구분자로 나눈 토큰 (괄호 병기는 2번 규칙이 따로 처리)
  const delimRe = /\s*[|·•\/>»—–:,\-]\s*/;
  for (const [text, sc] of [[titleText, 50], [descText, 35]]) {
    for (const tok of text.split(delimRe)) {
      if (/[\(\)（）]/.test(tok)) continue;
      add(tok, sc);
    }
  }

  // 4) 해시태그
  const hashRe = /#([^\s#]{2,20})/g;
  for (const text of [descText, body]) {
    for (const m of text.matchAll(hashRe)) add(m[1], 30);
  }

  // 5) 중국어 지점/장소 패턴: 한자 연속 + 장소 접미사
  const cjkRunRe = /[一-鿿]{2,16}/g;
  for (const text of [titleText, descText, body]) {
    for (const m of text.matchAll(cjkRunRe)) {
      const run = m[0];
      for (const suf of CJK_SUFFIXES) {
        if (run.endsWith(suf)) {
          add(run.slice(-12), 38);
          break;
        }
      }
    }
  }

  // 6) 한국어 장소 접미사로 끝나는 단어 (정안사, 우캉루, ~역, ~공원 등)
  const korSuffixRe = /[가-힣]{2,10}?(?:박물관|미술관|백화점|공원|시장|광장|타워|거리|역|사|루|몰)/g;
  for (const text of [titleText, descText, body]) {
    for (const m of text.matchAll(korSuffixRe)) {
      if (!KOR_SUFFIX_EXCLUDES.has(m[0])) add(m[0], 25);
    }
  }

  // 7) 제목형 줄만: "1. 이름", "매장명 : 이름" 같은 형태
  for (const line of body.split("\n")) {
    const t = line.trim();
    if (!t || [...t].length > 40) continue;
    const label = t.match(/^[^:：]{1,10}[:：]\s*(.{2,25})$/);
    if (label && !/[\(\)（）]/.test(label[1])) add(label[1], 20);
    const numbered = t.match(/^\d{1,2}[.)]\s*(.{2,25})$/);
    if (numbered && !/(다|요|네요)[.!?。]?\s*$/.test(numbered[1])) {
      add(numbered[1], 18);
    }
  }

  // 8) 단어 빈도: 제목 단어 + 본문/설명에서 2번 이상 반복되는 단어
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
    add(w, 30);
  }
  for (const w of tokenize(descText + " " + body)) {
    if (/[一-鿿]/.test(w)) continue; // 한자는 5번 규칙이 담당
    wordCounts.set(w, (wordCounts.get(w) ?? 0) + 1);
  }
  for (const [w, cnt] of wordCounts) {
    if (cnt < 2) continue;
    if ([...w].length < 2 || [...w].length > 10) continue;
    if (badEnding.test(w)) continue;
    add(w, cnt >= 3 ? 28 : 22);
  }

  return [...scores.values()]
    .sort((a, b) => b.score - a.score || a.order - b.order)
    .slice(0, 20)
    .map((v) => ({ name: v.name }));
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
async function fetchText(rawUrl: string, timeoutMs = 10000): Promise<string> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    let current = rawUrl;
    for (let hop = 0; ; hop++) {
      const gate = validateFetchUrl(current);
      if (!gate.ok) throw new BlockedUrlError(gate.reason);
      const res = await fetch(gate.url.toString(), {
        headers: {
          "User-Agent": BROWSER_UA,
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
  | { ok: true; title: string; candidates: { name: string }[]; source: string }
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

async function extractGeneric(url: URL): Promise<ExtractResult> {
  const isInstagram = /(^|\.)instagram\.com$/.test(url.hostname);
  const html = await fetchText(url.toString());
  const title = metaContent(html, "og:title");
  let description = metaContent(html, "og:description");
  const bodyText = htmlToText(html);

  if (isInstagram) {
    // og:description 안에 캡션이 따옴표로 들어오는 경우가 있다
    const cap = description.match(/["“]([^"”]{10,300})["”]/);
    const caption = cap ? cap[1] : "";
    const genericTitle = !title || title.trim() === "Instagram";
    if (genericTitle && !caption) {
      return {
        ok: false,
        reason:
          "인스타그램이 로그인 벽으로 막아서 게시물 내용을 읽지 못했어요. 장소는 아래에서 직접 입력해 주세요.",
      };
    }
    return {
      ok: true,
      title: title || "인스타그램 게시물",
      candidates: extractCandidates(title, description, caption || bodyText),
      source: "instagram",
    };
  }

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
