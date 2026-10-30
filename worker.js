/**
 * KIS Open API Proxy — Cloudflare Workers
 *
 * 역할: Artifact(브라우저)에서 직접 호출할 수 없는 KIS API를
 *       이 Worker가 대신 호출하고 CORS 헤더를 붙여 반환합니다.
 *
 * 엔드포인트:
 *   GET  /token               — 액세스 토큰 발급 (캐싱 20분)
 *   GET  /price?code=005930   — 주식 현재가 조회
 *   GET  /ohlcv?code=005930   — 최근 100일 OHLCV (일봉) 조회
 *   GET  /search?q=삼성       — 종목명 검색 (내장 DB)
 *   POST /kakao-token         — 카카오 OAuth 토큰 교환 (CORS 우회)
 *   POST /notify              — 카카오톡 나에게 메시지 전송
 *   POST /order               — 모의투자 주문 (매수/매도)
 *   GET  /balance             — 모의투자 잔고 조회
 *   GET  /quotes?codes=...    — 복수 종목 현재가 일괄 조회 (쉼표 구분, 최대 10종목)
 *   GET  /holdings-quotes     — Cron이 KV에 저장한 보유 포지션 종가 스냅샷
 *   POST /save-holdings       — 보유 포지션 목록을 KV에 저장 (앱 → Worker 동기화)
 *   GET  /market-index        — 코스피/코스닥 지수 (당일)
 *   GET  /kospi-ma           — 코스피 60일 이평선 & 장세 판단 (강세장/약세장)
 *   GET  /market-investor     — 외국인·기관·개인 수급 (코스피/코스닥)
 *   GET  /market-sector       — 업종별 등락률 그리드
 *   GET  /stock-detail?code=  — 종목 상세 (OHLCV + 투자자별 매매동향)
 *   GET  /blog-feed           — 네이버 블로그 RSS 피드 (chcmg2022)
 *   GET  /research-feed       — 한국투자증권 리서치 리포트 목록
 */

// ────────────────────────────────────────────────────────────
// KIS API 설정 (Cloudflare Workers 환경변수로 주입)
// wrangler secret put KIS_APP_KEY  등으로 설정
// ────────────────────────────────────────────────────────────
const KIS_BASE = 'https://openapi.koreainvestment.com:9443';

// 토큰 캐시 — Worker 인스턴스 메모리 (빠른 경로) + KV (인스턴스 간 공유)
let cachedToken = null;
let tokenExpiry = 0;
let tokenFetchPromise = null; // 동일 인스턴스 내 동시 발급 방지용 Promise 공유

// ────────────────────────────────────────────────────────────
// CORS 헤더
// ────────────────────────────────────────────────────────────
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Content-Type': 'application/json; charset=utf-8',
};

function corsResponse(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: CORS });
}

// ────────────────────────────────────────────────────────────
// 토큰 발급 — 메모리 캐시 → KV 캐시 → 신규 발급 순서로 확인
// KV에 저장하므로 Worker 인스턴스가 달라도 토큰을 재사용함
// ────────────────────────────────────────────────────────────
async function getToken(env) {
  const now = Date.now();
  // 1) 인스턴스 메모리 캐시 (가장 빠름)
  if (cachedToken && now < tokenExpiry) return cachedToken;

  // 2) 동일 인스턴스 내 동시 발급 방지 — 이미 진행 중인 발급이 있으면 그것을 기다림
  if (tokenFetchPromise) return tokenFetchPromise;

  // 3) KV 캐시 확인 + 신규 발급을 하나의 Promise로 묶어 공유
  tokenFetchPromise = (async () => {
    try {
      // KV 캐시 확인 (다른 인스턴스가 발급한 토큰 재사용)
      const kv = await env.KV.get('kis_token_cache', 'json');
      if (kv && kv.token && kv.expiry > Date.now() + 30000) { // 30초 여유
        cachedToken = kv.token;
        tokenExpiry = kv.expiry;
        return cachedToken;
      }
    } catch (_) { /* KV 실패 시 신규 발급으로 폴백 */ }

    // 신규 발급
    const res = await fetch(`${KIS_BASE}/oauth2/tokenP`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'client_credentials',
        appkey: env.KIS_APP_KEY,
        appsecret: env.KIS_APP_SECRET,
      }),
    });

    if (!res.ok) throw new Error(`토큰 발급 실패: HTTP ${res.status}`);
    const data = await res.json();
    if (!data.access_token) throw new Error('토큰 없음: ' + JSON.stringify(data));

    cachedToken = data.access_token;
    tokenExpiry = Date.now() + 23 * 60 * 60 * 1000; // 23시간 (KIS 토큰 유효기간 24시간)

    // KV에도 저장 (23시간 캐시 → 하루 1회 발급)
    try {
      await env.KV.put('kis_token_cache', JSON.stringify({ token: cachedToken, expiry: tokenExpiry }), { expirationTtl: 82800 });
    } catch (_) { /* KV 저장 실패 무시 */ }

    return cachedToken;
  })().finally(() => {
    tokenFetchPromise = null; // 완료 후 초기화 (다음 만료 시 새 발급 허용)
  });

  return tokenFetchPromise;
}

// ────────────────────────────────────────────────────────────
// KIS API 공통 헤더
// ────────────────────────────────────────────────────────────
function kisHeaders(token, trId, env) {
  return {
    'Content-Type': 'application/json',
    'authorization': `Bearer ${token}`,
    'appkey': env.KIS_APP_KEY,
    'appsecret': env.KIS_APP_SECRET,
    'tr_id': trId,
    'custtype': 'P',
  };
}

// ────────────────────────────────────────────────────────────
// 모의투자 토큰 발급 — 메모리 캐시 → KV 캐시 → 신규 발급
// ────────────────────────────────────────────────────────────
const MOCK_BASE = 'https://openapivts.koreainvestment.com:29443';
let cachedMockToken = null;
let mockTokenExpiry = 0;
let mockTokenFetchPromise = null; // 동일 인스턴스 내 동시 발급 방지용 Promise 공유

async function getMockToken(env) {
  const now = Date.now();
  // 1) 인스턴스 메모리 캐시
  if (cachedMockToken && now < mockTokenExpiry) return cachedMockToken;

  // 2) 동일 인스턴스 내 동시 발급 방지
  if (mockTokenFetchPromise) return mockTokenFetchPromise;

  // 3) KV 캐시 확인 + 신규 발급을 하나의 Promise로 묶어 공유
  mockTokenFetchPromise = (async () => {
    try {
      const kv = await env.KV.get('kis_mock_token_cache', 'json');
      if (kv && kv.token && kv.expiry > Date.now() + 30000) {
        cachedMockToken = kv.token;
        mockTokenExpiry = kv.expiry;
        return cachedMockToken;
      }
    } catch (_) { /* KV 실패 시 신규 발급으로 폴백 */ }

    // 신규 발급 (모의투자 전용 키 사용 — 없으면 실전투자 키로 폴백)
    const mockKey = env.KIS_MOCK_APP_KEY || env.KIS_APP_KEY;
    const mockSec = env.KIS_MOCK_APP_SECRET || env.KIS_APP_SECRET;
    const res = await fetch(`${MOCK_BASE}/oauth2/tokenP`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'client_credentials',
        appkey: mockKey,
        appsecret: mockSec,
      }),
    });
    if (!res.ok) throw new Error(`모의투자 토큰 발급 실패: HTTP ${res.status}`);
    const data = await res.json();
    if (!data.access_token) throw new Error('모의투자 토큰 없음: ' + JSON.stringify(data));

    cachedMockToken = data.access_token;
    mockTokenExpiry = Date.now() + 20 * 60 * 1000;

    try {
      await env.KV.put('kis_mock_token_cache', JSON.stringify({ token: cachedMockToken, expiry: mockTokenExpiry }), { expirationTtl: 1200 });
    } catch (_) { /* KV 저장 실패 무시 */ }

    return cachedMockToken;
  })().finally(() => {
    mockTokenFetchPromise = null;
  });

  return mockTokenFetchPromise;
}

// ────────────────────────────────────────────────────────────
// 모의투자 주문
// body: { code, side, orderType, qty, price }
//   side: 'buy' | 'sell'
//   orderType: 'market' | 'limit'
//   qty: 수량 (정수)
//   price: 지정가일 때만 사용 (시장가는 0)
// ────────────────────────────────────────────────────────────
// hashkey 발급 (POST 주문 시 필수)
async function getHashkey(reqBody, env, base) {
  // 모의투자(MOCK_BASE)일 경우 모의투자 전용 키 사용
  const isMock = base === MOCK_BASE;
  const appkey = isMock ? (env.KIS_MOCK_APP_KEY || env.KIS_APP_KEY) : env.KIS_APP_KEY;
  const appsecret = isMock ? (env.KIS_MOCK_APP_SECRET || env.KIS_APP_SECRET) : env.KIS_APP_SECRET;

  const res = await fetch(`${base}/uapi/hashkey`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'appkey': appkey,
      'appsecret': appsecret,
    },
    body: JSON.stringify(reqBody),
  });
  if (!res.ok) throw new Error(`hashkey 발급 실패: HTTP ${res.status}`);
  const data = await res.json();
  return data.HASH || '';
}

async function placeMockOrder(body, env) {
  const account = env.KIS_MOCK_ACCOUNT || '';
  if (!account) throw new Error('모의투자 계좌번호(KIS_MOCK_ACCOUNT)가 설정되지 않았습니다');
  const token = await getMockToken(env);
  const mockKey = env.KIS_MOCK_APP_KEY || env.KIS_APP_KEY;
  const mockSec = env.KIS_MOCK_APP_SECRET || env.KIS_APP_SECRET;

  // tr_id: 매수=VTTC0802U, 매도=VTTC0801U (모의투자)
  const trId = body.side === 'sell' ? 'VTTC0801U' : 'VTTC0802U';

  // 주문구분: 시장가=01, 지정가=00
  const ordDvsn = body.orderType === 'market' ? '01' : '00';
  const ordPrc  = body.orderType === 'market' ? '0' : String(body.price || 0);

  const reqBody = {
    CANO: account.slice(0, 8),          // 계좌번호 앞 8자리
    ACNT_PRDT_CD: '01',                 // 계좌상품코드 (주식=01)
    PDNO: body.code,                    // 종목코드
    ORD_DVSN: ordDvsn,                  // 주문구분
    ORD_QTY: String(body.qty || 1),     // 주문수량
    ORD_UNPR: ordPrc,                   // 주문단가
  };

  // POST 주문은 hashkey 헤더 필수
  const hashkey = await getHashkey(reqBody, env, MOCK_BASE);

  const res = await fetch(`${MOCK_BASE}/uapi/domestic-stock/v1/trading/order-cash`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'authorization': `Bearer ${token}`,
      'appkey': mockKey,
      'appsecret': mockSec,
      'tr_id': trId,
      'custtype': 'P',
      'hashkey': hashkey,
    },
    body: JSON.stringify(reqBody),
  });

  if (!res.ok) throw new Error(`주문 API 실패: HTTP ${res.status}`);
  const data = await res.json();

  if (data.rt_cd !== '0') {
    throw new Error(data.msg1 || '주문 실패');
  }

  return {
    ok: true,
    ordNo: data.output?.ODNO || '',     // 주문번호
    msg: data.msg1 || '주문 완료',
    code: body.code,
    side: body.side,
    orderType: body.orderType,
    qty: body.qty,
    price: body.price || 0,
  };
}

// ────────────────────────────────────────────────────────────
// 모의투자 잔고 조회
// ────────────────────────────────────────────────────────────
async function getMockBalance(env) {
  const account = env.KIS_MOCK_ACCOUNT || '';
  if (!account) throw new Error('모의투자 계좌번호(KIS_MOCK_ACCOUNT)가 설정되지 않았습니다');
  const token = await getMockToken(env);
  const mockKey = env.KIS_MOCK_APP_KEY || env.KIS_APP_KEY;
  const mockSec = env.KIS_MOCK_APP_SECRET || env.KIS_APP_SECRET;

  const url = `${MOCK_BASE}/uapi/domestic-stock/v1/trading/inquire-balance`
    + `?CANO=${account.slice(0, 8)}&ACNT_PRDT_CD=01&AFHR_FLPR_YN=N&OFL_YN=N&INQR_DVSN=02&UNPR_DVSN=01&FUND_STTL_ICLD_YN=N&FNCG_AMT_AUTO_RDPT_YN=N&PRCS_DVSN=00&CTX_AREA_FK100=&CTX_AREA_NK100=`;

  const res = await fetch(url, {
    headers: {
      'Content-Type': 'application/json',
      'authorization': `Bearer ${token}`,
      'appkey': mockKey,
      'appsecret': mockSec,
      'tr_id': 'VTTC8434R',
      'custtype': 'P',
    },
  });

  if (!res.ok) throw new Error(`잔고 조회 실패: HTTP ${res.status}`);
  const data = await res.json();
  if (data.rt_cd !== '0') throw new Error(data.msg1 || '잔고 조회 실패');

  const summary = data.output2?.[0] || {};
  const stocks = (data.output1 || []).map(h => ({
    code: h.pdno,
    name: h.prdt_name,
    qty: parseInt(h.hldg_qty) || 0,
    avgPrice: parseInt(h.pchs_avg_pric) || 0,
    currPrice: parseInt(h.prpr) || 0,
    evalAmt: parseInt(h.evlu_amt) || 0,
    evalPnl: parseInt(h.evlu_pfls_amt) || 0,
    ret: parseFloat(h.evlu_pfls_rt) || 0,
  }));

  return {
    ok: true,
    deposit: parseInt(summary.dnca_tot_amt) || 0,       // 예수금 총액
    evalAmt: parseInt(summary.tot_evlu_amt) || 0,       // 총평가금액
    pnl: parseInt(summary.evlu_pfls_smtl_amt) || 0,     // 평가손익합계
    stocks,
  };
}

// ────────────────────────────────────────────────────────────
// 주식 현재가 조회
// ────────────────────────────────────────────────────────────
async function getPrice(code, env) {
  const token = await getToken(env);
  const url = `${KIS_BASE}/uapi/domestic-stock/v1/quotations/inquire-price`
    + `?FID_COND_MRKT_DIV_CODE=J&FID_INPUT_ISCD=${code}`;

  const res = await fetch(url, {
    headers: kisHeaders(token, 'FHKST01010100', env),
  });
  if (!res.ok) throw new Error(`KIS 현재가 실패: HTTP ${res.status}`);
  const data = await res.json();
  if (data.rt_cd !== '0') throw new Error(data.msg1 || '조회 실패');

  const o = data.output;
  return {
    code,
    name: o.hts_kor_isnm || '',         // 종목명
    curr: parseInt(o.stck_prpr) || 0,   // 현재가
    open: parseInt(o.stck_oprc) || 0,
    high: parseInt(o.stck_hgpr) || 0,
    low:  parseInt(o.stck_lwpr) || 0,
    vol:  parseInt(o.acml_vol) || 0,    // 누적거래량
    chg:  parseFloat(o.prdy_ctrt) || 0, // 전일대비율(%)
    market_cap: parseInt(o.hts_avls) || 0,
    high52: parseInt(o.w52_hgpr) || 0,  // 52주 최고가
    low52:  parseInt(o.w52_lwpr) || 0,  // 52주 최저가
  };
}

// ────────────────────────────────────────────────────────────
// 일봉 OHLCV 조회 (최근 100일)
//   TR ID: FHKST03010100
//   /uapi/domestic-stock/v1/quotations/inquire-daily-price
// ────────────────────────────────────────────────────────────
async function getOHLCV(code, env) {
  const token = await getToken(env);
  const today = new Date().toISOString().slice(0,10).replace(/-/g,'');
  const url = `${KIS_BASE}/uapi/domestic-stock/v1/quotations/inquire-daily-price`
    + `?FID_COND_MRKT_DIV_CODE=J&FID_INPUT_ISCD=${code}`
    + `&FID_PERIOD_DIV_CODE=D&FID_ORG_ADJ_PRC=0`
    + `&FID_INPUT_DATE_1=20240101&FID_INPUT_DATE_2=${today}`;

  const res = await fetch(url, {
    headers: kisHeaders(token, 'FHKST03010100', env),
  });
  if (!res.ok) throw new Error(`KIS OHLCV 실패: HTTP ${res.status}`);
  const data = await res.json();
  if (data.rt_cd !== '0') throw new Error(data.msg1 || 'OHLCV 조회 실패');

  // output2가 일봉 배열 (최신순)
  const rows = (data.output2 || []).map(r => ({
    date:   r.stck_bsop_date,           // YYYYMMDD
    open:   parseInt(r.stck_oprc) || 0,
    high:   parseInt(r.stck_hgpr) || 0,
    low:    parseInt(r.stck_lwpr) || 0,
    close:  parseInt(r.stck_clpr) || 0,
    vol:    parseInt(r.acml_vol)  || 0,
  }));

  // 추세추종 지표 계산
  const closes = rows.map(r => r.close);
  const highs  = rows.map(r => r.high);
  const lows   = rows.map(r => r.low);
  const vols   = rows.map(r => r.vol);

  const curr   = closes[0] || 0;

  // 최근 20일 고가 (오늘 포함) — 장 마감 후 스캔이므로 오늘 종가 기준 정상
  const high20 = highs.length > 0 ? Math.max(...highs.slice(0, 20)) : 0;
  const low10  = Math.min(...lows.slice(0, 10));
  const avgVol = Math.round(vols.slice(0, 20).reduce((a,b)=>a+b,0) / Math.min(20, vols.length));
  const todayVol = vols[0] || 0;

  // 14일 ATR
  let atrSum = 0, atrCount = 0;
  for (let i = 0; i < Math.min(14, rows.length - 1); i++) {
    const tr = Math.max(
      highs[i] - lows[i],
      Math.abs(highs[i] - closes[i+1]),
      Math.abs(lows[i]  - closes[i+1]),
    );
    atrSum += tr; atrCount++;
  }
  const atr = atrCount > 0 ? Math.round(atrSum / atrCount) : 0;

  // 52주 고가
  const high52 = highs.length > 0 ? Math.max(...highs.slice(0, Math.min(250, highs.length))) : 0;

  // RS (상대강도): 최근 3개월(약 63거래일) 수익률
  // 코스피 비교는 런타임에 calcSignalScore에서 처리
  const close63ago = closes[Math.min(62, closes.length - 1)] || curr;
  const rs3m = close63ago > 0 ? ((curr - close63ago) / close63ago) * 100 : 0;

  // 월봉 10선 (MA10M): 일봉에서 월별 마지막 종가 추출 → 최근 10개월 평균
  // rows는 최신순이므로 날짜 기준 월별 그룹핑
  const monthlyCloses = (() => {
    const seen = new Set();
    const result = [];
    for (const r of rows) {
      if (!r.date || !r.close) continue;
      const ym = r.date.slice(0, 6); // YYYYMM
      if (!seen.has(ym)) {
        seen.add(ym);
        result.push(r.close); // 최신순이므로 월별 첫 번째 = 월말 종가
      }
    }
    return result; // 최신 월부터 과거 순
  })();
  // 현재 월은 아직 마감되지 않았을 수 있으므로 MA10 계산 시 현재월 제외 (index 1부터 10개)
  const ma10mSlice = monthlyCloses.slice(1, 11); // 직전 10개 완성 월
  const ma10m = ma10mSlice.length >= 5
    ? Math.round(ma10mSlice.reduce((a, b) => a + b, 0) / ma10mSlice.length)
    : 0;

  const latestDate = rows[0]?.date || ''; // 가장 최근 거래일 YYYYMMDD
  // 거래정지 판별: 최근 3거래일 모두 거래량 0이면 정지 종목으로 간주
  const haltedVol = vols.slice(0, 3).every(v => v === 0);
  // 거래정지 판별: 최근 3거래일 고가=저가=종가 (가격 변동 없음)
  const haltedPrice = rows.slice(0, 3).every(r => r.high === r.low && r.high === r.close && r.close > 0);
  const isHalted = haltedVol || haltedPrice;
  return { code, curr, high20, low10, avgVol, todayVol, atr, high52, rs3m, ma10m, rows, latestDate, isHalted };
}

// ────────────────────────────────────────────────────────────
// 코스피/코스닥 지수 조회
// TR: FHKUP03500100 (업종/지수 현재지수)
// ────────────────────────────────────────────────────────────
async function getMarketIndex(env) {
  const token = await getToken(env);
  const [kospiRes, kosdaqRes] = await Promise.all([
    fetch(`${KIS_BASE}/uapi/domestic-stock/v1/quotations/inquire-index-category-price?FID_COND_MRKT_DIV_CODE=U&FID_INPUT_ISCD=0001`,
      { headers: kisHeaders(token, 'FHPUP02100000', env) }),
    fetch(`${KIS_BASE}/uapi/domestic-stock/v1/quotations/inquire-index-category-price?FID_COND_MRKT_DIV_CODE=U&FID_INPUT_ISCD=1001`,
      { headers: kisHeaders(token, 'FHPUP02100000', env) }),
  ]);

  const parseIdx = async (res) => {
    if (!res.ok) return null;
    const d = await res.json().catch(() => null);
    if (!d || d.rt_cd !== '0') return null;
    const o = Array.isArray(d.output) ? (d.output[0] || {}) : (d.output || {});
    return {
      curr:   parseFloat(o.bstp_nmix_prpr)        || 0,
      chg:    parseFloat(o.bstp_nmix_prdy_ctrt)    || 0,
      chgAmt: parseFloat(o.bstp_nmix_prdy_vrss)    || 0,
      vol:    parseInt(o.acml_vol)                 || 0,
      high:   parseFloat(o.bstp_nmix_hgpr)         || 0,
      low:    parseFloat(o.bstp_nmix_lwpr)          || 0,
    };
  };

  const kospi  = await parseIdx(kospiRes);
  const kosdaq = await parseIdx(kosdaqRes);
  return { kospi, kosdaq };
}

// ────────────────────────────────────────────────────────────
// 코스피 60일 이동평균선 조회
// ────────────────────────────────────────────────────────────
async function getKospiMA(env) {
  const token = await getToken(env);
  const today = new Date(Date.now() + 9 * 60 * 60 * 1000).toISOString().slice(0,10).replace(/-/g,'');

  const res = await fetch(
    `${KIS_BASE}/uapi/domestic-stock/v1/quotations/inquire-daily-indexchartprice`
    + `?FID_COND_MRKT_DIV_CODE=U&FID_INPUT_ISCD=0001`
    + `&FID_INPUT_DATE_1=20240101&FID_INPUT_DATE_2=${today}`
    + `&FID_PERIOD_DIV_CODE=D`,
    { headers: kisHeaders(token, 'FHKUP03500100', env) }
  );

  if (!res.ok) throw new Error(`코스피 일봉 실패: HTTP ${res.status}`);
  const data = await res.json();

  const rows = Array.isArray(data.output2) ? data.output2 : [];
  const out1 = Array.isArray(data.output1) ? (data.output1[0] || {}) : (data.output1 || {});
  const currIdx = parseFloat(out1.bstp_nmix_prpr) || 0;

  const closes = rows.slice(0, 60).map(r => parseFloat(r.bstp_nmix_clpr || r.stck_clpr) || 0).filter(v => v > 0);
  const ma60 = closes.length > 0 ? closes.reduce((a,b)=>a+b,0) / closes.length : 0;

  const isBullish = currIdx > 0 && ma60 > 0 && currIdx >= ma60;

  return {
    curr: currIdx,
    ma60: Math.round(ma60 * 100) / 100,
    isBullish,
    label: isBullish ? '강세장' : '약세장',
    dataPoints: closes.length,
  };
}

// ────────────────────────────────────────────────────────────
// 외국인·기관·개인 수급 (코스피/코스닥 각각)
// ────────────────────────────────────────────────────────────
async function getMarketInvestor(env) {
  const token = await getToken(env);
  const [kospiRes, kosdaqRes] = await Promise.all([
    fetch(`${KIS_BASE}/uapi/domestic-stock/v1/quotations/inquire-index-category-price?FID_COND_MRKT_DIV_CODE=U&FID_INPUT_ISCD=0001`,
      { headers: kisHeaders(token, 'FHPUP02100000', env) }),
    fetch(`${KIS_BASE}/uapi/domestic-stock/v1/quotations/inquire-index-category-price?FID_COND_MRKT_DIV_CODE=U&FID_INPUT_ISCD=1001`,
      { headers: kisHeaders(token, 'FHPUP02100000', env) }),
  ]);

  const parseInv = async (res, label) => {
    if (!res.ok) {
      const txt = await res.text().catch(()=>'');
      console.error(`[investor/${label}] HTTP ${res.status}`, txt);
      return null;
    }
    const d = await res.json();
    if (d.rt_cd !== '0') {
      console.error(`[investor/${label}] rt_cd=${d.rt_cd} msg=${d.msg1}`);
      return null;
    }
    const o = Array.isArray(d.output) ? (d.output[0] || {}) : (d.output || {});
    const bidAmt  = parseInt(o.total_bidp_rsqn) || 0;
    const askAmt  = parseInt(o.total_askp_rsqn) || 0;
    const netAmt  = parseInt(o.ntby_rsqn)       || 0;
    const bidRate = parseFloat(o.shnu_rsqn_rate) || 0;
    const askRate = parseFloat(o.seln_rsqn_rate) || 0;
    return {
      foreign: 0, inst: 0, indiv: 0,
      foreignAmt: 0, instAmt: 0, indivAmt: 0,
      bidAmt, askAmt, netAmt, bidRate, askRate,
      curr: parseFloat(o.bstp_nmix_prpr) || 0,
      chg:  parseFloat(o.bstp_nmix_prdy_ctrt) || 0,
      date: '',
    };
  };

  const kospi  = await parseInv(kospiRes,  'kospi');
  const kosdaq = await parseInv(kosdaqRes, 'kosdaq');
  return { kospi, kosdaq };
}

// ────────────────────────────────────────────────────────────
// 업종별 등락률 조회
// ────────────────────────────────────────────────────────────
async function getMarketSector(env) {
  const token = await getToken(env);

  const kospiCodes  = Array.from({length:26}, (_,i) => String(i+1).padStart(4,'0'));
  const kosdaqCodes = Array.from({length:28}, (_,i) => String(1001+i));

  const parseRows = async (res) => {
    if (!res.ok) return [];
    const d = await res.json().catch(() => ({}));
    if (d.rt_cd !== '0') return [];
    return Array.isArray(d.output) ? d.output : (d.output ? [d.output] : []);
  };

  const [kospiResults, kosdaqResults] = await Promise.all([
    Promise.all(
      kospiCodes.map(c =>
        fetch(`${KIS_BASE}/uapi/domestic-stock/v1/quotations/inquire-index-category-price?FID_COND_MRKT_DIV_CODE=U&FID_INPUT_ISCD=${c}`,
          { headers: kisHeaders(token, 'FHPUP02100000', env) })
        .then(r => parseRows(r))
        .catch(() => [])
      )
    ),
    Promise.all(
      kosdaqCodes.map(c =>
        fetch(`${KIS_BASE}/uapi/domestic-stock/v1/quotations/inquire-index-category-price?FID_COND_MRKT_DIV_CODE=U&FID_INPUT_ISCD=${c}`,
          { headers: kisHeaders(token, 'FHPUP02100000', env) })
        .then(r => parseRows(r))
        .catch(() => [])
      )
    ),
  ]);

  const KOSPI_NAMES = {
    '0001':'종합(KOSPI)', '0002':'대형주',    '0003':'중형주',    '0004':'소형주',
    '0005':'음식료품',    '0006':'섬유의복',   '0007':'종이목재',   '0008':'화학',
    '0009':'의약품',      '0010':'비금속광물', '0011':'철강금속',  '0012':'기계',
    '0013':'전기전자',    '0014':'의료정밀',   '0015':'운수장비',  '0016':'유통업',
    '0017':'전기가스업',  '0018':'건설업',     '0019':'운수창고',  '0020':'통신업',
    '0021':'금융업',      '0022':'은행',       '0023':'증권',      '0024':'보험',
    '0025':'서비스업',    '0026':'제조업',
  };
  const KOSDAQ_NAMES = {
    '1001':'코스닥',       '1002':'대형주',      '1003':'중형주',     '1004':'소형주',
    '1005':'음식료·담배',  '1006':'섬유·의류',   '1007':'종이·목재',  '1008':'출판·매체복제',
    '1009':'화학',         '1010':'제약',         '1011':'비금속',     '1012':'금속',
    '1013':'기계·장비',   '1014':'일반전기전자', '1015':'의료·정밀기기','1016':'운송장비·부품',
    '1017':'기타제조',     '1018':'건설',         '1019':'유통',       '1020':'운수·창고',
    '1021':'방송서비스',   '1022':'통신서비스',   '1023':'IT부품',     '1024':'디지털컨텐츠',
    '1025':'소프트웨어',   '1026':'컴퓨터서비스', '1027':'통신장비',   '1028':'IT기타',
  };
  const SECTOR_NAMES = { ...KOSPI_NAMES, ...KOSDAQ_NAMES };

  const sectors = [];

  kospiCodes.forEach((c, i) => {
    const rows = kospiResults[i];
    const r = rows[0];
    if (!r) return;
    const chg  = parseFloat(r.bstp_nmix_prdy_ctrt) || 0;
    const curr = parseFloat(r.bstp_nmix_prpr) || 0;
    const vol  = parseInt(r.acml_vol) || 0;
    const name = SECTOR_NAMES[c] || `코스피 ${c}`;
    if (curr > 0) sectors.push({ code: c, name, curr, chg, vol, market: 'KOSPI' });
  });

  kosdaqCodes.forEach((c, i) => {
    const rows = kosdaqResults[i];
    const r = rows[0];
    if (!r) return;
    const chg  = parseFloat(r.bstp_nmix_prdy_ctrt) || 0;
    const curr = parseFloat(r.bstp_nmix_prpr) || 0;
    const vol  = parseInt(r.acml_vol) || 0;
    const name = SECTOR_NAMES[c] || `코스닥 ${c}`;
    if (curr > 0) sectors.push({ code: c, name, curr, chg, vol, market: 'KOSDAQ' });
  });

  sectors.sort((a, b) => b.chg - a.chg);
  return { sectors };
}

// ────────────────────────────────────────────────────────────
// 종목 상세: OHLCV 차트 + 투자자별 매매동향
// ────────────────────────────────────────────────────────────
async function getStockDetail(code, env) {
  const token = await getToken(env);

  const kstNow = new Date(Date.now() + 9 * 60 * 60 * 1000);
  const kstHour = kstNow.getUTCHours();
  const isBeforeClose = kstHour < 16;
  const todayStr  = kstNow.toISOString().slice(0,10).replace(/-/g,'');

  const ohlcvRes = await fetch(
    `${KIS_BASE}/uapi/domestic-stock/v1/quotations/inquire-daily-price`
    + `?FID_COND_MRKT_DIV_CODE=J&FID_INPUT_ISCD=${code}`
    + `&FID_PERIOD_DIV_CODE=D&FID_ORG_ADJ_PRC=0`
    + `&FID_INPUT_DATE_1=20240101&FID_INPUT_DATE_2=${todayStr}`,
    { headers: kisHeaders(token, 'FHKST03010100', env) }
  );

  const invRes = await fetch(
    `${KIS_BASE}/uapi/domestic-stock/v1/quotations/inquire-investor`
    + `?FID_COND_MRKT_DIV_CODE=J&FID_INPUT_ISCD=${code}&FID_INPUT_DATE_1=&FID_INPUT_DATE_2=`,
    { headers: kisHeaders(token, 'FHKST03010200', env) }
  );

  const priceRes = await fetch(
    `${KIS_BASE}/uapi/domestic-stock/v1/quotations/inquire-price`
    + `?FID_COND_MRKT_DIV_CODE=J&FID_INPUT_ISCD=${code}`,
    { headers: kisHeaders(token, 'FHKST01010100', env) }
  );

  let bars = [];
  let info = { code, name: '', curr: 0, open: 0, high: 0, low: 0, vol: 0, chg: 0, isBeforeClose };
  let investor = [];

  let ohlcvRows = [];
  if (ohlcvRes.ok) {
    const d = await ohlcvRes.json();
    if (d.rt_cd === '0' && d.output2) {
      ohlcvRows = d.output2;
      bars = ohlcvRows.slice(0, 60).map(r => ({
        date:  r.stck_bsop_date,
        open:  parseInt(r.stck_oprc) || 0,
        high:  parseInt(r.stck_hgpr) || 0,
        low:   parseInt(r.stck_lwpr) || 0,
        close: parseInt(r.stck_clpr) || 0,
        vol:   parseInt(r.acml_vol) || 0,
      }));
    }
  }

  if (priceRes.ok) {
    const d = await priceRes.json();
    if (d.rt_cd === '0' && d.output) {
      const o = d.output;
      if (isBeforeClose) {
        const prevRow = ohlcvRows.find(r => r.stck_bsop_date !== todayStr) || ohlcvRows[0];
        const prevClose = parseInt(prevRow?.stck_clpr) || 0;
        const prevOpen  = parseInt(prevRow?.stck_oprc) || 0;
        const prevHigh  = parseInt(prevRow?.stck_hgpr) || 0;
        const prevLow   = parseInt(prevRow?.stck_lwpr) || 0;
        const prevVol   = parseInt(prevRow?.acml_vol)  || 0;
        const prevDate  = prevRow?.stck_bsop_date || '';

        const prevPrevRow = ohlcvRows.find(r => r.stck_bsop_date !== todayStr && r !== prevRow);
        const prevPrevClose = parseInt(prevPrevRow?.stck_clpr) || prevClose;
        const chgAmt = prevClose - prevPrevClose;
        const chgPct = prevPrevClose ? (chgAmt / prevPrevClose * 100) : 0;

        info = {
          code,
          name:      o.hts_kor_isnm || '',
          curr:      prevClose,
          open:      prevOpen,
          high:      prevHigh,
          low:       prevLow,
          vol:       prevVol,
          chg:       parseFloat(chgPct.toFixed(2)),
          chgAmt,
          high52:    parseInt(o.w52_hgpr) || 0,
          low52:     parseInt(o.w52_lwpr) || 0,
          marketCap: parseInt(o.hts_avls) || 0,
          per:       parseFloat(o.per) || 0,
          pbr:       parseFloat(o.pbr) || 0,
          isBeforeClose: true,
          baseDate:  prevDate,
        };
      } else {
        info = {
          code,
          name:      o.hts_kor_isnm || '',
          curr:      parseInt(o.stck_prpr) || 0,
          open:      parseInt(o.stck_oprc) || 0,
          high:      parseInt(o.stck_hgpr) || 0,
          low:       parseInt(o.stck_lwpr) || 0,
          vol:       parseInt(o.acml_vol)  || 0,
          chg:       parseFloat(o.prdy_ctrt) || 0,
          chgAmt:    parseInt(o.prdy_vrss) || 0,
          high52:    parseInt(o.w52_hgpr) || 0,
          low52:     parseInt(o.w52_lwpr) || 0,
          marketCap: parseInt(o.hts_avls) || 0,
          per:       parseFloat(o.per) || 0,
          pbr:       parseFloat(o.pbr) || 0,
          isBeforeClose: false,
          baseDate:  todayStr,
        };
      }
    }
  }

  if (invRes.ok) {
    const d = await invRes.json();
    if (d.rt_cd === '0' && d.output) {
      investor = d.output.slice(0, 20).map(r => ({
        date:       r.stck_bsop_date,
        foreign:    parseInt(r.frgn_ntby_qty) || 0,
        inst:       parseInt(r.orgn_ntby_qty) || 0,
        indiv:      parseInt(r.indv_ntby_qty) || 0,
        foreignAmt: parseInt(r.frgn_ntby_tr_pbmn) || 0,
        instAmt:    parseInt(r.orgn_ntby_tr_pbmn) || 0,
        indivAmt:   parseInt(r.indv_ntby_tr_pbmn) || 0,
      }));
    }
  }

  return { info, bars, investor };
}

// ────────────────────────────────────────────────────────────
// 종목 마스터 DB
// ────────────────────────────────────────────────────────────
let masterDB = [];
let masterLoadedAt = 0;
const MASTER_TTL = 24 * 60 * 60 * 1000;

const MASTER_URLS = [
  { url: 'https://new.real.download.dws.co.kr/common/master/kospi_code.mst.zip',  tailLen: 228 },
  { url: 'https://new.real.download.dws.co.kr/common/master/kosdaq_code.mst.zip', tailLen: 222 },
];

async function parseMst(arrayBuffer, tailLen) {
  // 바이트 단위로 라인 분리 후 처리 (EUC-KR 한글이 디코딩되면 문자 수가 달라져
  // trimmed.length 기반 슬라이싱이 틀려지므로 반드시 바이트 단위로 처리)
  const bytes = new Uint8Array(arrayBuffer);
  const asciiDec = new TextDecoder('ascii', { fatal: false });
  const euckrDec = new TextDecoder('euc-kr', { fatal: false });
  const result = [];

  let lineStart = 0;
  for (let i = 0; i <= bytes.length; i++) {
    if (i === bytes.length || bytes[i] === 0x0A) { // '\n'
      let lineEnd = i;
      if (lineEnd > lineStart && bytes[lineEnd - 1] === 0x0D) lineEnd--; // '\r' 제거
      const lineLen = lineEnd - lineStart;
      if (lineLen < tailLen + 21) { lineStart = i + 1; continue; }

      // 앞부분(front): 바이트 기준 lineLen - tailLen
      // tailLen은 \n 제외 기준이지만 실제 라인에서 1바이트 오프셋 차이가 있어 +1 보정
      const frontByteLen = lineLen - tailLen + 1;
      const frontBytes = bytes.slice(lineStart, lineStart + frontByteLen);
      const tailBytes  = bytes.slice(lineStart + frontByteLen, lineEnd);

      // code: front의 앞 9바이트 (ASCII)
      const code = asciiDec.decode(frontBytes.slice(0, 9)).trim();
      if (!/^\d{6}$/.test(code)) { lineStart = i + 1; continue; }

      // tail의 첫 2바이트: scrt_grp_cls_code (증권그룹구분코드, ASCII)
      // ST=주권(보통주/우선주), EF=ETF, EW=ELW, RT=리츠, MF=투자회사,
      // BC=수익증권, FE=해외ETF, FS=외국주권, DR=예탁증서 등
      // 주식(보통주/우선주)만 포함: ST만 통과
      const grpCode = asciiDec.decode(tailBytes.slice(0, 2)).trim();
      if (grpCode !== 'ST') { lineStart = i + 1; continue; }

      // name: front의 21바이트 이후 (EUC-KR 한글 포함)
      const name = euckrDec.decode(frontBytes.slice(21)).trim();
      if (!name) { lineStart = i + 1; continue; }

      result.push({ code, name });
      lineStart = i + 1;
    }
  }
  return result;
}

async function loadMasterDB(env) {
  const now = Date.now();
  if (masterDB.length > 0 && now - masterLoadedAt < MASTER_TTL) return;

  const all = [];
  for (const { url, tailLen } of MASTER_URLS) {
    try {
      const res = await fetch(url);
      if (!res.ok) continue;

      const blob = await res.arrayBuffer();
      const view = new DataView(blob);
      let offset = 0;
      while (offset < blob.byteLength - 30) {
        const sig = view.getUint32(offset, true);
        if (sig !== 0x04034b50) break;
        const compMethod = view.getUint16(offset + 8, true);
        const compSize   = view.getUint32(offset + 18, true);
        const nameLen    = view.getUint16(offset + 26, true);
        const extraLen   = view.getUint16(offset + 28, true);
        const dataOffset = offset + 30 + nameLen + extraLen;
        const compData   = blob.slice(dataOffset, dataOffset + compSize);

        let rawBuffer;
        if (compMethod === 0) {
          rawBuffer = compData;
        } else if (compMethod === 8) {
          const ds = new DecompressionStream('deflate-raw');
          const writer = ds.writable.getWriter();
          const reader = ds.readable.getReader();
          writer.write(new Uint8Array(compData));
          writer.close();
          const chunks = [];
          let totalLen = 0;
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            chunks.push(value);
            totalLen += value.length;
          }
          const merged = new Uint8Array(totalLen);
          let pos = 0;
          for (const c of chunks) { merged.set(c, pos); pos += c.length; }
          rawBuffer = merged.buffer;
        } else {
          break;
        }

        const parsed = await parseMst(rawBuffer, tailLen);
        all.push(...parsed);
        break;
      }
    } catch (e) {
      console.error('마스터파일 로드 실패:', url, e.message);
    }
  }

  if (all.length > 0) {
    // 스팩(SPAC), 리츠 등 노이즈 종목 제거
    const EXCLUDE_KEYWORDS = ['스팩', 'SPAC', '스팩주'];
    masterDB = all.filter(({ name }) =>
      !EXCLUDE_KEYWORDS.some(kw => name.includes(kw))
    );
    masterLoadedAt = now;

    // KV에 masterDB 캐싱 (검색용 — TTL 25시간)
    try {
      if (env && env.KV) {
        await env.KV.put('master_db_cache', JSON.stringify(masterDB), { expirationTtl: 25 * 60 * 60 });
        console.log(`[마스터DB] KV 캐시 저장 완료: ${masterDB.length}개 종목`);
      }
    } catch (e) {
      console.warn('[마스터DB] KV 캐시 저장 실패:', e.message);
    }
  }
}

function searchStocks(q) {
  if (!q || q.length < 1) return [];
  const lower = q.toLowerCase();
  const db = masterDB.length > 0 ? masterDB : [];
  return db
    .filter(({ code, name }) =>
      name.toLowerCase().includes(lower) || code.includes(q)
    )
    .slice(0, 20)
    .map(({ code, name }) => ({ code, name }));
}

// ────────────────────────────────────────────────────────────
// 추세추종 신호 — 조건별 플래그 반환 (프론트에서 자유롭게 필터)
// kospiRs3m: 코스피 3개월 수익률 (runFullScan에서 미리 계산해서 넘김)
// ────────────────────────────────────────────────────────────
function calcSignalFlags(data, kospiRs3m = 0) {
  const flag_high20  = data.curr > 0 && data.high20 > 0 && data.curr >= data.high20 * 0.98; // 20일 신고가 2% 이내 근접 포함
  const flag_vol     = data.todayVol > 0 && data.avgVol > 0 && data.todayVol >= data.avgVol * 1.5;
  const flag_near52w = data.high52 > 0 && data.curr >= data.high52 * 0.90; // -10% 이내
  // RS: 청크 스캔 시 임시로 코스피 초과 조건 사용 (sendFinal에서 IBD RS 레이팅으로 재계산)
  const flag_rs      = data.rs3m > 0 && data.rs3m > kospiRs3m;
  // 월봉 10선 위: 현재가 > 최근 10개월 이동평균
  const flag_ma10m   = data.ma10m > 0 && data.curr > data.ma10m;

  const reasons = [];
  if (flag_high20)  reasons.push('20일 신고가 돌파');
  if (flag_vol)     reasons.push('거래량 1.5배');
  if (flag_near52w) reasons.push('52주 고점 -10% 이내');
  if (flag_rs)      reasons.push(`RS 강세 (${data.rs3m.toFixed(1)}% vs 코스피 ${kospiRs3m.toFixed(1)}%)`);
  if (flag_ma10m)   reasons.push(`월봉 10선 위 (MA: ${data.ma10m.toLocaleString()})`);

  // 하나라도 신호가 있으면 결과에 포함 (필터는 프론트에서)
  const anySignal = flag_high20 || flag_vol || flag_near52w || flag_rs || flag_ma10m;
  const score = [flag_high20, flag_vol, flag_near52w, flag_rs, flag_ma10m].filter(Boolean).length;

  return { score, reasons, anySignal, flags: { high20: flag_high20, vol: flag_vol, near52w: flag_near52w, rs: flag_rs, ma10m: flag_ma10m } };
}

// ────────────────────────────────────────────────────────────
// IBD RS 레이팅 계산: allResults 전체의 rs3m 기준 백분위 (0~99)
// RS 레이팅 90 = 전체 종목 중 상위 10%
// ────────────────────────────────────────────────────────────
function calcRsRatings(allResults) {
  // rs3m 값 정렬 (오름차순)
  const rs3mValues = allResults.map(r => r.rs3m).sort((a, b) => a - b);
  const n = rs3mValues.length;
  if (n === 0) return;

  allResults.forEach(r => {
    // 자신보다 낮은 rs3m 종목 수 / 전체 = 하위 몇% → 상위 % = 100 - 하위%
    const rank = rs3mValues.filter(v => v < r.rs3m).length;
    r.rsRating = Math.min(99, Math.floor((rank / n) * 100));
  });
}

// ────────────────────────────────────────────────────────────
// sendFinal에서 RS 조건 재적용: IBD RS 레이팅 90 이상으로 업데이트
// ────────────────────────────────────────────────────────────
function applyRsRatingCondition(allResults) {
  calcRsRatings(allResults);

  allResults.forEach(r => {
    const newFlagRs = (r.rsRating ?? 0) >= 90;
    const oldFlagRs = r.flags?.rs ?? false;

    if (newFlagRs === oldFlagRs) return; // 변화 없으면 패스

    r.flags = r.flags || {};
    r.flags.rs = newFlagRs;

    // reasons 업데이트: 기존 RS 관련 항목 제거 후 새 항목 추가
    r.reasons = (r.reasons || []).filter(s => !s.startsWith('RS 강세'));
    if (newFlagRs) r.reasons.push(`RS 레이팅 ${r.rsRating} (상위 ${100 - r.rsRating}%)`);

    // score 재계산
    r.score = [r.flags.high20, r.flags.vol, r.flags.near52w, r.flags.rs, r.flags.ma10m].filter(Boolean).length;
  });

  // score=0이 된 종목(다른 조건도 없는 경우)은 anySignal 없으므로 필터링
  return allResults.filter(r => r.score >= 1 ||
    r.flags?.high20 || r.flags?.vol || r.flags?.near52w || r.flags?.rs || r.flags?.ma10m);
}

// ────────────────────────────────────────────────────────────
// 전종목 스캔
// ────────────────────────────────────────────────────────────
async function runFullScan(env) {
  await loadMasterDB(env);
  if (masterDB.length === 0) throw new Error('마스터DB 로드 실패');

  // 코스피 3개월 수익률 미리 계산 (RS 비교 기준)
  let kospiRs3m = 0;
  try {
    const kospiData = await getKospiMA(env); // curr 값 있음
    // 코스피 63거래일 전 종가는 getKospiMA 내부 rows에서 취하기 어려우므로
    // KospiMA 대신 별도 간이 fetch
    const token = await getToken(env);
    const today = new Date(Date.now() + 9 * 60 * 60 * 1000).toISOString().slice(0,10).replace(/-/g,'');
    const idxRes = await fetch(
      `${KIS_BASE}/uapi/domestic-stock/v1/quotations/inquire-daily-indexchartprice`
      + `?FID_COND_MRKT_DIV_CODE=U&FID_INPUT_ISCD=0001`
      + `&FID_INPUT_DATE_1=20240101&FID_INPUT_DATE_2=${today}&FID_PERIOD_DIV_CODE=D`,
      { headers: kisHeaders(token, 'FHKUP03500100', env) }
    );
    if (idxRes.ok) {
      const idxData = await idxRes.json();
      const rows = Array.isArray(idxData.output2) ? idxData.output2 : [];
      const currIdx  = parseFloat(idxData.output1?.[0]?.bstp_nmix_prpr || idxData.output1?.bstp_nmix_prpr) || 0;
      const prev63   = parseFloat(rows[62]?.bstp_nmix_clpr || rows[62]?.stck_clpr) || 0;
      if (currIdx > 0 && prev63 > 0) kospiRs3m = ((currIdx - prev63) / prev63) * 100;
    }
  } catch(e) { console.error('코스피 RS 계산 실패:', e.message); }

  const allResults = [];
  const BATCH = 5;
  const DELAY = 300;

  for (let i = 0; i < masterDB.length; i += BATCH) {
    const batch = masterDB.slice(i, i + BATCH);
    const batchResults = await Promise.allSettled(
      batch.map(async ({ code, name }) => {
        try {
          const data = await getOHLCV(code, env);
          // 거래정지 종목 제외
          if (!data.curr || data.isHalted) return null;
          const { score, reasons, anySignal, flags } = calcSignalFlags(data, kospiRs3m);
          if (!anySignal) return null;
          return {
            code, name, score, reasons, flags,
            curr:     data.curr,
            high20:   data.high20,
            high52:   data.high52,
            avgVol:   data.avgVol,
            todayVol: data.todayVol,
            atr:      data.atr,
            low10:    data.low10,
            rs3m:     Math.round(data.rs3m * 10) / 10,
            ma10m:    data.ma10m,
          };
        } catch { return null; }
      })
    );
    for (const r of batchResults) {
      if (r.status === 'fulfilled' && r.value) allResults.push(r.value);
    }
    if (i + BATCH < masterDB.length) {
      await new Promise(res => setTimeout(res, DELAY));
    }
  }

  allResults.sort((a, b) => b.score - a.score);

  const scannedAt = new Date().toISOString();
  const total = masterDB.length;

  // 기본: 20일신고가·거래량급증·RS강세·월봉10선 중 2개 이상 / 엄격: 핵심3개(신고가·거래량·RS) 동시 충족
  const basicResults  = allResults.filter(r => {
    const { high20, vol, rs, ma10m } = r.flags;
    return [high20, vol, rs, ma10m].filter(Boolean).length >= 2;
  });
  const strictResults = allResults.filter(r => r.flags.high20 && r.flags.vol && r.flags.rs);

  const basicData  = { scannedAt, total, kospiRs3m: Math.round(kospiRs3m * 10) / 10, hits: basicResults.length,  results: basicResults.slice(0, 200) };
  const strictData = { scannedAt, total, kospiRs3m: Math.round(kospiRs3m * 10) / 10, hits: strictResults.length, results: strictResults.slice(0, 200) };

  await env.KV.put('scan_result_basic',  JSON.stringify(basicData),  { expirationTtl: 86400 });
  await env.KV.put('scan_result_strict', JSON.stringify(strictData), { expirationTtl: 86400 });

  return { basic: basicData, strict: strictData };
}

// ────────────────────────────────────────────────────────────
// 카카오 액세스 토큰 자동 갱신
// ────────────────────────────────────────────────────────────
async function refreshKakaoToken(env) {
  const refreshToken = env.KAKAO_REFRESH_TOKEN || await env.KV.get('kakao_refresh_token');
  if (!refreshToken) {
    console.error('[카카오] refresh token 없음 (Secret·KV 모두 없음)');
    return null;
  }

  const params = new URLSearchParams({
    grant_type: 'refresh_token',
    client_id: 'c52ddf70d09b1bb969c7fe77c91ad849',
    client_secret: '5mg0cMZz77qxpOsERhLSfaagrMofOXUm',
    refresh_token: refreshToken,
  });

  const res = await fetch('https://kauth.kakao.com/oauth/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString(),
  });
  const data = await res.json();
  console.log('[카카오] refresh 응답:', JSON.stringify(data).slice(0, 200));

  if (data.access_token) {
    console.log('[카카오] refresh token으로 access token 갱신 성공');
    try {
      // access token: 6시간 TTL로 KV 저장
      await env.KV.put('kakao_token_cache', data.access_token, { expirationTtl: 21600 });
      await env.KV.put('kakao_token', data.access_token);
      // refresh token이 새로 발급됐으면 갱신 (카카오는 만료 1개월 전부터 새 refresh token 발급)
      if (data.refresh_token) {
        await env.KV.put('kakao_refresh_token', data.refresh_token);
        console.log('[카카오] refresh token도 갱신됨');
      }
    } catch(e) {
      console.error('카카오 토큰 KV 저장 실패 (무시):', e.message);
    }
    return data.access_token;
  }
  console.error('[카카오] refresh token 갱신 실패:', JSON.stringify(data));
  // refresh token 자체가 만료된 경우 KV에서 삭제 (재인증 유도)
  if (data.error === 'invalid_grant') {
    try { await env.KV.delete('kakao_refresh_token'); } catch(_) {}
    console.error('[카카오] refresh token 만료됨 — /kakao-auth 재인증 필요');
  }
  return null;
}

// ────────────────────────────────────────────────────────────
// 카카오톡 자동 알림 전송
// ────────────────────────────────────────────────────────────
async function sendKakaoScanAlert(env, basic, strict) {
  const enabled = await env.KV.get('kakao_notify_enabled');
  if (enabled !== 'true') {
    console.log('[카카오] 알림 비활성화 상태 (kakao_notify_enabled !== "true"), enabled =', enabled);
    return;
  }

  let token = await refreshKakaoToken(env);
  if (!token) {
    token = await env.KV.get('kakao_token_cache');
    if (token) console.log('[카카오] KV kakao_token_cache 사용 (refresh 실패)');
  }
  if (!token) {
    token = env.KAKAO_ACCESS_TOKEN;
    if (token) console.log('[카카오] Secret KAKAO_ACCESS_TOKEN 사용 (fallback)');
  }
  if (!token) {
    token = await env.KV.get('kakao_token');
    if (token) console.log('[카카오] KV kakao_token 사용');
  }
  if (!token) {
    console.error('[카카오] 사용 가능한 토큰 없음 — 알림 전송 불가');
    return;
  }

  const today = new Date().toLocaleDateString('ko-KR', { timeZone: 'Asia/Seoul', year: 'numeric', month: 'long', day: 'numeric' });

  let msg = `📈 ${today} 자동선별 스캔 결과\n엄격 ${strict.hits}종목 / 기본 ${basic.hits}종목\n\n`;

  if (strict.hits > 0) {
    msg += `🎯 [엄격 ${strict.hits}종목]\n`;
    strict.results.slice(0, 5).forEach(r => {
      msg += `${r.name} (${r.code})\n`;
      r.reasons.forEach(reason => { msg += ` ✅ ${reason}\n`; });
      msg += ` 신호 점수: ${r.score}점\n\n`;
    });
  } else {
    msg += `🎯 [엄격] 신호 없음\n\n`;
  }

  if (basic.hits > 0) {
    const strictCodes = new Set((strict.results || []).map(r => r.code));
    const basicOnly = basic.results.filter(r => !strictCodes.has(r.code));
    if (basicOnly.length > 0) {
      msg += `📊 [기본 추가 ${basicOnly.length}종목]\n`;
      basicOnly.slice(0, 5).forEach(r => {
        msg += `${r.name} (${r.code})\n`;
        r.reasons.forEach(reason => { msg += ` ✅ ${reason}\n`; });
        msg += ` 신호 점수: ${r.score}점\n\n`;
      });
    }
  } else {
    msg += `📊 [기본] 신호 없음`;
  }

  msg = msg.trim();

  const params = new URLSearchParams({
    template_object: JSON.stringify({
      object_type: 'text',
      text: msg,
      link: {
        web_url: 'https://wlsdn816-eng.github.io/trend-tracker/',
        mobile_web_url: 'https://wlsdn816-eng.github.io/trend-tracker/',
      },
    }),
  });

  const kakaoRes = await fetch('https://kapi.kakao.com/v2/api/talk/memo/default/send', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params.toString(),
  });
  const kakaoData = await kakaoRes.json();
  if (kakaoData.result_code === 0) {
    console.log('[카카오] 알림 전송 성공');
  } else {
    console.error('[카카오] 알림 전송 실패:', JSON.stringify(kakaoData));
  }
}

// ────────────────────────────────────────────────────────────
// 네이버 블로그 RSS 피드 (chcmg2022 너쟁이 + jeunkim 피우스)
// ────────────────────────────────────────────────────────────
async function parseBlogRss(blogId, authorLabel, maxItems = 10) {
  const rss = await fetch(`https://rss.blog.naver.com/${blogId}.xml`, {
    headers: { 'User-Agent': 'Mozilla/5.0' },
  });
  if (!rss.ok) throw new Error(`RSS HTTP ${rss.status} (${blogId})`);
  const xml = await rss.text();

  const items = [];
  const itemRx = /<item>([\s\S]*?)<\/item>/g;
  let m;
  while ((m = itemRx.exec(xml)) !== null && items.length < maxItems) {
    const get = (tag) => {
      const r = new RegExp(`<${tag}[^>]*><!\\[CDATA\\[([\\s\\S]*?)\\]\\]><\\/${tag}>|<${tag}[^>]*>([^<]*)<\\/${tag}>`);
      const mm = r.exec(m[1]);
      return mm ? (mm[1] || mm[2] || '').trim() : '';
    };
    const title = get('title');
    const link  = get('link') || get('guid');
    const pub   = get('pubDate');
    const desc  = get('description').replace(/<[^>]*>/g, '').trim().slice(0, 100);
    let date = '';
    let ts = 0;
    if (pub) {
      const d = new Date(pub);
      if (!isNaN(d)) {
        date = (d.getMonth() + 1) + '/' + d.getDate();
        ts = d.getTime();
      }
    }
    if (title) items.push({ title, link, summary: desc, date, ts, author: authorLabel });
  }
  return items;
}

async function getBlogFeed() {
  const [neoItems, piusItems] = await Promise.allSettled([
    parseBlogRss('chcmg2022', '너쟁이', 10),
    parseBlogRss('jeunkim',   '피우스',  10),
  ]);
  const all = [
    ...(neoItems.status === 'fulfilled' ? neoItems.value : []),
    ...(piusItems.status === 'fulfilled' ? piusItems.value : []),
  ];
  // 날짜 내림차순 정렬, 날짜 없으면 뒤로
  all.sort((a, b) => (b.ts || 0) - (a.ts || 0));
  return { items: all.slice(0, 20) };
}

// ────────────────────────────────────────────────────────────
// 한국투자증권 리서치 리포트 (네이버 증권 브로커코드 15)
// Worker 서버사이드에서 직접 fetch → KV 캐시
// ────────────────────────────────────────────────────────────
async function fetchResearchFromNaver() {
  const commonHeaders = {
    'User-Agent': 'Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'ko-KR,ko;q=0.9',
  };

  // 작동 확인된 네이버 증권 모바일 API
  const apiUrl = 'https://m.stock.naver.com/api/research/company?brokerCode=15&page=1&pageSize=20';
  const res = await fetch(apiUrl, { headers: { ...commonHeaders, 'Referer': 'https://m.stock.naver.com/' } });
  if (!res.ok) throw new Error('naver_api_http_' + res.status);

  const ct = res.headers.get('content-type') || '';
  if (!ct.includes('json')) throw new Error('not_json:' + ct.slice(0, 50));

  const json = await res.json();
  const rawList = Array.isArray(json) ? json : (json?.list || json?.data || json?.items || []);
  if (!rawList.length) throw new Error('empty_list');

  return rawList.slice(0, 15).map(r => ({
    title:   r.title      || r.reportTitle || '',
    link:    r.endUrl     || r.url         || r.link || '',   // ← 실제 필드명 endUrl
    date:    r.writeDate  || r.reportDate  || r.date || '',   // ← 실제 필드명 writeDate
    company: r.brokerName || r.broker      || r.company || '한국투자',
    summary: r.category   || r.description || r.summary || '',
  })).filter(r => r.title.length > 2);
}

async function getResearchFeed(env) {
  const KV_KEY = 'research_feed_cache_v2'; // v2: endUrl/writeDate 필드 매핑 수정

  // 1) KV 캐시 확인 (6시간 유효)
  try {
    const cached = await env.KV.get(KV_KEY, 'json');
    if (cached && cached.items && cached.items.length > 0 && cached.fetchedAt) {
      const ageMs = Date.now() - new Date(cached.fetchedAt).getTime();
      if (ageMs < 6 * 60 * 60 * 1000) {
        return { items: cached.items, source: 'cache', fetchedAt: cached.fetchedAt };
      }
    }
  } catch (_) { /* KV 실패 시 직접 fetch */ }

  // 2) 네이버 증권 직접 fetch
  let fetchError = null;
  try {
    const items = await fetchResearchFromNaver();
    if (items.length > 0) {
      const fetchedAt = new Date(Date.now() + 9 * 60 * 60 * 1000).toISOString().slice(0, 16);
      // KV에 저장 (TTL 8시간)
      try {
        await env.KV.put(KV_KEY, JSON.stringify({ items, fetchedAt }), { expirationTtl: 8 * 60 * 60 });
      } catch (_) { /* KV 저장 실패는 무시 */ }
      return { items, source: 'live', fetchedAt };
    }
  } catch (e) {
    fetchError = e.message;
    console.error('네이버 증권 fetch 실패:', e.message);
  }

  // 3) KV에 만료된 캐시라도 있으면 반환
  try {
    const stale = await env.KV.get(KV_KEY, 'json');
    if (stale && stale.items && stale.items.length > 0) {
      return { items: stale.items, source: 'stale', fetchedAt: stale.fetchedAt };
    }
  } catch (_) {}

  return { items: [], error: fetchError || 'fetch_failed' };
}

// ────────────────────────────────────────────────────────────
// 메인 핸들러
// ────────────────────────────────────────────────────────────
export default {
  // Cron Trigger — 매일 오후 4시 (KST = UTC 07:00)
  async scheduled(event, env, ctx) {
    ctx.waitUntil((async () => {
      // 1) 자동선별 스캔 + 카카오 알림
      const data = await runFullScan(env);
      await sendKakaoScanAlert(env, data.basic, data.strict);

      // 2) 보유 포지션 종가 스냅샷 KV에 저장
      try {
        const holdingsRaw = await env.TREND_TRACKER_KV.get('tf_holdings');
        if (holdingsRaw) {
          const holdings = JSON.parse(holdingsRaw);
          const codes = [...new Set(holdings.map(h => h.code).filter(Boolean))];
          if (codes.length) {
            const results = await Promise.allSettled(
              codes.slice(0, 10).map(code => getPrice(code, env))
            );
            const kstNow = new Date(Date.now() + 9 * 60 * 60 * 1000);
            const fetchedAt   = kstNow.toISOString().slice(0, 10);
            const fetchedTime = kstNow.toISOString().slice(11, 16);
            const quotes = {};
            results.forEach((r, i) => {
              if (r.status === 'fulfilled') {
                quotes[codes[i]] = { curr: r.value.curr, chg: r.value.chg, name: r.value.name };
              }
            });
            await env.TREND_TRACKER_KV.put(
              'tf_holdings_quotes',
              JSON.stringify({ quotes, fetchedAt, fetchedTime }),
              { expirationTtl: 7 * 24 * 60 * 60 }
            );
          }
        }
      } catch(e) {
        console.error('보유 포지션 종가 업데이트 실패:', e);
      }

      // 3) 리서치 피드 KV 갱신
      try {
        await getResearchFeed(env);
        console.log('리서치 피드 KV 갱신 완료');
      } catch(e) {
        console.error('리서치 피드 갱신 실패:', e);
      }
    })());
  },

  async fetch(request, env) {
    const url = new URL(request.url);

    // Preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS });
    }

    try {
      // GET /search?q=삼성
      if (url.pathname === '/search') {
        const q = url.searchParams.get('q') || '';
        if (!q) return corsResponse({ results: [] });

        // 1순위: 메모리에 masterDB 있으면 즉시 검색
        if (masterDB.length > 0) {
          return corsResponse({ results: searchStocks(q), total: masterDB.length });
        }

        // 2순위: KV 캐시에서 masterDB 복원 후 검색
        try {
          const cached = await env.KV.get('master_db_cache');
          if (cached) {
            masterDB = JSON.parse(cached);
            masterLoadedAt = Date.now();
            console.log(`[검색] KV 캐시에서 masterDB 복원: ${masterDB.length}개`);
            return corsResponse({ results: searchStocks(q), total: masterDB.length });
          }
        } catch (_) {}

        // 3순위: KV 캐시도 없으면 KIS API로 검색
        try {
          const token = await getToken(env);
          const kisRes = await fetch(
            `${KIS_BASE}/uapi/domestic-stock/v1/quotations/search-stock-info?PRDT_TYPE_CD=300&PDNO=${encodeURIComponent(q)}&PRDT_ABRV_NAME=${encodeURIComponent(q)}`,
            {
              headers: {
                'content-type': 'application/json',
                'authorization': `Bearer ${token}`,
                'appkey': env.KIS_APP_KEY,
                'appsecret': env.KIS_APP_SECRET,
                'tr_id': 'CTPF1604R',
                'custtype': 'P',
              },
            }
          );
          if (kisRes.ok) {
            const kisData = await kisRes.json();
            const items = kisData.output || [];
            const results = items
              .filter(it => it.pdno && it.prdt_abrv_name)
              .map(it => ({ code: it.pdno, name: it.prdt_abrv_name }))
              .slice(0, 20);
            if (results.length > 0) return corsResponse({ results });
          }
        } catch (_) {}

        // 모두 실패 시: masterDB 백그라운드 로드 트리거 후 빈 결과 반환
        // (다음 요청에서는 KV 캐시가 채워져 있을 것)
        loadMasterDB(env).catch(() => {});
        return corsResponse({ results: [], error: '종목 DB 준비 중 — 잠시 후 다시 검색해주세요' });
      }

      // GET /master-reload
      if (url.pathname === '/master-reload') {
        masterLoadedAt = 0;
        await loadMasterDB(env);
        return corsResponse({ ok: true, total: masterDB.length });
      }

      // GET /master-debug — grpCode 분포 확인용 (배포 후 삭제)
      if (url.pathname === '/master-debug') {
        const debugResult = [];
        for (const { url: mUrl, tailLen } of MASTER_URLS) {
          try {
            const res = await fetch(mUrl);
            if (!res.ok) { debugResult.push({ url: mUrl, error: `HTTP ${res.status}` }); continue; }
            const blob = await res.arrayBuffer();
            // ZIP 해제
            const view = new DataView(blob);
            let offset = 0;
            let rawBuffer = null;
            while (offset < blob.byteLength - 30) {
              const sig = view.getUint32(offset, true);
              if (sig !== 0x04034b50) break;
              const compMethod = view.getUint16(offset + 8, true);
              const compSize   = view.getUint32(offset + 18, true);
              const nameLen    = view.getUint16(offset + 26, true);
              const extraLen   = view.getUint16(offset + 28, true);
              const dataOffset = offset + 30 + nameLen + extraLen;
              const compData   = blob.slice(dataOffset, dataOffset + compSize);
              if (compMethod === 0) {
                rawBuffer = compData;
              } else if (compMethod === 8) {
                const ds = new DecompressionStream('deflate-raw');
                const writer = ds.writable.getWriter();
                const reader = ds.readable.getReader();
                writer.write(new Uint8Array(compData));
                writer.close();
                const chunks = []; let totalLen = 0;
                while (true) { const { done, value } = await reader.read(); if (done) break; chunks.push(value); totalLen += value.length; }
                const merged = new Uint8Array(totalLen); let pos = 0;
                for (const c of chunks) { merged.set(c, pos); pos += c.length; }
                rawBuffer = merged.buffer;
              }
              break;
            }
            if (!rawBuffer) { debugResult.push({ url: mUrl, error: 'ZIP 해제 실패' }); continue; }
            // grpCode 분포 집계 (필터 없이)
            const bytes = new Uint8Array(rawBuffer);
            const asciiDec = new TextDecoder('ascii', { fatal: false });
            const grpDist = {}; let count = 0, stCount = 0;
            let lineStart = 0;
            for (let i = 0; i <= bytes.length; i++) {
              if (i === bytes.length || bytes[i] === 0x0A) {
                let lineEnd = i;
                if (lineEnd > lineStart && bytes[lineEnd - 1] === 0x0D) lineEnd--;
                const lineLen = lineEnd - lineStart;
                if (lineLen >= tailLen + 21) {
                  const frontByteLen = lineLen - tailLen + 1;
                  const code = asciiDec.decode(bytes.slice(lineStart, lineStart + 9)).trim();
                  if (/^\d{6}$/.test(code)) {
                    const grp = asciiDec.decode(bytes.slice(lineStart + frontByteLen, lineStart + frontByteLen + 2)).trim();
                    grpDist[grp] = (grpDist[grp] || 0) + 1;
                    count++; if (grp === 'ST') stCount++;
                  }
                }
                lineStart = i + 1;
              }
            }
            debugResult.push({ url: mUrl, total: count, stCount, grpDist });
          } catch (e) {
            debugResult.push({ url: mUrl, error: e.message });
          }
        }
        return corsResponse({ debug: debugResult });
      }

      // GET /price?code=005930
      if (url.pathname === '/price') {
        const code = url.searchParams.get('code') || '';
        if (!code) return corsResponse({ error: 'code 파라미터 필요' }, 400);
        const data = await getPrice(code, env);
        return corsResponse(data);
      }

      // GET /ohlcv?code=005930
      if (url.pathname === '/ohlcv') {
        const code = url.searchParams.get('code') || '';
        if (!code) return corsResponse({ error: 'code 파라미터 필요' }, 400);
        const data = await getOHLCV(code, env);
        return corsResponse(data);
      }

      // GET /scan-result?mode=basic|strict
      if (url.pathname === '/scan-result') {
        const mode = url.searchParams.get('mode') || 'basic';
        const key = mode === 'strict' ? 'scan_result_strict' : 'scan_result_basic';
        const raw = await env.KV.get(key);
        if (!raw) return corsResponse({ error: '스캔 결과 없음. /scan-now로 먼저 스캔하세요.' }, 404);
        return corsResponse(JSON.parse(raw));
      }

      // POST /scan-now
      if (url.pathname === '/scan-now') {
        if (request.method !== 'POST') return corsResponse({ error: 'POST만 허용' }, 405);
        const data = await runFullScan(env);
        return corsResponse({ ok: true, basic: data.basic.hits, strict: data.strict.hits, total: data.basic.total, scannedAt: data.basic.scannedAt });
      }

      // POST /scan-kakao — GitHub Actions에서 호출: 스캔 + 카카오 알림
      if (url.pathname === '/scan-kakao') {
        if (request.method !== 'POST') return corsResponse({ error: 'POST만 허용' }, 405);
        const data = await runFullScan(env);
        await sendKakaoScanAlert(env, data.basic, data.strict);
        return corsResponse({ ok: true, basicHits: data.basic.hits.length, strictHits: data.strict.hits.length, scannedAt: data.basic.scannedAt });
      }

      // POST /scan-chunk — GitHub Actions 청크 분할 스캔 (서브요청 50개 제한 우회)
      // body: { offset, chunkSize, scannedAt, kospiRs3m }
      //   → 청크 스캔 결과를 응답으로 반환 (KV 누적 저장 없음 — KV 쓰기 절약)
      // body: { sendFinal: true, scannedAt, kospiRs3m, allResults: [...] }
      //   → GitHub Actions가 누적한 전체 결과를 받아 KV 저장 + 카카오 알림 (KV 2회만)
      if (url.pathname === '/scan-chunk') {
        if (request.method !== 'POST') return corsResponse({ error: 'POST만 허용' }, 405);
        const body = await request.json().catch(() => ({}));

        // ── sendFinal 모드: 전체 결과 KV 저장 + 카카오 알림 ──
        if (body.sendFinal) {
          let allResults    = Array.isArray(body.allResults) ? body.allResults : [];
          const scannedAt   = body.scannedAt || new Date().toISOString();
          const total       = parseInt(body.total ?? 0);
          const kospiRs3m   = parseFloat(body.kospiRs3m ?? 0);
          const sendKakao   = !!body.sendKakao;

          // IBD RS 레이팅 90 이상으로 RS 조건 재적용 (전체 종목 기준 백분위)
          allResults = applyRsRatingCondition(allResults);

          allResults.sort((a, b) => b.score - a.score);
          // 기본: 20일신고가·거래량급증·RS강세·월봉10선 중 2개 이상 / 엄격: 핵심3개(신고가·거래량·RS) 동시 충족
          const basicResults  = allResults.filter(r => {
            const { high20, vol, rs, ma10m } = r.flags ?? {};
            return [high20, vol, rs, ma10m].filter(Boolean).length >= 2;
          });
          const strictResults = allResults.filter(r => r.flags?.high20 && r.flags?.vol && r.flags?.rs);
          const basicData  = { scannedAt, total, kospiRs3m: Math.round(kospiRs3m*10)/10, hits: basicResults.length,  results: basicResults.slice(0,200) };
          const strictData = { scannedAt, total, kospiRs3m: Math.round(kospiRs3m*10)/10, hits: strictResults.length, results: strictResults.slice(0,200) };

          // KV 저장 실패해도 카카오 알림은 반드시 전송
          let kvSaved = false;
          try {
            await env.KV.put('scan_result_basic',  JSON.stringify(basicData),  { expirationTtl: 86400 });
            await env.KV.put('scan_result_strict', JSON.stringify(strictData), { expirationTtl: 86400 });
            kvSaved = true;
          } catch(e) {
            console.error('KV 저장 실패 (무시하고 카카오 전송 진행):', e.message);
          }
          if (sendKakao) await sendKakaoScanAlert(env, basicData, strictData);
          return corsResponse({ ok: true, saved: kvSaved, basicHits: basicResults.length, strictHits: strictResults.length, total, scannedAt });
        }

        // ── 청크 스캔 모드: 결과만 반환, KV 쓰기 없음 ──
        const offset    = parseInt(body.offset    ?? 0);
        const chunkSize = parseInt(body.chunkSize ?? 50);
        const isFirst   = offset === 0;

        await loadMasterDB(env);
        if (masterDB.length === 0) throw new Error('마스터DB 로드 실패');

        // 첫 청크: 코스피 RS 계산
        let kospiRs3m = parseFloat(body.kospiRs3m ?? 0);
        const scannedAt = body.scannedAt || new Date().toISOString();
        const total = masterDB.length;

        if (isFirst) {
          try {
            const token = await getToken(env);
            const today = new Date(Date.now() + 9*60*60*1000).toISOString().slice(0,10).replace(/-/g,'');
            const idxRes = await fetch(
              `${KIS_BASE}/uapi/domestic-stock/v1/quotations/inquire-daily-indexchartprice`
              + `?FID_COND_MRKT_DIV_CODE=U&FID_INPUT_ISCD=0001&FID_INPUT_DATE_1=20240101&FID_INPUT_DATE_2=${today}&FID_PERIOD_DIV_CODE=D`,
              { headers: kisHeaders(token, 'FHKUP03500100', env) }
            );
            if (idxRes.ok) {
              const idxData = await idxRes.json();
              const rows = Array.isArray(idxData.output2) ? idxData.output2 : [];
              const currIdx = parseFloat(idxData.output1?.[0]?.bstp_nmix_prpr) || 0;
              const prev63  = parseFloat(rows[62]?.bstp_nmix_clpr) || 0;
              if (currIdx > 0 && prev63 > 0) kospiRs3m = ((currIdx - prev63) / prev63) * 100;
            }
          } catch(e) { console.error('코스피 RS 실패:', e.message); }
        }

        // 해당 청크 종목 스캔
        const chunk = masterDB.slice(offset, offset + chunkSize);
        const chunkResults = [];
        for (let i = 0; i < chunk.length; i += 5) {
          const mini = chunk.slice(i, i + 5);
          const results = await Promise.allSettled(mini.map(async ({ code, name }) => {
            try {
              const data = await getOHLCV(code, env);
              // 거래정지 종목 제외
              if (!data.curr || data.isHalted) return null;
              const { score, reasons, anySignal, flags } = calcSignalFlags(data, kospiRs3m);
              if (!anySignal) return null;
              return { code, name, score, reasons, flags, curr: data.curr, high20: data.high20, high52: data.high52, avgVol: data.avgVol, todayVol: data.todayVol, atr: data.atr, low10: data.low10, rs3m: Math.round(data.rs3m*10)/10, ma10m: data.ma10m };
            } catch { return null; }
          }));
          for (const r of results) if (r.status === 'fulfilled' && r.value) chunkResults.push(r.value);
          if (i + 5 < chunk.length) await new Promise(res => setTimeout(res, 200));
        }

        const nextOffset = offset + chunkSize;
        const done = nextOffset >= total;

        // KV 쓰기 없이 결과를 응답으로만 반환
        return corsResponse({ ok: true, done, nextOffset: done ? null : nextOffset, total, kospiRs3m, scannedAt, chunkResults });
      }

      // GET /token
      if (url.pathname === '/token') {
        await getToken(env);
        return corsResponse({ ok: true, expires_in: Math.max(0, tokenExpiry - Date.now()) });
      }

      // POST /kakao-token
      if (url.pathname === '/kakao-token') {
        if (request.method !== 'POST') return corsResponse({ error: 'POST만 허용' }, 405);
        const body = await request.text();
        const res = await fetch('https://kauth.kakao.com/oauth/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body,
        });
        const data = await res.json();
        return corsResponse(data);
      }

      // POST /notify
      if (url.pathname === '/notify') {
        if (request.method !== 'POST') return corsResponse({ error: 'POST만 허용' }, 405);
        const { message, kakaoToken } = await request.json();
        const token = kakaoToken || env.KAKAO_ACCESS_TOKEN;
        if (!token) return corsResponse({ error: 'kakaoToken 없음' }, 400);

        const params = new URLSearchParams({
          template_object: JSON.stringify({
            object_type: 'text',
            text: message || '알림',
            link: {
              web_url: 'https://wlsdn816-eng.github.io/trend-tracker/',
              mobile_web_url: 'https://wlsdn816-eng.github.io/trend-tracker/',
            },
          }),
        });

        const res = await fetch('https://kapi.kakao.com/v2/api/talk/memo/default/send', {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: params.toString(),
        });
        const data = await res.json();
        return corsResponse(data);
      }

      // GET /kakao-test — KV 토큰으로 카카오 알림 직접 테스트 (디버그용)
      if (url.pathname === '/kakao-test') {
        const enabled = await env.KV.get('kakao_notify_enabled');
        const kvToken = await env.KV.get('kakao_token');
        const kvCache = await env.KV.get('kakao_token_cache');
        const kvRefresh = await env.KV.get('kakao_refresh_token');

        // refresh 시도 (실패 원인 상세 기록)
        let refreshedToken = null;
        let refreshError = null;
        let refreshDetail = null;
        try {
          // refresh token으로 직접 시도해서 응답 확인
          if (kvRefresh) {
            const rParams = new URLSearchParams({
              grant_type: 'refresh_token',
              client_id: 'c52ddf70d09b1bb969c7fe77c91ad849',
              refresh_token: kvRefresh,
              client_secret: '5mg0cMZz77qxpOsERhLSfaagrMofOXUm',
            });
            const rRes = await fetch('https://kauth.kakao.com/oauth/token', {
              method: 'POST',
              headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
              body: rParams.toString(),
            });
            refreshDetail = await rRes.json();
            if (refreshDetail.access_token) {
              refreshedToken = refreshDetail.access_token;
              await env.KV.put('kakao_token_cache', refreshedToken, { expirationTtl: 21600 });
              await env.KV.put('kakao_token', refreshedToken);
              if (refreshDetail.refresh_token) await env.KV.put('kakao_refresh_token', refreshDetail.refresh_token);
            }
          }
        } catch(e) {
          refreshError = e.message;
        }

        const tokenToUse = refreshedToken || kvCache || kvToken;
        let kakaoResult = null;
        if (tokenToUse) {
          const params = new URLSearchParams({
            template_object: JSON.stringify({
              object_type: 'text',
              text: '🔔 카카오 테스트 알림 — Worker KV 토큰으로 전송',
              link: { web_url: 'https://wlsdn816-eng.github.io/trend-tracker/', mobile_web_url: 'https://wlsdn816-eng.github.io/trend-tracker/' },
            }),
          });
          const res = await fetch('https://kapi.kakao.com/v2/api/talk/memo/default/send', {
            method: 'POST',
            headers: { Authorization: `Bearer ${tokenToUse}`, 'Content-Type': 'application/x-www-form-urlencoded' },
            body: params.toString(),
          });
          kakaoResult = await res.json();
        }

        return corsResponse({
          enabled,
          hasKvToken: !!kvToken,
          hasKvCache: !!kvCache,
          hasKvRefresh: !!kvRefresh,
          refreshed: !!refreshedToken,
          refreshError,
          refreshDetail,  // refresh 실패 시 카카오 응답 상세
          kakaoResult,
          tokenUsed: tokenToUse ? tokenToUse.slice(0, 10) + '...' : null,
        });
      }

      // GET /kakao-auth — 카카오 OAuth 인증 URL로 리다이렉트
      if (url.pathname === '/kakao-auth') {
        const restApiKey = 'c52ddf70d09b1bb969c7fe77c91ad849';
        const redirectUri = `https://kis-proxy.wlsdn816.workers.dev/kakao-callback`;
        const authUrl = `https://kauth.kakao.com/oauth/authorize?client_id=${restApiKey}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code`;
        return Response.redirect(authUrl, 302);
      }

      // GET /kakao-callback — 카카오 인증 코드 → 토큰 교환 후 KV 저장
      if (url.pathname === '/kakao-callback') {
        const code = url.searchParams.get('code');
        if (!code) {
          return new Response('인증 코드 없음', { status: 400 });
        }
        const restApiKey = 'c52ddf70d09b1bb969c7fe77c91ad849';
        const redirectUri = `https://kis-proxy.wlsdn816.workers.dev/kakao-callback`;
        const params = new URLSearchParams({
          grant_type: 'authorization_code',
          client_id: restApiKey,
          redirect_uri: redirectUri,
          code,
          client_secret: '5mg0cMZz77qxpOsERhLSfaagrMofOXUm',
        });
        const res = await fetch('https://kauth.kakao.com/oauth/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: params.toString(),
        });
        const data = await res.json();
        if (!data.access_token) {
          return new Response(`토큰 발급 실패: ${JSON.stringify(data)}`, { status: 400 });
        }
        // KV에 저장
        await env.KV.put('kakao_token', data.access_token);
        await env.KV.put('kakao_token_cache', data.access_token, { expirationTtl: 21600 });
        if (data.refresh_token) await env.KV.put('kakao_refresh_token', data.refresh_token);
        await env.KV.put('kakao_notify_enabled', 'true');
        console.log('[카카오] 인증 완료 — access_token·refresh_token KV 저장 성공');
        return new Response(`
          <html><body style="font-family:sans-serif;padding:40px;text-align:center">
            <h2>✅ 카카오 인증 완료!</h2>
            <p>액세스 토큰과 리프레시 토큰이 저장되었습니다.</p>
            <p>이제 창을 닫으셔도 됩니다.</p>
          </body></html>
        `, { status: 200, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
      }

      // POST /kakao-setting
      if (url.pathname === '/kakao-setting') {
        if (request.method !== 'POST') return corsResponse({ error: 'POST만 허용' }, 405);
        const body = await request.json();

        if (body.action === 'save-token') {
          if (!body.token) return corsResponse({ error: 'token 필요' }, 400);
          await env.KV.put('kakao_token', body.token);
          if (body.refreshToken) await env.KV.put('kakao_refresh_token', body.refreshToken);
          if (body.clientSecret)  await env.KV.put('kakao_client_secret', body.clientSecret);
          return corsResponse({ ok: true, message: '카카오 토큰 저장 완료' });
        }
        if (body.action === 'set-notify') {
          await env.KV.put('kakao_notify_enabled', body.enabled ? 'true' : 'false');
          return corsResponse({ ok: true, enabled: body.enabled });
        }
        if (body.action === 'get-status') {
          const enabled = await env.KV.get('kakao_notify_enabled');
          const hasToken = !!(await env.KV.get('kakao_token'));
          return corsResponse({ enabled: enabled === 'true', hasToken });
        }
        return corsResponse({ error: '알 수 없는 action' }, 400);
      }

      // POST /order
      if (url.pathname === '/order') {
        if (request.method !== 'POST') return corsResponse({ error: 'POST만 허용' }, 405);
        const body = await request.json();
        if (!body.code) return corsResponse({ error: 'code 필요' }, 400);
        if (!['buy','sell'].includes(body.side)) return corsResponse({ error: 'side는 buy|sell' }, 400);
        if (!body.qty || body.qty < 1) return corsResponse({ error: 'qty는 1 이상' }, 400);
        const result = await placeMockOrder(body, env);
        return corsResponse(result);
      }

      // GET /balance
      if (url.pathname === '/balance') {
        const result = await getMockBalance(env);
        return corsResponse(result);
      }

      // GET /holdings-quotes
      if (url.pathname === '/holdings-quotes') {
        const cached = await env.TREND_TRACKER_KV.get('tf_holdings_quotes', 'json');
        if (!cached) return corsResponse({ error: '아직 저장된 종가 데이터가 없습니다. 다음 평일 오후 4시에 자동 업데이트됩니다.' }, 404);
        return corsResponse(cached);
      }

      // POST /save-holdings
      if (url.pathname === '/save-holdings' && request.method === 'POST') {
        const body = await request.json();
        const holdings = body.holdings;
        if (!Array.isArray(holdings)) return corsResponse({ error: 'holdings 배열 필요' }, 400);
        await env.TREND_TRACKER_KV.put('tf_holdings', JSON.stringify(holdings));
        return corsResponse({ ok: true, count: holdings.length });
      }

      // GET /quotes?codes=005930,035720
      if (url.pathname === '/quotes') {
        const codesParam = url.searchParams.get('codes') || '';
        const codes = codesParam.split(',').map(c => c.trim()).filter(Boolean);
        if (!codes.length) return corsResponse({ error: 'codes 파라미터 필요 (쉼표 구분)' }, 400);

        const results = await Promise.allSettled(
          codes.slice(0, 10).map(code => getPrice(code, env))
        );

        const kstNow = new Date(Date.now() + 9 * 60 * 60 * 1000);
        const fetchedAt   = kstNow.toISOString().slice(0, 10);
        const fetchedTime = kstNow.toISOString().slice(11, 16);

        const quotes = results.map((r, i) => {
          if (r.status === 'fulfilled') {
            return { code: codes[i], name: r.value.name, curr: r.value.curr, chg: r.value.chg };
          }
          return { code: codes[i], name: '', curr: 0, chg: 0, error: r.reason?.message };
        });

        return corsResponse({ quotes, fetchedAt, fetchedTime });
      }

      // GET /market-index
      if (url.pathname === '/market-index') {
        const data = await getMarketIndex(env);
        return corsResponse(data);
      }

      // GET /kospi-ma
      if (url.pathname === '/kospi-ma') {
        const data = await getKospiMA(env);
        return corsResponse(data);
      }

      // GET /market-investor
      if (url.pathname === '/market-investor') {
        const data = await getMarketInvestor(env);
        return corsResponse(data);
      }

      // GET /market-sector
      if (url.pathname === '/market-sector') {
        const data = await getMarketSector(env);
        return corsResponse(data);
      }

      // GET /blog-feed — 네이버 블로그 RSS (chcmg2022)
      if (url.pathname === '/blog-feed') {
        try {
          const data = await getBlogFeed();
          return new Response(JSON.stringify(data), {
            headers: { ...CORS, 'Cache-Control': 'max-age=300' },
          });
        } catch(e) {
          return corsResponse({ items: [], error: e.message });
        }
      }

      // GET /research-feed — 한국투자증권 리서치 리포트
      if (url.pathname === '/research-feed') {
        try {
          const data = await getResearchFeed(env);
          return new Response(JSON.stringify(data), {
            headers: { ...CORS, 'Cache-Control': 'max-age=600' },
          });
        } catch(e) {
          return corsResponse({ items: [], error: e.message });
        }
      }

      // GET /debug-home
      if (url.pathname === '/debug-home') {
        const token = await getToken(env);

        const safeJson = async (res, label) => {
          const status = res.status;
          const text = await res.text().catch(() => '(읽기 실패)');
          let json = null;
          try { json = JSON.parse(text); } catch(e) {}
          const outputArr = json?.output || json?.output1 || json?.output2 || [];
          const arr = Array.isArray(outputArr) ? outputArr : (outputArr ? [outputArr] : []);
          return {
            label, status,
            rt_cd: json?.rt_cd,
            msg1: json?.msg1,
            outputKeys: json ? Object.keys(json) : null,
            outputLength: arr.length,
            firstRowKeys: arr[0] ? Object.keys(arr[0]) : null,
            first3Rows: arr.slice(0, 3),
          };
        };

        const [
          invKospiRes, invKosdaqRes,
          sec0005Res, sec0013Res, sec1005Res, sec1025Res,
        ] = await Promise.all([
          fetch(`${KIS_BASE}/uapi/domestic-stock/v1/quotations/inquire-index-category-price?FID_COND_MRKT_DIV_CODE=U&FID_INPUT_ISCD=0001`, { headers: kisHeaders(token, 'FHPUP02100000', env) }),
          fetch(`${KIS_BASE}/uapi/domestic-stock/v1/quotations/inquire-index-category-price?FID_COND_MRKT_DIV_CODE=U&FID_INPUT_ISCD=1001`, { headers: kisHeaders(token, 'FHPUP02100000', env) }),
          fetch(`${KIS_BASE}/uapi/domestic-stock/v1/quotations/inquire-index-category-price?FID_COND_MRKT_DIV_CODE=U&FID_INPUT_ISCD=0005`, { headers: kisHeaders(token, 'FHPUP02100000', env) }),
          fetch(`${KIS_BASE}/uapi/domestic-stock/v1/quotations/inquire-index-category-price?FID_COND_MRKT_DIV_CODE=U&FID_INPUT_ISCD=0013`, { headers: kisHeaders(token, 'FHPUP02100000', env) }),
          fetch(`${KIS_BASE}/uapi/domestic-stock/v1/quotations/inquire-index-category-price?FID_COND_MRKT_DIV_CODE=U&FID_INPUT_ISCD=1005`, { headers: kisHeaders(token, 'FHPUP02100000', env) }),
          fetch(`${KIS_BASE}/uapi/domestic-stock/v1/quotations/inquire-index-category-price?FID_COND_MRKT_DIV_CODE=U&FID_INPUT_ISCD=1025`, { headers: kisHeaders(token, 'FHPUP02100000', env) }),
        ]);

        const results = await Promise.all([
          safeJson(invKospiRes,  '수급/코스피  FHPUP02100000 U 0001'),
          safeJson(invKosdaqRes, '수급/코스닥  FHPUP02100000 U 1001'),
          safeJson(sec0005Res,   '업종/음식료품 FHPUP02100000 U 0005'),
          safeJson(sec0013Res,   '업종/전기전자 FHPUP02100000 U 0013'),
          safeJson(sec1005Res,   '업종/코스닥음식료 FHPUP02100000 U 1005'),
          safeJson(sec1025Res,   '업종/소프트웨어 FHPUP02100000 U 1025'),
        ]);

        return corsResponse({ debug: results });
      }

      // GET /orders
      if (url.pathname === '/orders') {
        const account = env.KIS_MOCK_ACCOUNT || '';
        if (!account) return corsResponse({ error: '모의투자 계좌번호(KIS_MOCK_ACCOUNT)가 설정되지 않았습니다' }, 500);
        const token = await getMockToken(env);
        const mockKey = env.KIS_MOCK_APP_KEY || env.KIS_APP_KEY;
        const mockSec = env.KIS_MOCK_APP_SECRET || env.KIS_APP_SECRET;

        // 오늘 날짜를 YYYYMMDD 형식으로 (KST 기준)
        const kstToday = new Date(Date.now() + 9 * 60 * 60 * 1000).toISOString().slice(0, 10).replace(/-/g, '');
        const commonHeaders = {
          'Content-Type': 'application/json',
          'authorization': `Bearer ${token}`,
          'appkey': mockKey,
          'appsecret': mockSec,
          'custtype': 'P',
        };

        // 1) 미체결 주문 조회 (VTTC0802R)
        const unfilledUrl = `${MOCK_BASE}/uapi/domestic-stock/v1/trading/inquire-psbl-rvsecncl`
          + `?CANO=${account.slice(0,8)}&ACNT_PRDT_CD=01&CTX_AREA_FK100=&CTX_AREA_NK100=&INQR_DVSN_1=0&INQR_DVSN_2=0`;
        const [unfilledRes, ccldRes] = await Promise.allSettled([
          fetch(unfilledUrl, { headers: { ...commonHeaders, 'tr_id': 'VTTC0802R' } }),
          fetch(
            `${MOCK_BASE}/uapi/domestic-stock/v1/trading/inquire-daily-ccld`
            + `?CANO=${account.slice(0,8)}&ACNT_PRDT_CD=01&INQR_STRT_DT=${kstToday}&INQR_END_DT=${kstToday}&SLL_BUY_DVSN_CD=00&INQR_DVSN=01&PDNO=&CCLD_DVSN=00&ORD_GNO_BRNO=&ODNO=&INQR_DVSN_3=00&INQR_DVSN_1=&CTX_AREA_FK100=&CTX_AREA_NK100=`,
            { headers: { ...commonHeaders, 'tr_id': 'VTTC8001R' } }
          ),
        ]);

        // 미체결 파싱
        let unfilledOrders = [];
        if (unfilledRes.status === 'fulfilled' && unfilledRes.value.ok) {
          const d = await unfilledRes.value.json();
          if (d.rt_cd === '0') {
            unfilledOrders = (d.output1 || []).map(o => ({
              code: o.pdno,
              name: o.prdt_name,
              qty: parseInt(o.ord_qty) || 0,
              price: parseInt(o.ord_unpr) || 0,
              side: o.sll_buy_dvsn_cd === '01' ? 'sell' : 'buy',
              sideCode: o.sll_buy_dvsn_cd,
              status: '미체결',
              ordTime: o.ord_tmd || '',
              ordNo: o.odno || '',
            }));
          }
        }

        // 체결 내역 파싱
        let ccldOrders = [];
        if (ccldRes.status === 'fulfilled' && ccldRes.value.ok) {
          const d = await ccldRes.value.json();
          if (d.rt_cd === '0') {
            // 미체결 주문번호 set — 중복 제거용
            const unfilledNos = new Set(unfilledOrders.map(o => o.ordNo).filter(Boolean));
            ccldOrders = (d.output1 || [])
              .filter(o => !unfilledNos.has(o.odno))
              .map(o => ({
                code: o.pdno,
                name: o.prdt_name,
                qty: parseInt(o.ord_qty) || 0,
                price: parseInt(o.ord_unpr) || 0,
                side: o.sll_buy_dvsn_cd === '01' ? 'sell' : 'buy',
                sideCode: o.sll_buy_dvsn_cd,
                status: parseInt(o.tot_ccld_qty) > 0 ? '체결' : '취소',
                ordTime: o.ord_tmd || '',
                ordNo: o.odno || '',
              }));
          }
        }

        const orders = [...unfilledOrders, ...ccldOrders];
        return corsResponse({ ok: true, orders });
      }

      // GET /stock-detail?code=005930
      if (url.pathname === '/stock-detail') {
        const code = url.searchParams.get('code') || '';
        if (!code) return corsResponse({ error: 'code 파라미터 필요' }, 400);
        const data = await getStockDetail(code, env);
        return corsResponse(data);
      }

      return corsResponse({ error: '알 수 없는 경로' }, 404);

    } catch (err) {
      return corsResponse({ error: err.message || '서버 오류' }, 500);
    }
  },
};
