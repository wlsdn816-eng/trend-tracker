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
// Web Push / VAPID 유틸리티
// VAPID_PRIVATE_KEY, VAPID_PUBLIC_KEY 는 Worker Secret으로 설정
// wrangler secret put VAPID_PRIVATE_KEY
// wrangler secret put VAPID_PUBLIC_KEY
// ────────────────────────────────────────────────────────────

/** base64url → Uint8Array */
function b64uDecode(str) {
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = '='.repeat((4 - b64.length % 4) % 4);
  const raw = atob(b64 + pad);
  return Uint8Array.from(raw, c => c.charCodeAt(0));
}

/** Uint8Array → base64url */
function b64uEncode(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/** VAPID JWT 생성 */
async function makeVapidJwt(endpoint, privateKeyB64u, subject) {
  const url   = new URL(endpoint);
  const aud   = url.origin;
  const exp   = Math.floor(Date.now() / 1000) + 12 * 3600;
  const header  = b64uEncode(new TextEncoder().encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const payload = b64uEncode(new TextEncoder().encode(JSON.stringify({ aud, exp, sub: subject })));
  const data    = `${header}.${payload}`;

  const keyBytes = b64uDecode(privateKeyB64u);
  const key = await crypto.subtle.importKey(
    'pkcs8', keyBytes,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false, ['sign']
  );
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    new TextEncoder().encode(data)
  );
  return `${data}.${b64uEncode(sig)}`;
}

/**
 * Web Push 암호화 (RFC 8291 / aes128gcm)
 * 구독 정보의 p256dh(브라우저 공개키)와 auth(인증 비밀)를 사용해
 * ECDH 키 교환 → HKDF 키 도출 → AES-128-GCM 암호화
 */
async function encryptWebPush(subscription, plaintext) {
  const sub = typeof subscription === 'string' ? JSON.parse(subscription) : subscription;
  const p256dh = b64uDecode(sub.keys.p256dh);
  const auth   = b64uDecode(sub.keys.auth);

  // 1) 임시 EC 키쌍 생성 (발신자)
  const senderKeys = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']
  );
  const senderPubRaw = new Uint8Array(
    await crypto.subtle.exportKey('raw', senderKeys.publicKey)
  );

  // 2) 수신자(브라우저) 공개키 import
  const receiverPub = await crypto.subtle.importKey(
    'raw', p256dh, { name: 'ECDH', namedCurve: 'P-256' }, false, []
  );

  // 3) ECDH shared secret (32바이트)
  const sharedBits = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: 'ECDH', public: receiverPub }, senderKeys.privateKey, 256
    )
  );

  // 4) salt 16바이트 랜덤 생성
  const salt = crypto.getRandomValues(new Uint8Array(16));

  // 5) HKDF-SHA256 헬퍼
  async function hkdf(ikm, salt_, info, len) {
    const keyMat = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
    return new Uint8Array(await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: salt_, info }, keyMat, len * 8
    ));
  }

  // 6) PRK = HKDF-Extract(auth, sharedSecret)
  const prk = await hkdf(sharedBits, auth,
    concat(str('WebPush: info\x00'), p256dh, senderPubRaw), 32);

  // 7) CEK(16바이트)와 Nonce(12바이트) 도출
  //
  // info 문자열은 RFC 8188 §2.2에 고정돼 있다.
  //   CEK   : "Content-Encoding: aes128gcm" || 0x00
  //   Nonce : "Content-Encoding: nonce"     || 0x00
  //
  // 예전에는 'Content-Encryption-Key\x00\x01' / 'Nonce\x00\x01'을 썼는데
  // 이는 구버전 aesgcm 방식의 문자열이라 브라우저가 복호화에 실패하고
  // 푸시를 조용히 버린다(=알림이 안 뜬다). 중계 서버는 본문을 열어보지
  // 않으므로 전송은 201로 성공한 것처럼 보여서 원인을 찾기 어렵다.
  //
  // 끝의 \x01도 빼야 한다. HKDF-Expand가 카운터 바이트를 알아서 붙인다.
  const cek   = await hkdf(prk, salt, str('Content-Encoding: aes128gcm\x00'), 16);
  const nonce = await hkdf(prk, salt, str('Content-Encoding: nonce\x00'), 12);

  // 8) AES-128-GCM 암호화 (패딩: 평문 끝에 \x02 추가)
  const pt = concat(new TextEncoder().encode(
    typeof plaintext === 'string' ? plaintext : JSON.stringify(plaintext)
  ), new Uint8Array([2]));

  const aesKey = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128 }, aesKey, pt)
  );

  // 9) aes128gcm 레코드: salt(16) + rs(4) + keyidlen(1) + senderPub(65) + ciphertext
  const rs = new Uint8Array(4);
  new DataView(rs.buffer).setUint32(0, 4096, false);
  const header = concat(salt, rs, new Uint8Array([65]), senderPubRaw);
  return concat(header, ct);

  function str(s) { return new TextEncoder().encode(s); }
  function concat(...arrays) {
    const len = arrays.reduce((n, a) => n + a.length, 0);
    const out = new Uint8Array(len);
    let off = 0;
    for (const a of arrays) { out.set(a, off); off += a.length; }
    return out;
  }
}

/** FCM v1 API — 서비스 계정으로 OAuth2 액세스 토큰 발급 */
async function getFcmAccessToken(env) {
  if (!env.FIREBASE_SERVICE_ACCOUNT) throw new Error('FIREBASE_SERVICE_ACCOUNT 미설정');
  const sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);

  // JWT 생성 (RS256)
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const claim  = {
    iss: sa.client_email,
    scope: 'https://www.googleapis.com/auth/firebase.messaging',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600,
  };
  const enc = v => btoa(JSON.stringify(v)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
  const sigInput = `${enc(header)}.${enc(claim)}`;

  // PEM private key → CryptoKey
  const pem = sa.private_key.replace(/-----[^-]+-----/g,'').replace(/\s/g,'');
  const der = Uint8Array.from(atob(pem), c => c.charCodeAt(0));
  const key = await crypto.subtle.importKey(
    'pkcs8', der.buffer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false, ['sign']
  );
  const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', key, new TextEncoder().encode(sigInput));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
  const jwt = `${sigInput}.${sigB64}`;

  // 토큰 교환
  const res = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=${jwt}`,
  });
  if (!res.ok) throw new Error(`토큰 발급 실패 ${res.status}: ${await res.text()}`);
  const data = await res.json();
  return data.access_token;
}

/** FCM v1 API로 단일 구독자에게 푸시 발송 */
async function sendFcmV1Push(subscription, payload, env) {
  const sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);
  const token = await getFcmAccessToken(env);

  // Web Push subscription → FCM v1 메시지 형식
  const sub = typeof subscription === 'string' ? JSON.parse(subscription) : subscription;
  const msg = {
    message: {
      // FCM v1의 필드명은 webpush (언더바 없음). web_push로 보내면
      // "Unknown name web_push at 'message'" 400 오류가 난다.
      webpush: {
        notification: {
          title: payload.title || '📈 추세추종 매매 트래커',
          body:  payload.body  || '새 알림이 있어요.',
          icon:  'https://wlsdn816-eng.github.io/trend-tracker/icon-192.png',
        },
        fcm_options: {
          link: payload.url || 'https://wlsdn816-eng.github.io/trend-tracker/',
        },
        headers: { TTL: '86400' },
      },
      token: sub.fcmToken || sub._fcmToken,
    },
  };

  // fcmToken이 없으면 endpoint에서 추출 시도
  if (!msg.message.token) {
    const ep = sub.endpoint || '';
    const m = ep.match(/fcm\/send\/(.+)$/);
    if (m) msg.message.token = m[1];
    else throw new Error('FCM 토큰을 찾을 수 없습니다');
  }

  const res = await fetch(
    `https://fcm.googleapis.com/v1/projects/${sa.project_id}/messages:send`,
    {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type':  'application/json',
      },
      body: JSON.stringify(msg),
    }
  );
  if (!res.ok) {
    const txt = await res.text().catch(() => '');
    throw new Error(`FCM v1 실패 ${res.status}: ${txt}`);
  }
  return res.status;
}

/** 단일 구독자에게 Web Push 발송 (RFC 8291 암호화 적용) */
async function sendWebPush(subscription, payload, env) {
  const sub = typeof subscription === 'string' ? JSON.parse(subscription) : subscription;

  // 모든 브라우저(Chrome/FCM, Edge/WNS, Firefox, Safari)를 VAPID Web Push로 처리한다.
  //
  // 한때 FCM 주소는 FCM v1 API로 따로 보냈는데, 이는 잘못이었다.
  // 구독 주소 .../fcm/send/<ID>의 <ID>는 Web Push 구독 식별자이지
  // FCM v1이 요구하는 등록 토큰(Firebase SDK getToken()으로 받는 값)이 아니다.
  // 그대로 token에 넣으면 FCM이 404 NotRegistered로 거절한다.
  //
  // 2024년에 종료된 것은 서버키(Authorization: key=...) 방식이고,
  // VAPID 기반 Web Push는 FCM 주소에서도 그대로 동작한다.
  // → Firebase 서비스 계정 없이 표준 방식 하나로 통일.
  if (!env.VAPID_PRIVATE_KEY || !env.VAPID_PUBLIC_KEY) {
    throw new Error('VAPID 키가 설정되지 않았습니다');
  }
  const jwt = await makeVapidJwt(sub.endpoint, env.VAPID_PRIVATE_KEY, 'mailto:wlsdn816@gmail.com');
  const authHeader = `vapid t=${jwt},k=${env.VAPID_PUBLIC_KEY}`;

  // 실제 aes128gcm 암호화 적용
  const encrypted = await encryptWebPush(sub, payload);

  const res = await fetch(sub.endpoint, {
    method: 'POST',
    headers: {
      'Authorization':    authHeader,
      'Content-Type':     'application/octet-stream',
      'Content-Encoding': 'aes128gcm',
      'TTL':              '86400',
    },
    body: encrypted,
  });
  if (!res.ok && res.status !== 201) {
    const txt = await res.text().catch(() => '');
    throw new Error(`Push failed ${res.status}: ${txt}`);
  }
  return res.status;
}

/** KV에 저장된 모든 구독자에게 푸시 발송 */
async function broadcastPush(payload, env) {
  const list = await env.KV.list({ prefix: 'push_sub:' });
  const results = [];
  for (const key of list.keys) {
    try {
      const sub = await env.KV.get(key.name, 'json');
      if (!sub) continue;
      const status = await sendWebPush(sub, payload, env);
      results.push({ key: key.name, ok: true, status });
    } catch(e) {
      results.push({ key: key.name, ok: false, error: e.message });
      // 만료·해지된 구독은 삭제한다. 그대로 두면 매번 실패 로그만 쌓인다.
      //   410 Gone            — Web Push 표준 (구독 만료)
      //   404 NotRegistered   — FCM (앱 삭제·데이터 초기화된 기기)
      //   UNREGISTERED        — FCM v1 errorCode
      const msg = e.message || '';
      const isGone = msg.includes('410')
        || msg.includes('UNREGISTERED')
        || msg.includes('NotRegistered');
      if (isGone) {
        await env.KV.delete(key.name).catch(() => {});
        console.log(`[푸시] 만료된 구독 삭제: ${key.name}`);
      }
    }
  }
  return results;
}

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

  // 일봉 + 주봉 + 월봉을 병렬로 조회
  //
  // 주봉이 필요한 이유: 이 API는 일봉을 100개까지만 준다.
  // 그래서 150일선·200일선을 일봉으로 만들면 둘 다 "있는 데이터 전부의 평균"이
  // 되어 값이 같아지고, 150일선 > 200일선 조건이 영원히 거짓이 된다.
  // 52주 고점·저점도 실제로는 100일 범위가 된다.
  // → 장기 지표는 주봉에서 뽑는다 (100주 ≈ 2년치).
  const period = (div) =>
    `${KIS_BASE}/uapi/domestic-stock/v1/quotations/inquire-daily-price`
    + `?FID_COND_MRKT_DIV_CODE=J&FID_INPUT_ISCD=${code}`
    + `&FID_PERIOD_DIV_CODE=${div}&FID_ORG_ADJ_PRC=0`
    + `&FID_INPUT_DATE_1=20200101&FID_INPUT_DATE_2=${today}`;

  // 호출은 종목당 2회로 묶는다. 3회로 늘렸더니 KIS 쪽에서 막혀
  // 수집률이 80% → 51%로 떨어졌다(2,596종목 중 1,332개만 성공).
  // 월봉은 10개월선 하나 때문에 불렀던 것이라 주봉 43개로 대신한다.
  const [dailyRes, weeklyRes] = await Promise.all([
    fetch(period('D'), { headers: kisHeaders(token, 'FHKST03010100', env) }),
    fetch(period('W'), { headers: kisHeaders(token, 'FHKST03010100', env) }),
  ]);

  // 실패를 두 종류로 나눈다.
  //   RETRY — HTTP 단계 실패(호출 제한·일시 장애). 다시 부르면 될 수 있다.
  //   SKIP  — KIS가 정상 응답하면서 "데이터 없음"이라 한 경우.
  //           상장폐지·신규상장·거래정지 등이라 몇 번을 불러도 같다.
  // 구분하지 않으면 재시도를 헛돌리고, 실패 집계도 원인을 알 수 없다.
  if (!dailyRes.ok) {
    const e = new Error(`HTTP ${dailyRes.status}`); e.kind = 'RETRY'; throw e;
  }
  const dailyData = await dailyRes.json();
  if (dailyData.rt_cd !== '0') {
    const e = new Error(dailyData.msg1 || 'OHLCV 조회 실패'); e.kind = 'SKIP'; throw e;
  }

  // output2가 일봉 배열 (최신순)
  const rows = (dailyData.output2 || []).map(r => ({
    date:   r.stck_bsop_date,
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
  const prevClose = closes[1] || 0; // 전일 종가 (돌파 판정용)

  // 최근 20일 고가 (오늘 포함) — 장 마감 후 스캔이므로 오늘 종가 기준 정상
  const high20 = highs.length > 0 ? Math.max(...highs.slice(0, 20)) : 0;
  const low10  = Math.min(...lows.slice(0, 10));
  const avgVol = Math.round(vols.slice(0, 20).reduce((a,b)=>a+b,0) / Math.min(20, vols.length));
  const todayVol = vols[0] || 0;

  // 20일 평균 거래대금 — 거래량 배수만 보면 분모가 작은 종목이 유리해진다.
  // 하루 몇천만원 도는 종목은 신호가 맞아도 사고팔 수가 없다.
  const turnN = Math.min(20, rows.length);
  const avgTurnover = turnN > 0
    ? Math.round(rows.slice(0, turnN).reduce((a, r) => a + r.close * r.vol, 0) / turnN)
    : 0;

  // 당일 종가 위치 (0~100). 같은 양봉이라도 고가에 마감한 것과
  // 위꼬리 달고 밀린 것은 다르다. 후자는 돌파가 매도에 눌린 것.
  const dayRange = (highs[0] ?? 0) - (lows[0] ?? 0);
  const closePos = dayRange > 0
    ? Math.round(((curr - lows[0]) / dayRange) * 100)
    : 50;   // 상한가 등으로 고가=저가면 판단 보류

  // 변동성 수축(VCP) — 최근 5일 평균 일중변동폭 / 그 직전 20일 평균.
  // 1보다 작을수록 조여진 상태. 미너비니는 돌파 전 수축을 핵심으로 본다.
  const rangePct = (i) => {
    const c = closes[i];
    return c > 0 ? ((highs[i] - lows[i]) / c) * 100 : 0;
  };
  const meanRange = (from, n) => {
    const idx = [];
    for (let i = from; i < from + n && i < rows.length; i++) idx.push(i);
    if (idx.length < n * 0.8) return 0;
    return idx.reduce((a, i) => a + rangePct(i), 0) / idx.length;
  };
  const recentRange = meanRange(0, 5);
  const priorRange  = meanRange(5, 20);
  const vcpRatio = (recentRange > 0 && priorRange > 0)
    ? Math.round((recentRange / priorRange) * 100) / 100
    : 0;   // 0 = 계산 불가

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

  // 이동평균 헬퍼 — 배열은 최신순이므로 slice(from, from+n)이 "from칸 전부터 n칸".
  // 요구 길이의 90%는 있어야 유효한 값으로 본다. 모자라면 0을 돌려
  // 상장 초기 종목이 엉뚱한 평균으로 관문을 통과하지 않게 한다.
  const smaOf = (arr, from, n) => {
    const seg = arr.slice(from, from + n);
    if (seg.length < n * 0.9) return 0;
    return seg.reduce((a, b) => a + b, 0) / seg.length;
  };

  // 50일선은 일봉 100개 안에 들어오므로 일봉으로 계산
  const ma50 = smaOf(closes, 0, 50);

  // ── 주봉 기반 장기 지표 ──
  let ma150 = 0, ma200 = 0, ma200Prev = 0, high52 = 0, low52 = 0, ma10m = 0;
  try {
    if (weeklyRes.ok) {
      const wData = await weeklyRes.json();
      if (wData.rt_cd === '0') {
        const wRows = (wData.output2 || [])
          .map(r => ({
            close: parseInt(r.stck_clpr) || 0,
            high:  parseInt(r.stck_hgpr) || 0,
            low:   parseInt(r.stck_lwpr) || 0,
          }))
          .filter(r => r.close > 0);

        const wCloses = wRows.map(r => r.close);
        // 1주 ≈ 5거래일 → 150일선 ≈ 30주선, 200일선 ≈ 40주선
        ma150 = smaOf(wCloses, 0, 30);
        ma200 = smaOf(wCloses, 0, 40);
        // 200일선 추세 판정용 — 약 한 달(4주) 전 시점
        ma200Prev = smaOf(wCloses, 4, 40);
        // 월봉 10선(10개월 이동평균) ≈ 43주선
        ma10m = Math.round(smaOf(wCloses, 0, 43));

        // 진짜 52주 고가·저가 (주봉 52개)
        const w52 = wRows.slice(0, 52);
        if (w52.length >= 30) {
          high52 = Math.max(...w52.map(r => r.high));
          low52  = Math.min(...w52.map(r => r.low));
        }
      }
    }
  } catch(e) {
    console.warn(`[주봉] ${code} 처리 실패:`, e.message);
  }

  // 주봉을 못 받았을 때의 차선책 — 일봉 범위로라도 52주 고저를 채운다
  if (high52 === 0 && highs.length > 0) high52 = Math.max(...highs);
  if (low52  === 0 && lows.length  > 0) low52  = Math.min(...lows);

  // RS (상대강도): 최근 3개월(약 63거래일) 수익률
  const close63ago = closes[Math.min(62, closes.length - 1)] || curr;
  const rs3m = close63ago > 0 ? ((curr - close63ago) / close63ago) * 100 : 0;

  const latestDate = rows[0]?.date || '';
  const haltedVol = vols.slice(0, 3).every(v => v === 0);
  const haltedPrice = rows.slice(0, 3).every(r => r.high === r.low && r.high === r.close && r.close > 0);
  const isHalted = haltedVol || haltedPrice;
  return { code, curr, prevClose, high20, low10, avgVol, todayVol, atr, high52, low52,
           avgTurnover, closePos, vcpRatio,
           ma50, ma150, ma200, ma200Prev, rs3m, ma10m, rows, latestDate, isHalted };
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
  let failed = 0;
  for (const { url, tailLen } of MASTER_URLS) {
    try {
      const res = await fetch(url);
      if (!res.ok) { failed++; continue; }

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
      failed++;
      console.error('마스터파일 로드 실패:', url, e.message);
    }
  }

  // 코스피/코스닥 중 한쪽만 로드되면 종목 목록이 통째로 달라져서
  // 청크 오프셋이 어긋난다 → 같은 종목이 두 번 스캔되거나 일부가 누락됨.
  // 그래서 반쪽짜리 목록은 절대 채택하지 않는다.
  if (failed > 0) {
    // 이미 목록을 들고 있으면 그대로 쓴다
    if (masterDB.length > 0) {
      console.error(`[마스터DB] ${failed}개 시장 로드 실패 — 기존 목록 유지 (${masterDB.length}개)`);
      return;
    }
    // 목록이 없는 새 인스턴스라면 KV 캐시에서 되살린다.
    // 캐시는 직전에 양쪽 다 성공했을 때 저장된 완전한 목록이라 안전하다.
    try {
      const cached = env && env.KV ? await env.KV.get('master_db_cache') : null;
      if (cached) {
        masterDB = JSON.parse(cached);
        masterLoadedAt = now;
        console.error(`[마스터DB] ${failed}개 시장 로드 실패 — KV 캐시로 복원 (${masterDB.length}개)`);
        return;
      }
    } catch (e) {
      console.error('[마스터DB] KV 캐시 복원 실패:', e.message);
    }
    console.error(`[마스터DB] ${failed}개 시장 로드 실패 — 복원할 캐시도 없음`);
    return;
  }

  if (all.length > 0) {
    // 스팩(SPAC), 리츠 등 노이즈 종목 제거
    const EXCLUDE_KEYWORDS = ['스팩', 'SPAC', '스팩주'];
    const filtered = all.filter(({ name }) =>
      !EXCLUDE_KEYWORDS.some(kw => name.includes(kw))
    );

    // 종목코드 기준 중복 제거 + 코드순 정렬.
    // 정렬이 핵심 — 신규 로드든 KV 캐시 복원이든 순서가 같아야
    // 청크마다 다른 isolate가 처리해도 오프셋이 일치한다.
    const byCode = new Map();
    for (const item of filtered) byCode.set(item.code, item);
    masterDB = [...byCode.values()].sort((a, b) => a.code.localeCompare(b.code));

    const dupCount = filtered.length - masterDB.length;
    if (dupCount > 0) console.log(`[마스터DB] 중복 종목 ${dupCount}개 제거`);
    masterLoadedAt = now;

    // KV에 masterDB 캐싱 (검색용 — TTL 25시간)
    try {
      if (env && env.KV) {
        // TTL은 MASTER_TTL(24시간)과 맞춘다 — 캐시가 더 오래 살아남으면
        // 어떤 isolate는 어제 목록, 어떤 isolate는 오늘 목록을 쓰게 되어 오프셋이 어긋난다.
        await env.KV.put('master_db_cache', JSON.stringify(masterDB), { expirationTtl: 24 * 60 * 60 });
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
// RS 레이팅 기준선 — 시장 상위 20%
const RS_RATING_MIN = 80;

// 20일 평균 거래대금 하한 (원).
// 신호가 맞아도 사고팔 수 없는 종목을 걸러낸다.
// 3억이면 500만원어치 매매가 하루 거래의 1.7% 수준이라 호가를 밀지 않는다.
// 더 큰 금액을 운용하면 이 값을 올리면 된다.
const MIN_TURNOVER = 300_000_000;

/**
 * 미너비니 추세 템플릿 — "지금 상승 추세인가"를 판정하는 관문.
 * 여기를 통과하지 못하면 신고가가 터지든 거래량이 터지든 후보가 아니다.
 * (RS 레이팅은 전 종목 백분위라 sendFinal 단계에서 따로 적용한다)
 */
function calcTrendTemplate(data) {
  const { curr, ma50, ma150, ma200, ma200Prev, high52, low52, avgTurnover } = data;
  const haveMa = curr > 0 && ma50 > 0 && ma150 > 0 && ma200 > 0;

  // 1) 정배열: 현재가 > 50일선 > 150일선 > 200일선
  const t_stack    = haveMa && curr > ma50 && ma50 > ma150 && ma150 > ma200;
  // 2) 200일선이 한 달 전보다 위 — 장기 추세가 살아있는가
  const t_ma200Up  = ma200 > 0 && ma200Prev > 0 && ma200 > ma200Prev;
  // 3) 52주 저점 대비 +30% 이상 — 바닥에서 충분히 올라왔는가
  const t_offLow   = low52 > 0 && curr >= low52 * 1.30;
  // 4) 52주 고점 대비 -25% 이내 — 고점에서 크게 밀리지 않았는가
  const t_nearHigh = high52 > 0 && curr >= high52 * 0.75;
  // 5) 유동성 — 살 수 있고 팔 수 있는 종목인가
  const t_liquid   = (avgTurnover ?? 0) >= MIN_TURNOVER;

  const pass = t_stack && t_ma200Up && t_offLow && t_nearHigh && t_liquid;
  return { pass, t_stack, t_ma200Up, t_offLow, t_nearHigh, t_liquid };
}

function calcSignalFlags(data, kospiRs3m = 0) {
  // ── 방아쇠: 관문을 통과한 종목이 "지금 움직이는가" ──
  const flag_high20  = data.curr > 0 && data.high20 > 0 && data.curr >= data.high20 * 0.98; // 20일 신고가 2% 이내 근접 포함
  const flag_vol     = data.todayVol > 0 && data.avgVol > 0 && data.todayVol >= data.avgVol * 2.0;

  // ── 참고 지표 ──
  const flag_near52w = data.high52 > 0 && data.curr >= data.high52 * 0.90; // -10% 이내
  // RS: 청크 단계의 임시 판정 (sendFinal에서 전 종목 기준 RS 레이팅으로 교체)
  const flag_rs      = data.rs3m > 0 && data.rs3m > kospiRs3m;

  const trend = calcTrendTemplate(data);

  const reasons = [];
  if (flag_high20)  reasons.push('20일 신고가 돌파');
  if (flag_vol)     reasons.push('거래량 2배');
  if (flag_near52w) reasons.push('52주 고점 -10% 이내');

  // 방아쇠 개수가 점수 (0~2). 정렬·표시에 쓴다.
  const score = [flag_high20, flag_vol].filter(Boolean).length;

  // 결과에 포함할지: 추세 관문을 통과한 종목만.
  // 방아쇠가 아직 없어도 '관찰 목록'으로 쓰므로 포함한다.
  const anySignal = trend.pass;

  return {
    score, reasons, anySignal,
    trend,
    flags: { high20: flag_high20, vol: flag_vol, near52w: flag_near52w, rs: flag_rs },
  };
}

// ────────────────────────────────────────────────────────────
// IBD RS 레이팅: rs3m 백분위 (0~99). 레이팅 80 = 시장 상위 20%
//
// 모집단은 반드시 "스캔한 전 종목"이어야 한다. 예전에는 1차 통과
// 종목들끼리만 순위를 매겨서, 이미 강한 종목들 사이의 상대 순위가
// 나왔다. 그러면 '상위 20%'가 시장 기준 상위 20%를 뜻하지 않는다.
// ────────────────────────────────────────────────────────────
function calcRsRatings(results, marketRs3m) {
  // marketRs3m: 스캔한 모든 종목의 rs3m 배열 (관문 탈락 종목 포함)
  const pool = (Array.isArray(marketRs3m) && marketRs3m.length > 0)
    ? marketRs3m
    : results.map(r => r.rs3m);          // 전 종목 데이터가 없으면 차선책
  const sorted = [...pool].sort((a, b) => a - b);
  const n = sorted.length;
  if (n === 0) return;

  // 이진 탐색으로 "자신보다 낮은 값의 개수" — 전 종목(수천 개) 기준이라
  // 선형 탐색이면 O(결과수 × 전종목수)로 느려진다.
  const countBelow = (v) => {
    let lo = 0, hi = n;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (sorted[mid] < v) lo = mid + 1; else hi = mid;
    }
    return lo;
  };

  results.forEach(r => {
    r.rsRating = Math.min(99, Math.floor((countBelow(r.rs3m) / n) * 100));
  });
}

// ────────────────────────────────────────────────────────────
// sendFinal에서 RS 레이팅 적용 — 기준 미달은 후보에서 제외
// ────────────────────────────────────────────────────────────
function applyRsRatingCondition(allResults, marketRs3m) {
  calcRsRatings(allResults, marketRs3m);

  allResults.forEach(r => {
    r.flags = r.flags || {};
    r.flags.rs = (r.rsRating ?? 0) >= RS_RATING_MIN;

    r.reasons = (r.reasons || []).filter(s => !s.startsWith('RS 강세') && !s.startsWith('RS 레이팅'));
    if (r.flags.rs) r.reasons.push(`RS 레이팅 ${r.rsRating} (상위 ${100 - r.rsRating}%)`);
  });

  // 추세 관문의 마지막 항목 = RS 레이팅. 미달이면 추세주로 보지 않는다.
  return allResults.filter(r => r.flags.rs);
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
  if (data.error === 'invalid_grant') {
    // refresh token 만료 — KV에서 삭제하지 않음 (삭제하면 다음 요청도 복구 불가)
    // 대신 에러 로그만 남기고 재인증은 사용자가 /kakao-auth로 수동 진행
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

  const gate = basic.gatePassed ?? 0;
  const watchCount = Math.max(0, gate - (basic.hits ?? 0));

  let msg = `📈 ${today} 자동선별 스캔 결과\n`
          + `추세 관문 통과 ${gate}종목 → 매수 후보 ${basic.hits}종목 (엄격 ${strict.hits}) · 관찰 ${watchCount}종목\n\n`;

  if (gate === 0) {
    msg += `오늘은 추세 관문을 통과한 종목이 없습니다.\n`
         + `시장이 약할 때는 정상적인 결과예요.`;
  } else {
    if (strict.hits > 0) {
      msg += `🎯 [엄격 ${strict.hits}종목] 신고가 + 거래량 동시\n`;
      strict.results.slice(0, 5).forEach(r => {
        msg += `${r.name} (${r.code}) · RS ${r.rsRating ?? '-'}\n`;
        r.reasons.forEach(reason => { msg += ` ✅ ${reason}\n`; });
        msg += `\n`;
      });
    } else {
      msg += `🎯 [엄격] 신호 없음\n\n`;
    }

    const strictCodes = new Set((strict.results || []).map(r => r.code));
    const basicOnly = (basic.results || []).filter(r => !strictCodes.has(r.code));
    if (basicOnly.length > 0) {
      msg += `📊 [기본 추가 ${basicOnly.length}종목]\n`;
      basicOnly.slice(0, 5).forEach(r => {
        msg += `${r.name} (${r.code}) · RS ${r.rsRating ?? '-'}\n`;
        r.reasons.forEach(reason => { msg += ` ✅ ${reason}\n`; });
        msg += `\n`;
      });
    } else if (strict.hits === 0) {
      msg += `📊 [기본] 신호 없음\n`;
      if (watchCount > 0) msg += `추세는 좋은데 방아쇠를 기다리는 종목 ${watchCount}개는 앱의 관찰 목록에서 확인하세요.`;
    }
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
// GitHub Actions 스캔 워크플로 직접 호출 (Cloudflare Cron → GitHub)
// 필요: Worker Secret GITHUB_TOKEN (이 저장소 Actions: Read and write)
// ────────────────────────────────────────────────────────────
async function dispatchScanWorkflow(env, cron) {
  const rec = { at: new Date().toISOString(), cron, ok: false, status: 0, note: '' };
  try {
    if (!env.GITHUB_TOKEN) {
      rec.note = 'GITHUB_TOKEN 미설정';
    } else {
      const res = await fetch(
        'https://api.github.com/repos/wlsdn816-eng/trend-tracker/actions/workflows/daily-scan.yml/dispatches',
        {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${env.GITHUB_TOKEN}`,
            'Accept': 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
            'User-Agent': 'kis-proxy-worker',
            'Content-Type': 'application/json',
          },
          // source=cloudflare → 워크플로가 중복(이미 스캔함)·휴장일 확인을 거친다. (수동 실행은 무조건 스캔)
          body: JSON.stringify({ ref: 'main', inputs: { source: 'cloudflare' } }),
        }
      );
      rec.status = res.status;
      rec.ok = res.status === 204;
      if (!rec.ok) rec.note = (await res.text()).slice(0, 200);
    }
  } catch (e) {
    rec.note = String(e.message || e).slice(0, 200);
  }
  console.log('[스캔 깨우기]', JSON.stringify(rec));
  try { await env.KV.put('last_scan_dispatch', JSON.stringify(rec), { expirationTtl: 7 * 86400 }); } catch (_) {}
  return rec;
}

// ────────────────────────────────────────────────────────────
// 메인 핸들러
// ────────────────────────────────────────────────────────────
export default {
  // Cron Trigger — 매일 오후 4시 (KST = UTC 07:00)
  // ※ 자동선별 스캔 + 카카오 알림은 GitHub Actions(/scan-chunk + sendFinal)에서 담당
  async scheduled(event, env, ctx) {
    ctx.waitUntil((async () => {
      // 0) 평일이면 GitHub 스캔 워크플로를 직접 깨운다.
      //    GitHub의 예약 실행은 지연되거나 통째로 건너뛰는 날이 있어서(11/12, 11/17, 11/18 실측),
      //    시각이 정확한 Cloudflare Cron이 GitHub에 "지금 시작해"라고 요청한다.
      //    07:00에 한 번, 07:30에 한 번 더 — 이미 그날 스캔이 끝났으면 워크플로가 스스로 종료한다.
      {
        const kstDow = new Date(Date.now() + 9 * 60 * 60 * 1000).getUTCDay(); // 0=일
        // event.cron이 있을 때만 = 진짜 예약 실행. /run-cron 수동 호출로는 스캔을 깨우지 않는다.
        if (event?.cron && kstDow >= 1 && kstDow <= 5) {
          await dispatchScanWorkflow(env, event.cron);
        }
      }
      // 이 아래(보유종목 종가·푸시)는 하루 한 번(07:00 Cron)만
      if (event?.cron === '30 7 * * 1-5') return;

      // 1) 보유 포지션 종가 스냅샷 KV에 저장
      try {
        const holdingsRaw = await env.KV.get('tf_holdings');
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
            await env.KV.put(
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

      // 4) 웹 푸시 알림 발송 (VAPID 설정된 경우)
      if (env.VAPID_PRIVATE_KEY && env.VAPID_PUBLIC_KEY) {
        try {
          const kstNow  = new Date(Date.now() + 9 * 60 * 60 * 1000);
          const dateStr = `${kstNow.getMonth() + 1}/${kstNow.getDate()}`;
          const payload = {
            title: '📊 보유종목 종가 업데이트',
            body:  `${dateStr} 보유종목 종가가 저장됐어요. (자동 스크리너 결과는 별도 알림으로 와요)`,
            url:   'https://wlsdn816-eng.github.io/trend-tracker/',
          };
          const results = await broadcastPush(payload, env);
          console.log('웹 푸시 발송 결과:', JSON.stringify(results));
        } catch(e) {
          console.error('웹 푸시 발송 실패:', e);
        }
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

        // 3순위: KV 캐시도 없으면 masterDB 직접 로드 (await — 이번 요청에서 바로 검색)
        // KIS API fallback은 타임아웃이 잦아 제거함
        try {
          console.log('[검색] KV 캐시 없음 — masterDB 직접 로드 시작');
          await loadMasterDB(env);
          if (masterDB.length > 0) {
            console.log(`[검색] masterDB 로드 완료: ${masterDB.length}개`);
            return corsResponse({ results: searchStocks(q), total: masterDB.length });
          }
        } catch (e) {
          console.error('[검색] masterDB 로드 실패:', e.message);
        }

        // 모두 실패 시: 빈 결과 반환
        return corsResponse({ results: [], error: '종목 DB 로드 실패 — 잠시 후 다시 검색해주세요' });
      }

      // GET /master-reload
      if (url.pathname === '/master-reload') {
        masterLoadedAt = 0;
        await loadMasterDB(env);
        return corsResponse({ ok: true, total: masterDB.length });
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
        // 수동 스크리너용: withRs=1이면 자동 스크리너와 같은 추세 관문·RS 레이팅을 함께 계산해 준다.
        // (휴장일 확인 등 다른 호출은 KV를 읽지 않도록 옵션으로만 켠다)
        if (url.searchParams.get('withRs') === '1') {
          const trend = calcTrendTemplate(data);
          let rsRating = null, rsPoolAt = null;
          try {
            const pool = await env.KV.get('market_rs3m', 'json');
            if (pool && Array.isArray(pool.values) && pool.values.length > 0) {
              const v = pool.values;                 // 오름차순 정렬 저장
              let lo = 0, hi = v.length;
              while (lo < hi) { const mid = (lo + hi) >> 1; if (v[mid] < data.rs3m) lo = mid + 1; else hi = mid; }
              rsRating = Math.min(99, Math.floor((lo / v.length) * 100));
              rsPoolAt = pool.scannedAt || null;
            }
          } catch(e) { console.error('RS 모집단 읽기 실패:', e.message); }
          return corsResponse({
            ...data,
            ma50: Math.round(data.ma50), ma150: Math.round(data.ma150), ma200: Math.round(data.ma200),
            trend, rsRating, rsPoolAt, rsMin: RS_RATING_MIN,
          });
        }
        return corsResponse(data);
      }

      // GET /scan-result?mode=basic|strict|watch
      if (url.pathname === '/scan-result') {
        const mode = url.searchParams.get('mode') || 'basic';
        const key = mode === 'strict' ? 'scan_result_strict'
                  : mode === 'watch'  ? 'scan_result_watch'
                  : 'scan_result_basic';
        const raw = await env.KV.get(key);
        if (!raw) return corsResponse({ error: '스캔 결과 없음. GitHub Actions 스캔을 먼저 실행하세요.' }, 404);
        return corsResponse(JSON.parse(raw));
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

          // 종목코드 기준 중복 제거 (안전망).
          // masterDB 쪽을 고쳤지만, 청크마다 다른 isolate가 처리하는 구조라
          // 목록이 어긋나면 같은 종목이 두 번 들어올 수 있다.
          // 같은 종목이 여러 번 왔다면 가장 늦게 조회된(= 종가에 가까운) 것을 남긴다.
          {
            const byCode = new Map();
            for (const r of allResults) byCode.set(r.code, r);
            const dupCount = allResults.length - byCode.size;
            if (dupCount > 0) console.warn(`[스캔결과] 중복 종목 ${dupCount}개 제거`);
            allResults = [...byCode.values()];
          }

          // RS 레이팅을 시장 전체(관문 탈락 종목 포함) 기준으로 매기고,
          // 기준 미달은 여기서 탈락시킨다 = 추세 관문의 마지막 항목.
          const marketRs3m = Array.isArray(body.marketRs3m) ? body.marketRs3m : [];
          const gatePassed = applyRsRatingCondition(allResults, marketRs3m);

          // 방아쇠 개수 → RS 레이팅 순으로 정렬
          gatePassed.sort((a, b) => (b.score - a.score) || ((b.rsRating ?? 0) - (a.rsRating ?? 0)));

          // 관문을 통과한 종목을 방아쇠 유무로 나눈다.
          //   엄격 — 신고가와 거래량이 둘 다 터짐
          //   기본 — 둘 중 하나 이상
          //   관찰 — 추세는 좋은데 아직 방아쇠가 없음
          const strictResults = gatePassed.filter(r => r.flags?.high20 && r.flags?.vol);
          const basicResults  = gatePassed.filter(r => r.flags?.high20 || r.flags?.vol);
          const watchResults  = gatePassed.filter(r => !r.flags?.high20 && !r.flags?.vol);

          const meta = {
            scannedAt, total,
            kospiRs3m: Math.round(kospiRs3m * 10) / 10,
            rsRatingMin: RS_RATING_MIN,
            gatePassed: gatePassed.length,   // 추세 관문 통과 종목 수 (0이어도 정상 — 하락장)
          };
          const basicData  = { ...meta, hits: basicResults.length,  results: basicResults.slice(0,200) };
          const strictData = { ...meta, hits: strictResults.length, results: strictResults.slice(0,200) };
          const watchData  = { ...meta, hits: watchResults.length,  results: watchResults.slice(0,200) };

          // KV 저장 실패해도 카카오 알림은 반드시 전송
          let kvSaved = false;
          try {
            await env.KV.put('scan_result_basic',  JSON.stringify(basicData),  { expirationTtl: 86400 });
            await env.KV.put('scan_result_strict', JSON.stringify(strictData), { expirationTtl: 86400 });
            await env.KV.put('scan_result_watch',  JSON.stringify(watchData),  { expirationTtl: 86400 });
            // 수동 스크리너가 같은 기준으로 RS 레이팅을 매길 수 있도록 시장 전체 rs3m 분포를 남긴다
            if (marketRs3m.length > 0) {
              const values = marketRs3m.filter(x => Number.isFinite(x)).sort((a, b) => a - b);
              await env.KV.put('market_rs3m', JSON.stringify({ scannedAt, values }), { expirationTtl: 7 * 86400 });
            }
            kvSaved = true;
          } catch(e) {
            console.error('KV 저장 실패 (무시하고 카카오 전송 진행):', e.message);
          }
          if (sendKakao) await sendKakaoScanAlert(env, basicData, strictData);

          // 웹 푸시 알림 — KV에 등록된 모든 구독자에게 발송
          let pushResults = [];
          try {
            const pushMsg = {
              title: '📈 자동 스크리너 완료',
              body: basicResults.length > 0
                ? `매수 후보 ${basicResults.length}종목 (엄격 ${strictResults.length}) · 관찰 ${watchResults.length}종목`
                : `오늘은 매수 후보 없음 · 추세 통과 ${gatePassed.length}종목은 관찰 목록에`,
              url: '/trend-tracker/#screener'
            };
            pushResults = await broadcastPush(pushMsg, env);
          } catch(e) {
            console.error('웹 푸시 발송 실패:', e.message);
          }

          return corsResponse({ ok: true, saved: kvSaved, basicHits: basicResults.length, strictHits: strictResults.length, watchHits: watchResults.length, gatePassed: gatePassed.length, total, scannedAt, pushSent: pushResults.length });
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
        // RS 레이팅을 시장 전체 기준으로 내려면 관문 탈락 종목의 rs3m도 필요하다.
        // 종목 정보는 빼고 숫자만 모아 보낸다 (전 종목이라도 수십 KB).
        const chunkRs = [];

        const scanOne = async ({ code, name }) => {
          const data = await getOHLCV(code, env);          // 실패 시 throw → 재시도 대상
          if (!data.curr || data.isHalted) return null;    // 거래정지 — 조용히 제외
          const rs3m = Math.round(data.rs3m * 10) / 10;
          const { score, reasons, anySignal, flags, trend } = calcSignalFlags(data, kospiRs3m);
          if (!anySignal) return { _rsOnly: true, rs3m };  // 관문 탈락 — RS 모집단에만 기여
          return {
            code, name, score, reasons, flags, trend,
            curr: data.curr, high20: data.high20, high52: data.high52, low52: data.low52,
            avgVol: data.avgVol, todayVol: data.todayVol, atr: data.atr, low10: data.low10,
            avgTurnover: data.avgTurnover, closePos: data.closePos, vcpRatio: data.vcpRatio,
            rs3m,
            ma50: Math.round(data.ma50), ma150: Math.round(data.ma150), ma200: Math.round(data.ma200),
          };
        };

        const collect = (r) => {
          if (r.status !== 'fulfilled' || !r.value) return;
          chunkRs.push(r.value.rs3m);
          if (!r.value._rsOnly) chunkResults.push(r.value);
        };

        // KIS 호출 제한은 대략 초당 20건. 종목당 2호출이므로
        // 5종목(=10건)을 보내고 500ms 쉬면 초당 20건에 맞는다.
        // 예전에는 200ms라 초당 50건을 쏴서 20% 가까이 거절당했다.
        const BATCH = 5;
        const GAP   = 500;

        let skipped = 0;   // 데이터 자체가 없는 종목 (재시도 무의미)

        const runPass = async (list, gap) => {
          const retryItems = [];
          for (let i = 0; i < list.length; i += BATCH) {
            const mini = list.slice(i, i + BATCH);
            const results = await Promise.allSettled(mini.map(scanOne));
            results.forEach((r, idx) => {
              if (r.status !== 'rejected') { collect(r); return; }
              if (r.reason?.kind === 'SKIP') skipped++;      // 다시 불러도 같다
              else retryItems.push(mini[idx]);               // 호출 제한 등 — 재시도
            });
            if (i + BATCH < list.length) await new Promise(res => setTimeout(res, gap));
          }
          return retryItems;
        };

        // 1차 → 실패분 2차 → 그래도 실패하면 3차. 간격을 점점 넓힌다.
        // 조용한 누락은 스크리너에서 가장 위험한 실패 방식이라 끝까지 건진다.
        let pending = await runPass(chunk, GAP);
        for (const gap of [900, 1500]) {
          if (pending.length === 0) break;
          await new Promise(res => setTimeout(res, gap));
          pending = await runPass(pending, gap);
        }
        const failed = pending.length;   // 재시도까지 하고도 못 받은 종목

        const nextOffset = offset + chunkSize;
        const done = nextOffset >= total;

        // KV 쓰기 없이 결과를 응답으로만 반환
        return corsResponse({ ok: true, done, nextOffset: done ? null : nextOffset, total, kospiRs3m, scannedAt, chunkResults, chunkRs, failed, skipped });
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
        const cached = await env.KV.get('tf_holdings_quotes', 'json');
        if (!cached) return corsResponse({ error: '아직 저장된 종가 데이터가 없습니다. 다음 평일 오후 4시에 자동 업데이트됩니다.' }, 404);
        return corsResponse(cached);
      }

      // POST /save-holdings
      if (url.pathname === '/save-holdings' && request.method === 'POST') {
        const body = await request.json();
        const holdings = body.holdings;
        if (!Array.isArray(holdings)) return corsResponse({ error: 'holdings 배열 필요' }, 400);
        await env.KV.put('tf_holdings', JSON.stringify(holdings));
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
        const CACHE_KEY = 'cache:market-index';
        const CACHE_TTL = 5 * 60; // 5분
        try {
          const data = await getMarketIndex(env);
          await env.KV.put(CACHE_KEY, JSON.stringify({ data, ts: Date.now() }), { expirationTtl: CACHE_TTL * 2 });
          return corsResponse(data);
        } catch(e) {
          const cached = await env.KV.get(CACHE_KEY, 'json');
          if (cached?.data) return corsResponse({ ...cached.data, _cached: true });
          return corsResponse({ kospi: null, kosdaq: null, _error: e.message });
        }
      }

      // GET /kospi-ma
      if (url.pathname === '/kospi-ma') {
        const CACHE_KEY = 'cache:kospi-ma';
        const CACHE_TTL = 10 * 60; // 10분
        try {
          const data = await getKospiMA(env);
          await env.KV.put(CACHE_KEY, JSON.stringify({ data, ts: Date.now() }), { expirationTtl: CACHE_TTL * 2 });
          return corsResponse(data);
        } catch(e) {
          const cached = await env.KV.get(CACHE_KEY, 'json');
          if (cached?.data) return corsResponse({ ...cached.data, _cached: true });
          return corsResponse({ curr: 0, ma60: 0, isBullish: false, _error: e.message });
        }
      }

      // GET /market-investor
      if (url.pathname === '/market-investor') {
        const CACHE_KEY = 'cache:market-investor';
        const CACHE_TTL = 5 * 60;
        try {
          const data = await getMarketInvestor(env);
          await env.KV.put(CACHE_KEY, JSON.stringify({ data, ts: Date.now() }), { expirationTtl: CACHE_TTL * 2 });
          return corsResponse(data);
        } catch(e) {
          const cached = await env.KV.get(CACHE_KEY, 'json');
          if (cached?.data) return corsResponse({ ...cached.data, _cached: true });
          return corsResponse({ kospi: null, kosdaq: null, _error: e.message });
        }
      }

      // GET /market-sector
      if (url.pathname === '/market-sector') {
        const CACHE_KEY = 'cache:market-sector';
        const CACHE_TTL = 10 * 60;
        try {
          const data = await getMarketSector(env);
          await env.KV.put(CACHE_KEY, JSON.stringify({ data, ts: Date.now() }), { expirationTtl: CACHE_TTL * 2 });
          return corsResponse(data);
        } catch(e) {
          const cached = await env.KV.get(CACHE_KEY, 'json');
          if (cached?.data) return corsResponse({ ...cached.data, _cached: true });
          return corsResponse({ kospi: [], kosdaq: [], _error: e.message });
        }
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

      // ────────────────────────────────────────────────────────
      // 구글 로그인 — 토큰 검증 + 허용 이메일 체크
      // POST /auth/google  { idToken }
      // ────────────────────────────────────────────────────────
      if (url.pathname === '/auth/google' && request.method === 'POST') {
        const body = await request.json().catch(() => ({}));
        const { idToken } = body || {};
        if (!idToken) return corsResponse({ error: 'idToken 필요' }, 400);

        // 구글 토큰 검증 (tokeninfo 엔드포인트)
        const verifyRes = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${idToken}`);
        if (!verifyRes.ok) return corsResponse({ error: '구글 토큰 검증 실패' }, 401);
        const info = await verifyRes.json();

        // 발급자 확인
        if (!['accounts.google.com', 'https://accounts.google.com'].includes(info.iss)) {
          return corsResponse({ error: '유효하지 않은 토큰' }, 401);
        }

        const email = info.email;
        const userId = info.sub; // 구글 고유 ID

        // 허용 이메일 목록 — 환경변수와 KV를 "합쳐서" 본다.
        // 예전에는 env.ALLOWED_EMAILS가 있으면 KV를 아예 무시해서,
        // 대시보드 KV에 이메일을 추가해도 반영되지 않았다.
        const envRaw = env.ALLOWED_EMAILS || '';
        const kvRaw  = (await env.KV.get('allowed_emails')) || '';
        const allowed = [...new Set(
          [...envRaw.split(','), ...kvRaw.split(',')]
            .map(e => e.trim().toLowerCase())
            .filter(Boolean)
        )];

        if (allowed.length > 0 && !allowed.includes(email.toLowerCase())) {
          // allowedCount만 노출 — 다른 사람의 이메일은 응답에 담지 않는다.
          return corsResponse({ error: '접근 권한 없음', email, allowedCount: allowed.length }, 403);
        }

        return corsResponse({ ok: true, email, userId, name: info.name, picture: info.picture });
      }

      // ────────────────────────────────────────────────────────
      // PWA 웹 푸시 구독 저장/삭제
      // POST /push/subscribe   { userId, subscription }
      // POST /push/unsubscribe { userId }
      // ────────────────────────────────────────────────────────
      if (url.pathname === '/push/subscribe' && request.method === 'POST') {
        const body = await request.json().catch(() => ({}));
        const { userId, subscription } = body || {};
        if (!userId || !subscription) return corsResponse({ error: 'userId, subscription 필요' }, 400);
        // 기기별 별도 저장 — endpoint 끝 20자를 키로 사용해 같은 기기는 덮어쓰고 다른 기기는 추가
        const sub = typeof subscription === 'string' ? JSON.parse(subscription) : subscription;
        const epKey = (sub.endpoint || '').slice(-20).replace(/[^a-zA-Z0-9]/g, '_');
        await env.KV.put(`push_sub:${userId}:${epKey}`, JSON.stringify(subscription), { expirationTtl: 60 * 60 * 24 * 90 }); // 90일
        return corsResponse({ ok: true });
      }

      if (url.pathname === '/push/unsubscribe' && request.method === 'POST') {
        const body = await request.json().catch(() => ({}));
        const { userId, subscription } = body || {};
        if (!userId) return corsResponse({ error: 'userId 필요' }, 400);
        if (subscription) {
          // 특정 기기만 해제
          const sub = typeof subscription === 'string' ? JSON.parse(subscription) : subscription;
          const epKey = (sub.endpoint || '').slice(-20).replace(/[^a-zA-Z0-9]/g, '_');
          await env.KV.delete(`push_sub:${userId}:${epKey}`);
        } else {
          // 이전 형식 키도 같이 삭제
          await env.KV.delete(`push_sub:${userId}`);
        }
        return corsResponse({ ok: true });
      }

      // GET /push/vapid-public-key — 클라이언트가 구독 시 사용할 공개키 반환
      if (url.pathname === '/push/vapid-public-key' && request.method === 'GET') {
        if (!env.VAPID_PUBLIC_KEY) return corsResponse({ error: 'VAPID 미설정' }, 503);
        return corsResponse({ publicKey: env.VAPID_PUBLIC_KEY });
      }

      // GET /push/debug-vapid — VAPID 키 형식 검증
      if (url.pathname === '/push/debug-vapid' && request.method === 'GET') {
        try {
          const pub = env.VAPID_PUBLIC_KEY || '';
          const priv = env.VAPID_PRIVATE_KEY || '';
          const pubBytes = b64uDecode(pub);
          const privBytes = b64uDecode(priv);
          // VAPID public key는 65바이트 uncompressed P-256 point여야 함
          // VAPID private key는 PKCS8 DER 형식이어야 함
          let privValid = false;
          try {
            await crypto.subtle.importKey('pkcs8', privBytes, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
            privValid = true;
          } catch(e) { privValid = false; }
          return corsResponse({
            pub_len: pubBytes.length,       // 정상: 65
            pub_prefix: pubBytes[0],        // 정상: 4 (uncompressed)
            priv_len: privBytes.length,     // 정상: PKCS8은 보통 138~141바이트
            priv_valid_pkcs8: privValid,
            pub_first10: pub.slice(0, 10),
          });
        } catch(e) {
          return corsResponse({ error: e.message });
        }
      }

      // GET /push/debug-subs — 저장된 구독 endpoint 확인 (디버그용)
      if (url.pathname === '/push/debug-subs' && request.method === 'GET') {
        const list = await env.KV.list({ prefix: 'push_sub:' });
        const subs = await Promise.all(list.keys.map(async k => {
          const sub = await env.KV.get(k.name, 'json');
          const ep = (sub?.endpoint || '');
          return { key: k.name, endpoint: ep.substring(0, 60) + '...' };
        }));
        return corsResponse({ subs });
      }

      // POST /push/send-raw — 암호화 없이 평문 발송 (디버그용)
      if (url.pathname === '/push/send-raw' && request.method === 'POST') {
        const body = await request.json().catch(() => ({}));
        const payload = JSON.stringify({ title: body.title || '테스트', body: body.body || '평문 테스트' });
        const list = await env.KV.list({ prefix: 'push_sub:' });
        const results = [];
        for (const key of list.keys) {
          try {
            const sub = await env.KV.get(key.name, 'json');
            if (!sub) continue;
            const jwt = await makeVapidJwt(sub.endpoint, env.VAPID_PRIVATE_KEY, 'mailto:wlsdn816@gmail.com');
            const res = await fetch(sub.endpoint, {
              method: 'POST',
              headers: {
                'Authorization': `vapid t=${jwt},k=${env.VAPID_PUBLIC_KEY}`,
                'Content-Type': 'application/json',
                'TTL': '86400',
              },
              body: payload,
            });
            const txt = await res.text().catch(() => '');
            results.push({ key: key.name, status: res.status, body: txt.slice(0, 100) });
          } catch(e) {
            results.push({ key: key.name, error: e.message });
          }
        }
        return corsResponse({ ok: true, results });
      }

      // POST /push/send { title, body, url } — 테스트 발송 (내부용)
      // GET /push/test — 브라우저에서 바로 테스트용
      if (url.pathname === '/push/test' && request.method === 'GET') {
        const payload = {
          title: '🔔 FCM v1 테스트',
          body:  '알림이 정상 작동해요!',
          url:   'https://wlsdn816-eng.github.io/trend-tracker/',
        };
        try {
          const results = await broadcastPush(payload, env);
          return corsResponse({ ok: true, results });
        } catch(e) {
          return corsResponse({ error: e.message, stack: e.stack }, 500);
        }
      }

      if (url.pathname === '/push/send' && request.method === 'POST') {
        const body = await request.json().catch(() => ({}));
        const payload = {
          title: body.title || '📈 추세추종 매매 트래커',
          body:  body.body  || '알림 테스트',
          url:   body.url   || 'https://wlsdn816-eng.github.io/trend-tracker/',
        };
        try {
          const results = await broadcastPush(payload, env);
          return corsResponse({ ok: true, results });
        } catch(e) {
          return corsResponse({ error: e.message }, 500);
        }
      }

      // ────────────────────────────────────────────────────────
      // 계정별 보유종목 저장/조회
      // GET  /user-holdings?userId=xxx
      // POST /user-holdings  { userId, holdings }
      // ────────────────────────────────────────────────────────
      if (url.pathname === '/user-holdings') {
        if (request.method === 'GET') {
          const userId = url.searchParams.get('userId');
          if (!userId) return corsResponse({ error: 'userId 필요' }, 400);
          const data = await env.KV.get(`user:${userId}:holdings`, 'json');
          return corsResponse({ holdings: data || [] });
        }
        if (request.method === 'POST') {
          const body = await request.json().catch(() => ({}));
          const { userId, holdings } = body || {};
          if (!userId || !Array.isArray(holdings)) return corsResponse({ error: 'userId, holdings 필요' }, 400);
          await env.KV.put(`user:${userId}:holdings`, JSON.stringify(holdings));
          // 기존 tf_holdings도 소유자(지누님) 계정이면 함께 저장 (Cron 호환)
          const ownerEmail = (env.ALLOWED_EMAILS || '').split(',')[0].trim();
          const ownerKey = await env.KV.get('owner_user_id');
          if (!ownerKey || ownerKey === userId) {
            await env.KV.put('tf_holdings', JSON.stringify(holdings));
          }
          return corsResponse({ ok: true, count: holdings.length });
        }
      }

      // ────────────────────────────────────────────────────────
      // 범용 사용자 데이터 저장/조회
      // GET  /user-data?userId=xxx&key=journal
      // POST /user-data  { userId, key, data }
      // ────────────────────────────────────────────────────────
      if (url.pathname === '/user-data') {
        if (request.method === 'GET') {
          const userId = url.searchParams.get('userId');
          const key = url.searchParams.get('key');
          if (!userId || !key) return corsResponse({ error: 'userId, key 필요' }, 400);
          const data = await env.KV.get(`user:${userId}:${key}`, 'json');
          return corsResponse({ data: data ?? null });
        }
        if (request.method === 'POST') {
          const body = await request.json().catch(() => ({}));
          const { userId, key, data } = body || {};
          if (!userId || !key || data === undefined) return corsResponse({ error: 'userId, key, data 필요' }, 400);
          await env.KV.put(`user:${userId}:${key}`, JSON.stringify(data));
          return corsResponse({ ok: true });
        }
      }

      // 수동 Cron 트리거 (관리용)
      // GET  /scan-dispatch → 마지막 "스캔 깨우기" 기록 (읽기 전용)
      // POST /scan-dispatch → 지금 한 번 깨워 본다 (점검용, 10분에 한 번만 허용)
      //   그날 스캔이 이미 끝났다면 워크플로가 곧바로 종료하므로 안전하다.
      if (url.pathname === '/scan-dispatch') {
        const last = await env.KV.get('last_scan_dispatch', 'json');
        if (request.method === 'POST') {
          if (last?.at && Date.now() - new Date(last.at).getTime() < 10 * 60 * 1000) {
            return corsResponse({ error: '10분 안에 이미 호출됨', last }, 429);
          }
          return corsResponse(await dispatchScanWorkflow(env, 'manual-check'));
        }
        return corsResponse({ last: last || null, tokenSet: !!env.GITHUB_TOKEN });
      }

      if (url.pathname === '/run-cron' && request.method === 'GET') {
        const ctx = { waitUntil: (p) => p };
        await this.scheduled({}, env, ctx);
        return corsResponse({ ok: true, message: '스크리너 실행 완료' });
      }

      return corsResponse({ error: '알 수 없는 경로' }, 404);

    } catch (err) {
      return corsResponse({ error: err.message || '서버 오류' }, 500);
    }
  },
};
