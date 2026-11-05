// Service Worker — 추세추종 매매 트래커 PWA
const CACHE_NAME = 'trend-tracker-v2';
const BASE = '/trend-tracker';

self.addEventListener('install', e => {
  self.skipWaiting();
});

self.addEventListener('activate', e => {
  e.waitUntil(clients.claim());
});

// 푸시 알림 수신
self.addEventListener('push', e => {
  if (!e.data) return;

  let data = {};
  try { data = e.data.json(); } catch(_) {
    data = { title: '📈 스캔 완료', body: e.data.text() };
  }

  const title   = data.title || '📈 추세추종 매매 트래커';
  const options = {
    body:              data.body  || '오늘의 스캔 결과가 준비됐어요.',
    icon:              BASE + '/icon-192.png',
    badge:             BASE + '/icon-72.png',
    data:              { url: data.url || BASE + '/' },
    vibrate:           [200, 100, 200],
    requireInteraction: false,
  };

  e.waitUntil(self.registration.showNotification(title, options));
});

// 알림 클릭 → 앱 열기
self.addEventListener('notificationclick', e => {
  e.notification.close();
  const targetUrl = e.notification.data?.url || BASE + '/';
  e.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
      for (const c of list) {
        if (c.url.includes('trend-tracker') && 'focus' in c) return c.focus();
      }
      return clients.openWindow(targetUrl);
    })
  );
});
