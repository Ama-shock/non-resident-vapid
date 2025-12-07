self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});
self.addEventListener("push", (event) => {
  const text = event.data ? event.data.text() : "push received";
  event.waitUntil((async () => {
    const クライアント一覧 = await self.clients.matchAll({ includeUncontrolled: true });
    クライアント一覧.forEach((client) => {
      client.postMessage({ type: "push", text });
    });
    await self.registration.showNotification("e2e push", {
      body: text,
    });
  })());
});
