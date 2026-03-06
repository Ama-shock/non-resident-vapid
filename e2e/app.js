import init, { encode_credential_bundle_wasm } from "/pkg/non_resident_vapid.js";

const 結果要素 = document.querySelector("#result");
window.__pushText = undefined;

const base64UrlをUint8Arrayへ = (base64String) => {
  const padding = "=".repeat((4 - (base64String.length % 4)) % 4);
  const base64 = (base64String + padding).replace(/-/g, "+").replace(/_/g, "/");
  const rawData = window.atob(base64);
  const outputArray = new Uint8Array(rawData.length);
  for (let i = 0; i < rawData.length; ++i) {
    outputArray[i] = rawData.charCodeAt(i);
  }
  return outputArray;
};

async function メイン() {
  console.log("userAgent", navigator.userAgent);
  navigator.serviceWorker.addEventListener("message", (event) => {
    if (event.data?.type === "push") {
      window.__pushText = event.data.text;
      結果要素.textContent = JSON.stringify({
        ...JSON.parse(結果要素.textContent || "{}"),
        push: event.data.text,
      });
    }
  });
  try {
    const 設定 = await fetch("/bundle-config").then((r) => r.json());
    const vapid公開鍵 = 設定.vapidPublicKey;

    const 許可 = await Notification.requestPermission();
    if (許可 !== "granted") {
      throw new Error("通知許可が得られませんでした");
    }

    const 登録 = await navigator.serviceWorker.register(new URL("/sw.js", location.href).toString());
    await navigator.serviceWorker.ready;
    await 有効化待ち(登録);

    const 購読 = await 登録.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: base64UrlをUint8Arrayへ(vapid公開鍵),
    });

    const json = 購読.toJSON();
    const ペイロード = {
      endpoint: json.endpoint,
      auth: json.keys?.auth,
      p256dh: json.keys?.p256dh,
      expirationTime: json.expirationTime ?? null,
    };

    await init();
    const バンドルb64 = await encode_credential_bundle_wasm(
      JSON.stringify(ペイロード),
      設定.keyIdBase64Url,
      設定.publicKeyBase64Url,
      BigInt(設定.expirationSec)
    );

    await fetch("/save-bundle", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        bundleBase64: バンドルb64,
        subscription: ペイロード,
      }),
    });

    結果要素.textContent = JSON.stringify({
      ...ペイロード,
      bundle: バンドルb64,
    });
    結果要素.dataset.ready = "1";
  } catch (error) {
    結果要素.textContent = JSON.stringify({ error: error.message });
    結果要素.dataset.ready = "1";
    console.error(error);
  }
}

async function 有効化待ち(登録, タイムアウトms = 10000) {
  const 開始 = Date.now();
  const sw = 登録.installing || 登録.waiting || 登録.active;

  if (!sw) {
    throw new Error("Service Worker が見つかりません");
  }

  if (sw.state === "activated") return;

  return new Promise((resolve, reject) => {
    const 状態変更 = () => {
      if (sw.state === "activated") {
        sw.removeEventListener("statechange", 状態変更);
        resolve();
      } else if (sw.state === "redundant") {
        sw.removeEventListener("statechange", 状態変更);
        reject(new Error("Service Worker が redundant になりました"));
      } else if (Date.now() - 開始 > タイムアウトms) {
        sw.removeEventListener("statechange", 状態変更);
        reject(new Error("Service Worker が有効化されません"));
      }
    };

    sw.addEventListener("statechange", 状態変更);
    const interval = setInterval(() => {
      if (Date.now() - 開始 > タイムアウトms) {
        clearInterval(interval);
        sw.removeEventListener("statechange", 状態変更);
        reject(new Error("Service Worker が有効化されません"));
      }
    }, 250);
  });
}

const 開始ボタン = document.querySelector("#start");
if (開始ボタン) {
  開始ボタン.addEventListener("click", () => {
    メイン();
  });
} else {
  // フォールバック（ボタンが無い場合）
  メイン();
}
