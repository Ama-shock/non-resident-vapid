// コンテナ内の Chrome で PushSubscription を取得し、クレデンシャルバンドル用の4要素を出力。
// そのまま Push を受信するまで待機し、本文を標準出力へ出す。
import http from "node:http";
import { createECDH } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import path from "node:path";
import puppeteer from "puppeteer-core";

const ポート = process.env.E2E_PORT ? Number(process.env.E2E_PORT) : 3000;
const ホスト = "0.0.0.0";
const オリジン = `http://localhost:${ポート}`;
const プッシュ待機ms = process.env.PUSH_WAIT_MS
  ? Number(process.env.PUSH_WAIT_MS)
  : 60_000;

const 出力ディレクトリ = process.env.E2E_OUTPUT_DIR || ".";
const { 公開鍵, 秘密鍵 } = vapid鍵生成();
const vapidファイルパス = path.join(出力ディレクトリ, "vapid_keys.json");
const vapidEnvパス = path.join(出力ディレクトリ, "vapid.env");
const 購読ファイルパス = path.join(出力ディレクトリ, "subscription.json");
const 自動送信する = process.env.E2E_SEND_PUSH !== "0"; // 既定で送信する

const サーバ = http.createServer((要求, 応答) => {
  console.log(`[サーバ] 受信: ${要求.method} ${要求.url}`);
  if (!要求.url) {
    応答.writeHead(400);
    応答.end("不正なリクエスト");
    return;
  }

  if (要求.url === "/") {
    応答.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    応答.end(インデックスHTML(公開鍵));
    return;
  }

  if (要求.url === "/sw.js") {
    応答.writeHead(200, {
      "Content-Type": "application/javascript",
      "Service-Worker-Allowed": "/",
    });
    応答.end(サービスワーカーJS());
    return;
  }

  if (要求.url === "/vapid-public-key") {
    応答.writeHead(200, { "Content-Type": "text/plain" });
    応答.end(公開鍵);
    return;
  }

  応答.writeHead(404);
  応答.end("Not found");
});

サーバ.listen(ポート, ホスト, async () => {
  console.log(`[サーバ] 待受: ${オリジン}`);
  console.log(`[VAPID] 公開鍵=${公開鍵}`);
  console.log(`[VAPID] 秘密鍵=${秘密鍵}`);
  await mkdir(出力ディレクトリ, { recursive: true });
  await writeFile(
    vapidファイルパス,
    JSON.stringify({ vapid公開鍵: 公開鍵, vapid秘密鍵: 秘密鍵 }, null, 2),
    "utf8"
  );
  await writeFile(
    vapidEnvパス,
    `VAPID_PUBLIC_KEY=${公開鍵}\nVAPID_PRIVATE_KEY=${秘密鍵}\n`,
    "utf8"
  );
  console.log(`[VAPID] ${vapidファイルパス} と ${vapidEnvパス} に保存しました`);

  try {
    await ブラウザ実行();
  } catch (エラー) {
    console.error("[e2e] エラー:", エラー);
    process.exitCode = 1;
  } finally {
    サーバ.close();
  }
});

async function ブラウザ実行() {
  const 実行ファイルパス =
    process.env.CHROME_BIN ||
    process.env.PUPPETEER_EXECUTABLE_PATH ||
    "/usr/bin/chromium";

  const ブラウザ = await puppeteer.launch({
    headless: false,
    executablePath: 実行ファイルパス,
    userDataDir: "/tmp/chrome-profile",
    args: [
      "--no-sandbox",
      "--disable-dev-shm-usage",
      "--disable-gpu",
      `--unsafely-treat-insecure-origin-as-secure=${オリジン}`,
      "--disable-features=EnableUseZoomForDSF,UserAgentClientHint",
      "--disable-incognito-mode",
    ],
  });

  const デフォルトコンテキスト = ブラウザ.defaultBrowserContext();
  await デフォルトコンテキスト.overridePermissions(オリジン, ["notifications"]);
  const ページ = await ブラウザ.newPage();

  ページ.on("console", (メッセージ) => {
    console.log(`[ページコンソール] ${メッセージ.type()}: ${メッセージ.text()}`);
  });
  ページ.on("requestfailed", (要求) => {
    console.log(
      `[リクエスト失敗] ${要求.url()} ${要求.failure()?.errorText ?? ""}`
    );
  });
  ページ.on("response", (応答) => {
    if (応答.status() >= 400) {
      console.log(`[レスポンス] ${応答.status()} ${応答.url()}`);
    }
  });

  console.log("[ブラウザ] userAgent:", await ページ.browser().userAgent());

  // Service Worker を確実に配信するため、Puppeteer 側でルーティングも用意する
  await ページ.setRequestInterception(true);
  ページ.on("request", (要求) => {
    if (要求.url() === `${オリジン}/sw.js`) {
      要求.respond({
        status: 200,
        contentType: "application/javascript",
        body: サービスワーカーJS(),
      });
      return;
    }
    要求.continue();
  });

  await ページ.goto(オリジン, { waitUntil: "networkidle2" });
  await ページ.waitForSelector("#result[data-ready='1']", { timeout: 20000 });

  const ペイロード文字列 = await ページ.$eval(
    "#result",
    (ノード) => ノード.textContent || ""
  );
  const 解析済み = JSON.parse(ペイロード文字列);

  await writeFile(購読ファイルパス, JSON.stringify(解析済み, null, 2), "utf8");

  console.log("\n[push-subscription]");
  console.log(JSON.stringify(解析済み, null, 2));
  console.log(`[e2e] subscription.json に保存しました。プッシュ受信を待機します (${プッシュ待機ms}ms)。`);

  if (自動送信する) {
    await pushを送信();
  }

  try {
    await ページ.waitForFunction(
      () => typeof window.__pushText !== "undefined",
      { timeout: プッシュ待機ms }
    );
    const プッシュ本文 = await ページ.evaluate(() => window.__pushText);
    console.log(`\n[push-received]\n${プッシュ本文}`);
  } catch (err) {
    console.error("[e2e] プッシュ受信タイムアウト:", err.message);
  }

  await ブラウザ.close();
}

async function pushを送信() {
  console.log("[sender] non-resident-vapid で送信を開始します");
  return new Promise((resolve, reject) => {
    const args = [
      "--subscription-file",
      購読ファイルパス,
      "--vapid-keys-file",
      vapidファイルパス,
      "--payload",
      process.env.E2E_PUSH_PAYLOAD || "e2e送信テスト",
      "--subject",
      process.env.E2E_PUSH_SUBJECT || "mailto:test@example.com",
      "--ttl",
      process.env.E2E_PUSH_TTL || "60",
    ];
    const 子 = execFile("non-resident-vapid", args, { env: process.env });
    子.stdout?.on("data", (d) => process.stdout.write(`[sender] ${d}`));
    子.stderr?.on("data", (d) => process.stderr.write(`[sender][stderr] ${d}`));
    子.on("exit", (code) => {
      if (code === 0) {
        console.log("[sender] 送信完了");
        resolve();
      } else {
        reject(new Error(`送信プロセスが異常終了しました (code=${code})`));
      }
    });
    子.on("error", reject);
  });
}

function インデックスHTML(vapid公開鍵) {
  return /* html */ `<!doctype html>
<html lang="ja">
<head>
  <meta charset="utf-8" />
  <title>Push Subscription 取得フィクスチャ</title>
</head>
<body>
  <main>
    <h1>Push Subscription（Headless Chrome フィクスチャ）</h1>
    <pre id="result" aria-live="polite">待機中...</pre>
  </main>
  <script type="module">
    const 結果要素 = document.querySelector("#result");
    window.__pushText = undefined;

    const vapid公開鍵 = ${JSON.stringify(vapid公開鍵)};

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

        結果要素.textContent = JSON.stringify(ペイロード);
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

    メイン();
  </script>
</body>
</html>`;
}

function サービスワーカーJS() {
  return `
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
`;
}

function vapid鍵生成() {
  const ecdh = createECDH("prime256v1");
  ecdh.generateKeys();
  const 公開鍵 = base64url化(ecdh.getPublicKey());
  const 秘密鍵 = base64url化(ecdh.getPrivateKey());
  return { 公開鍵, 秘密鍵 };
}

function base64url化(バッファ) {
  return バッファ.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
