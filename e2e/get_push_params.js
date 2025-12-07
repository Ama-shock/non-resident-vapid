// コンテナ内の Chrome で PushSubscription を取得し、ブラウザ内 WASM でクレデンシャルバンドルを生成。
// バンドル・購読情報を保存したうえで Push を送信し、受信まで待機する。
import http from "node:http";
import { createECDH, randomBytes } from "node:crypto";
import { mkdir, writeFile, readFile } from "node:fs/promises";
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
const バンドル鍵情報 = 生成バンドル鍵(); // VAPID 兼用の鍵
const 公開鍵 = バンドル鍵情報.publicKeyBase64Url;
const 秘密鍵 = バンドル鍵情報.privateKeyBase64Url;
const vapidファイルパス = path.join(出力ディレクトリ, "vapid_keys.json");
const vapidEnvパス = path.join(出力ディレクトリ, "vapid.env");
const 購読ファイルパス = path.join(出力ディレクトリ, "subscription.json");
const バンドルファイルパス = path.join(
  出力ディレクトリ,
  "credential_bundle.b64"
);
const バンドル鍵ファイルパス = path.join(
  出力ディレクトリ,
  "bundle_key.json"
);
const バンドル鍵サーバーファイルパス = path.join(
  出力ディレクトリ,
  "bundle_server_key.json"
);
const 自動送信する = process.env.E2E_SEND_PUSH !== "0"; // 既定で送信する
const バンドル有効期限秒 =
  process.env.E2E_BUNDLE_EXPIRES ||
  Math.floor(Date.now() / 1000) + 3600;
const サーバ = http.createServer((要求, 応答) => {
  console.log(`[サーバ] 受信: ${要求.method} ${要求.url}`);
  if (!要求.url) {
    応答.writeHead(400);
    応答.end("不正なリクエスト");
    return;
  }

  if (要求.url === "/") {
    応答.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    応答.end(インデックスHTML());
    return;
  }

  if (要求.url === "/bundle-config") {
    応答.writeHead(200, { "Content-Type": "application/json" });
    応答.end(
      JSON.stringify({
        keyIdBase64Url: バンドル鍵情報.keyIdBase64Url,
        publicKeyBase64Url: バンドル鍵情報.publicKeyBase64Url,
        expirationSec: バンドル有効期限秒,
        vapidPublicKey: 公開鍵,
      })
    );
    return;
  }

  if (要求.url === "/sw.js") {
    readFile("/e2e/sw.js")
      .then((buf) => {
        応答.writeHead(200, {
          "Content-Type": "application/javascript",
          "Service-Worker-Allowed": "/",
        });
        応答.end(buf);
      })
      .catch((err) => {
        console.error(err);
        応答.writeHead(500);
        応答.end("sw.js 読み込み失敗");
      });
    return;
  }

  if (要求.url === "/vapid-public-key") {
    応答.writeHead(200, { "Content-Type": "text/plain" });
    応答.end(公開鍵);
    return;
  }

  if (要求.url === "/app.js") {
    readFile("/e2e/app.js")
      .then((buf) => {
        応答.writeHead(200, { "Content-Type": "application/javascript" });
        応答.end(buf);
      })
      .catch((err) => {
        console.error(err);
        応答.writeHead(404);
        応答.end("not found");
      });
    return;
  }

  if (要求.url?.startsWith("/pkg/")) {
    const ファイルパス = path.join("/e2e", 要求.url);
    readFile(ファイルパス)
      .then((buf) => {
        const ext = path.extname(ファイルパス);
        const type =
          ext === ".js"
            ? "application/javascript"
            : ext === ".wasm"
            ? "application/wasm"
            : "application/octet-stream";
        応答.writeHead(200, { "Content-Type": type });
        応答.end(buf);
      })
      .catch((err) => {
        console.error(err);
        応答.writeHead(404);
        応答.end("not found");
      });
    return;
  }

  if (要求.url === "/save-bundle" && 要求.method === "POST") {
    let body = "";
    要求.on("data", (chunk) => {
      body += chunk;
    });
    要求.on("end", async () => {
      try {
        const data = JSON.parse(body);
        await writeFile(購読ファイルパス, JSON.stringify(data.subscription, null, 2), "utf8");
        await writeFile(バンドルファイルパス, data.bundleBase64, "utf8");
        // ブラウザに渡していない秘密鍵をサーバー側で保持
        await writeFile(バンドル鍵サーバーファイルパス, JSON.stringify(バンドル鍵情報, null, 2), "utf8");
        応答.writeHead(200, { "Content-Type": "application/json" });
        応答.end(JSON.stringify({ ok: true }));
      } catch (err) {
        console.error(err);
        応答.writeHead(500);
        応答.end("保存に失敗");
      }
    });
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
    if (自動送信する) {
      await pushを送信();
    } else {
      console.log("[sender] 自動送信をスキップします (E2E_SEND_PUSH=0)");
    }
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

  await ページ.goto(オリジン, { waitUntil: "networkidle2" });
  await ページ.waitForSelector("#result[data-ready='1']", { timeout: 20000 });

  const ペイロード文字列 = await ページ.$eval(
    "#result",
    (ノード) => ノード.textContent || ""
  );
  const 解析済み = JSON.parse(ペイロード文字列);

  console.log("\n[push-subscription]");
  console.log(JSON.stringify(解析済み, null, 2));
  console.log(`[e2e] プッシュ受信を待機します (${プッシュ待機ms}ms)。`);

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
  console.log("[sender] bundle-server で送信を開始します");
  return new Promise((resolve, reject) => {
    // bundle-server CLI で復号＋送信
    const args = [
      "--bundle-file",
      バンドルファイルパス,
      "--key-id-base64url",
      バンドル鍵情報.keyIdBase64Url,
      "--private-key-base64url",
      バンドル鍵情報.privateKeyBase64Url,
      "--payload",
      process.env.E2E_PUSH_PAYLOAD || "e2e送信テスト",
      "--subject",
      process.env.E2E_PUSH_SUBJECT || "mailto:test@example.com",
      "--ttl",
      process.env.E2E_PUSH_TTL || "60",
    ];
    const 子 = execFile("bundle-server", args, { env: process.env });
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

function インデックスHTML() {
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
  <script type="module" src="/app.js"></script>
</body>
</html>`;
}

function vapid鍵生成() {
  const ecdh = createECDH("prime256v1");
  ecdh.generateKeys();
  const 公開鍵 = base64url化(ecdh.getPublicKey());
  const 秘密鍵 = base64url化(ecdh.getPrivateKey());
  return { 公開鍵, 秘密鍵 };
}

function 生成バンドル鍵() {
  const ecdh = createECDH("prime256v1");
  ecdh.generateKeys();
  const 公開鍵 = ecdh.getPublicKey(undefined, "compressed");
  const 秘密鍵 = ecdh.getPrivateKey();
  const 鍵識別子 = randomBytes(8);
  return {
    keyIdBase64Url: base64url化(鍵識別子),
    publicKeyBase64Url: base64url化(公開鍵),
    privateKeyBase64Url: base64url化(秘密鍵),
  };
}

function base64url化(バッファ) {
  return バッファ.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
