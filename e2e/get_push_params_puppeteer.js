// Puppeteer で Chrome を使い、購読 -> バンドル生成 -> サーバー復号 -> Push 受信までを実施
import { createServer } from 'node:http';
import { createECDH, randomBytes } from 'node:crypto';
import { mkdir, writeFile, readFile, access, rm } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import path from 'node:path';
import puppeteer from 'puppeteer';

const ポート = process.env.E2E_PORT ? Number(process.env.E2E_PORT) : 3000;
const ホスト = '0.0.0.0';
const オリジン = `http://localhost:${ポート}`;
const 出力ディレクトリ = process.env.E2E_OUTPUT_DIR || '.';
const 自動送信する = process.env.E2E_SEND_PUSH !== '0';
const バンドル有効期限秒 = process.env.E2E_BUNDLE_EXPIRES
  ? Number(process.env.E2E_BUNDLE_EXPIRES)
  : Math.floor(Date.now() / 1000) + 3600;

const バンドル鍵情報 = 生成バンドル鍵();
const 公開鍵 = バンドル鍵情報.publicKeyBase64Url;
const 秘密鍵 = バンドル鍵情報.privateKeyBase64Url;

const vapidファイルパス = path.join(出力ディレクトリ, 'vapid_keys.json');
const vapidEnvパス = path.join(出力ディレクトリ, 'vapid.env');
const 購読ファイルパス = path.join(出力ディレクトリ, 'subscription.json');
const バンドルファイルパス = path.join(出力ディレクトリ, 'credential_bundle.b64');
const バンドル鍵サーバーファイルパス = path.join(出力ディレクトリ, 'bundle_server_key.json');
const 復号購読ファイルパス = path.join(出力ディレクトリ, 'subscription_decoded.json');

// HTTP サーバー
const サーバ = createServer((要求, 応答) => {
  console.log(`[サーバ] 受信: ${要求.method} ${要求.url}`);
  if (!要求.url) {
    応答.writeHead(400);
    応答.end('不正なリクエスト');
    return;
  }

  if (要求.url === '/') {
    応答.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    応答.end(インデックスHTML());
    return;
  }

  if (要求.url === '/bundle-config') {
    応答.writeHead(200, { 'Content-Type': 'application/json' });
    応答.end(
      JSON.stringify({
        keyIdBase64Url: バンドル鍵情報.keyIdBase64Url,
        publicKeyBase64Url: バンドル鍵情報.publicKeyBase64Url,
        expirationSec: バンドル有効期限秒,
        vapidPublicKey: 公開鍵,
      }),
    );
    return;
  }

  if (要求.url === '/sw.js') {
    readFile('/e2e/sw.js')
      .then((buf) => {
        応答.writeHead(200, {
          'Content-Type': 'application/javascript',
          'Service-Worker-Allowed': '/',
        });
        応答.end(buf);
      })
      .catch((err) => {
        console.error(err);
        応答.writeHead(500);
        応答.end('sw.js 読み込み失敗');
      });
    return;
  }

  if (要求.url === '/vapid-public-key') {
    応答.writeHead(200, { 'Content-Type': 'text/plain' });
    応答.end(公開鍵);
    return;
  }

  if (要求.url === '/app.js') {
    readFile('/e2e/app.js')
      .then((buf) => {
        応答.writeHead(200, { 'Content-Type': 'application/javascript' });
        応答.end(buf);
      })
      .catch((err) => {
        console.error(err);
        応答.writeHead(404);
        応答.end('not found');
      });
    return;
  }

  if (要求.url?.startsWith('/pkg/')) {
    const ファイルパス = path.join('/e2e', 要求.url);
    readFile(ファイルパス)
      .then((buf) => {
        const ext = path.extname(ファイルパス);
        const type =
          ext === '.js'
            ? 'application/javascript'
            : ext === '.wasm'
              ? 'application/wasm'
              : 'application/octet-stream';
        応答.writeHead(200, { 'Content-Type': type });
        応答.end(buf);
      })
      .catch((err) => {
        console.error(err);
        応答.writeHead(404);
        応答.end('not found');
      });
    return;
  }

  if (要求.url === '/save-bundle' && 要求.method === 'POST') {
    let body = '';
    要求.on('data', (chunk) => { body += chunk; });
    要求.on('end', async () => {
      try {
        const data = JSON.parse(body);
        await writeFile(購読ファイルパス, JSON.stringify(data.subscription, null, 2), 'utf8');
        await writeFile(バンドルファイルパス, data.bundleBase64, 'utf8');
        await writeFile(バンドル鍵サーバーファイルパス, JSON.stringify(バンドル鍵情報, null, 2), 'utf8');
        await ログ出力_バンドル分解(data.subscription, data.bundleBase64);
        応答.writeHead(200, { 'Content-Type': 'application/json' });
        応答.end(JSON.stringify({ ok: true }));
      } catch (err) {
        console.error(err);
        応答.writeHead(500);
        応答.end('保存に失敗');
      }
    });
    return;
  }

  応答.writeHead(404);
  応答.end('Not found');
});

let exitCode = 0;

サーバ.listen(ポート, ホスト, async () => {
  console.log(`[サーバ] 待受: ${オリジン}`);
  console.log(`[VAPID] 公開鍵=${公開鍵}`);
  console.log(`[VAPID] 秘密鍵=${秘密鍵}`);

  await mkdir(出力ディレクトリ, { recursive: true });
  try {
    const entries = await (await import('node:fs/promises')).readdir(出力ディレクトリ, { withFileTypes: true });
    for (const entry of entries) {
      const full = path.join(出力ディレクトリ, entry.name);
      await rm(full, { recursive: true, force: true });
    }
  } catch (err) {
    console.warn('[サーバ] 出力ディレクトリの初期化に失敗しましたが続行します:', err.message);
  }

  await writeFile(vapidファイルパス, JSON.stringify({ vapid公開鍵: 公開鍵, vapid秘密鍵: 秘密鍵 }, null, 2), 'utf8');
  await writeFile(vapidEnvパス, `VAPID_PUBLIC_KEY=${公開鍵}\nVAPID_PRIVATE_KEY=${秘密鍵}\n`, 'utf8');
  console.log(`[VAPID] ${vapidファイルパス} と ${vapidEnvパス} に保存しました`);

  try {
    await ブラウザ実行();
  } catch (err) {
    console.error('[e2e] エラー:', err);
    exitCode = 1;
  } finally {
    サーバ.close(() => process.exit(exitCode));
  }
});

async function ブラウザ実行() {
  console.log('\n[chromium] 実行開始');

  const browser = await puppeteer.launch({
    headless: true,
    args: [
      '--no-sandbox',
      '--disable-dev-shm-usage',
      '--disable-gpu',
      '--enable-features=PushMessaging',
    ],
  });

  try {
    const page = await browser.newPage();

    page.on('console', (メッセージ) => {
      console.log(`[chromium][ページ] ${メッセージ.type()}: ${メッセージ.text()}`);
    });
    page.on('requestfailed', (要求) => {
      console.log(`[chromium][リクエスト失敗] ${要求.url()} ${要求.failure()?.errorText ?? ''}`);
    });
    page.on('response', (応答) => {
      if (応答.status() >= 400) {
        console.log(`[chromium][レスポンス] ${応答.status()} ${応答.url()}`);
      }
    });

    // 通知許可を付与
    await browser.defaultBrowserContext().overridePermissions(オリジン, ['notifications']);

    await page.goto(オリジン, { waitUntil: 'networkidle2' });
    await page.evaluate(() => { window.__pushText = undefined; });
    await page.click('#start');

    // 購読・バンドルエンコードが完了するまで待機
    await page.waitForSelector('#result[data-ready="1"]', { timeout: 20000 });

    const resultText = await page.$eval('#result', (el) => el.textContent ?? '');
    const result = JSON.parse(resultText);
    if (result.error) {
      throw new Error(`ブラウザエラー: ${result.error}`);
    }

    console.log('[chromium] ✅ 購読・バンドルエンコード成功');

    if (自動送信する) {
      let bundleExists = false;
      try {
        await access(バンドルファイルパス);
        bundleExists = true;
      } catch {
        console.warn('[chromium] バンドルファイルが無いため送信をスキップします');
      }

      if (bundleExists) {
        await pushを送信('chromium');
        try {
          await page.waitForFunction(() => typeof window.__pushText !== 'undefined', {
            timeout: Number(process.env.PUSH_WAIT_MS ?? 30000),
          });
          const 受信 = await page.evaluate(() => window.__pushText);
          console.log(`[chromium] ✅ Push 受信: ${受信}`);
        } catch {
          console.warn('[chromium] ⚠️  Push 受信タイムアウト（FCM アクセス制限の可能性あり）');
        }
      }
    } else {
      console.log('[chromium] 自動送信をスキップします (E2E_SEND_PUSH=0)');
    }

    console.log('[chromium] 完了');
  } finally {
    await browser.close();
  }
}

async function pushを送信(prefix = 'sender') {
  console.log(`[${prefix}] bundle-server で送信を開始します`);
  return new Promise((resolve) => {
    const args = [
      '--bundle-file', バンドルファイルパス,
      '--key-id-base64url', バンドル鍵情報.keyIdBase64Url,
      '--private-key-base64url', バンドル鍵情報.privateKeyBase64Url,
      '--payload', process.env.E2E_PUSH_PAYLOAD || 'e2e送信テスト',
      '--subject', process.env.E2E_PUSH_SUBJECT || 'mailto:test@example.com',
      '--ttl', process.env.E2E_PUSH_TTL || '60',
    ];
    const 子 = execFile('bundle-server-cli', args, { env: process.env });
    子.stdout?.on('data', (d) => process.stdout.write(`[${prefix}] ${d}`));
    子.stderr?.on('data', (d) => process.stderr.write(`[${prefix}][stderr] ${d}`));
    子.on('exit', (code) => {
      if (code === 0) {
        console.log(`[${prefix}] 送信完了`);
      } else {
        console.warn(`[${prefix}] 送信プロセスが異常終了しました (code=${code})。ネットワーク制限などの可能性がありますがテストは継続します。`);
      }
      resolve();
    });
    子.on('error', (err) => {
      console.warn(`[${prefix}] 送信プロセス起動に失敗しました: ${err.message}`);
      resolve();
    });
    const timeoutMs = Number(process.env.E2E_SEND_TIMEOUT_MS ?? 30000);
    setTimeout(() => {
      if (!子.killed) {
        console.warn(`[${prefix}] 送信プロセスがタイムアウトしたため終了します`);
        子.kill('SIGKILL');
        resolve();
      }
    }, timeoutMs);
  });
}

async function ログ出力_バンドル分解(購読, bundleBase64) {
  const bundleBuf = base64urlデコード(bundleBase64);
  const keyId = bundleBuf.subarray(0, 8);
  const ciphertext = bundleBuf.subarray(8);
  console.log('[bundle-log] 暗号化前 (購読データ)', {
    endpoint: 購読.endpoint,
    auth: 購読.auth,
    p256dh: 購読.p256dh,
    expirationTime: 購読.expirationTime,
  });
  console.log('[bundle-log] バンドル構造', {
    keyIdBase64: base64url化(keyId),
    ciphertextLength: ciphertext.length,
  });

  try {
    await execFileAsync('credential-bundle-cli', [
      'decode',
      '--bundle-file', バンドルファイルパス,
      '--key-id-base64url', バンドル鍵情報.keyIdBase64Url,
      '--private-key-base64url', バンドル鍵情報.privateKeyBase64Url,
      '--output-file', 復号購読ファイルパス,
    ]);
    const 復号購読 = JSON.parse(await readFile(復号購読ファイルパス, 'utf8'));
    console.log('[bundle-log] 復号後 (購読データ)', 復号購読);

    // エンドポイントと auth が一致することを確認
    if (復号購読.endpoint !== 購読.endpoint) {
      throw new Error(`エンドポイント不一致: ${復号購読.endpoint} !== ${購読.endpoint}`);
    }
    if (復号購読.auth !== 購読.auth) {
      throw new Error(`auth 不一致: ${復号購読.auth} !== ${購読.auth}`);
    }
    console.log('[bundle-log] ✅ エンコード/デコードのラウンドトリップ確認完了');
  } catch (err) {
    console.error('[bundle-log] 復号ログ取得に失敗', err);
    throw err;
  }
}

function execFileAsync(cmd, args) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { env: process.env }, (error, stdout, stderr) => {
      if (stdout) process.stdout.write(`[${cmd}] ${stdout}`);
      if (stderr) process.stderr.write(`[${cmd}][stderr] ${stderr}`);
      if (error) reject(error);
      else resolve();
    });
  });
}

function base64url化(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlデコード(str) {
  const padding = '='.repeat((4 - (str.length % 4)) % 4);
  const base64 = (str + padding).replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(base64, 'base64');
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
    <h1>Push Subscription（Puppeteer フィクスチャ）</h1>
    <button id="start" type="button">購読開始</button>
    <pre id="result" aria-live="polite">待機中...</pre>
  </main>
  <script type="module" src="/app.js"></script>
</body>
</html>`;
}

function 生成バンドル鍵() {
  const ecdh = createECDH('prime256v1');
  ecdh.generateKeys();
  const 公開鍵 = ecdh.getPublicKey(undefined, 'uncompressed');
  const 秘密鍵 = ecdh.getPrivateKey();
  const 鍵識別子 = randomBytes(8);
  return {
    keyIdBase64Url: base64url化(鍵識別子),
    publicKeyBase64Url: base64url化(公開鍵),
    privateKeyBase64Url: base64url化(秘密鍵),
  };
}
