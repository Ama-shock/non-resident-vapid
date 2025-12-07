//! 暗号化済みクレデンシャルバンドルを復号して即時送信するサーバサイド用 CLI（E2E 用実装）。

use anyhow::{bail, Context, Result};
use clap::Parser;
use non_resident_vapid::key_store::{KeyHandle, KeyStore};
use non_resident_vapid::deliver_push_from_bundle;
use p256::SecretKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use std::fs;

#[derive(Parser, Debug)]
#[command(name = "bundle-server", about = "暗号化バンドルを復号して WebPush を送信するツール")]
struct Args {
    /// バンドル Base64URL ファイル
    #[arg(long)]
    bundle_file: String,
    /// 鍵識別子 (Base64URL, 8バイト)
    #[arg(long)]
    key_id_base64url: String,
    /// バンドル復号と署名に使う秘密鍵 (Base64URL, raw 32 バイト)
    #[arg(long)]
    private_key_base64url: String,
    /// 送信する本文
    #[arg(long, default_value = "e2e送信テスト")]
    payload: String,
    /// TTL 秒
    #[arg(long, default_value_t = 60)]
    ttl: u32,
    /// subject (mailto 等)
    #[arg(long, default_value = "mailto:test@example.com")]
    subject: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let bundle_b64 = fs::read_to_string(&args.bundle_file)
        .with_context(|| format!("バンドルファイル読み込み失敗: {}", &args.bundle_file))?;
    let bundle = base64::decode_config(bundle_b64.trim(), base64::URL_SAFE_NO_PAD)
        .context("バンドル Base64URL デコードに失敗")?;

    let key_id = base64::decode_config(args.key_id_base64url.trim(), base64::URL_SAFE_NO_PAD)
        .context("鍵IDの Base64URL デコードに失敗")?;
    if key_id.len() != 8 {
        bail!("鍵識別子は 8 バイトである必要があります");
    }
    let private_raw = base64::decode_config(args.private_key_base64url.trim(), base64::URL_SAFE_NO_PAD)
        .context("秘密鍵の Base64URL デコードに失敗")?;
    let secret = SecretKey::from_slice(&private_raw)
        .map_err(|_| anyhow::anyhow!("秘密鍵の復元に失敗しました"))?;
    let public = secret.public_key().to_encoded_point(true);

    let store = 単一鍵ストア {
        handle: 単一鍵ハンドル {
            key_id,
            secret,
            public: public.as_bytes().to_vec(),
        },
    };

    deliver_push_from_bundle(&bundle, &args.payload, args.ttl, &args.subject, &store).await
}

#[derive(Clone)]
struct 単一鍵ハンドル {
    key_id: Vec<u8>,
    secret: SecretKey,
    public: Vec<u8>,
}

impl KeyHandle for 単一鍵ハンドル {
    fn key_identifier(&self) -> &[u8] {
        &self.key_id
    }
    fn public_key_bytes(&self) -> &[u8] {
        &self.public
    }
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        non_resident_vapid::credential_bundle::crypto::p256dhで復号(ciphertext, &self.secret)
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        use p256::ecdsa::{signature::Signer, SigningKey};
        let signing: SigningKey = (&self.secret).into();
        let sig: p256::ecdsa::Signature = signing.sign(message);
        Ok(sig.to_bytes().to_vec())
    }
}

struct 単一鍵ストア {
    handle: 単一鍵ハンドル,
}

impl KeyStore for 単一鍵ストア {
    fn lookup(&self, key_id: &[u8; 8]) -> Result<Box<dyn KeyHandle>> {
        if self.handle.key_id.as_slice() != key_id {
            bail!("未対応の鍵IDです");
        }
        Ok(Box::new(self.handle.clone()))
    }
}
