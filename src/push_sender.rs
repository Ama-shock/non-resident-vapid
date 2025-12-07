use anyhow::{Context, Result};
use base64::{CharacterSet, Config as B64Config};
use serde::Deserialize;
use web_push::{
    ContentEncoding, SubscriptionInfo, VapidSignatureBuilder, WebPushClient, WebPushMessageBuilder,
};

#[derive(Debug, Deserialize)]
pub struct 購読データ {
    pub endpoint: String,
    pub auth: String,
    pub p256dh: String,
    #[allow(dead_code)]
    pub expirationTime: Option<serde_json::Value>,
}

pub async fn pushを送信(
    購読: &購読データ,
    本文: &str,
    ttl: u32,
    subject: &str,
    署名提供者: &impl Vapid署名提供者,
) -> Result<()> {
    let 購読情報 = SubscriptionInfo::new(&購読.endpoint, &購読.p256dh, &購読.auth);
    let vapid署名 = 署名提供者.vapid署名作成(&購読情報, subject)?;

    let mut メッセージ = WebPushMessageBuilder::new(&購読情報)
        .with_context(|| "WebPushMessageBuilder の初期化に失敗")?;
    メッセージ.set_vapid_signature(vapid署名);
    メッセージ.set_ttl(ttl);
    メッセージ.set_payload(ContentEncoding::Aes128Gcm, 本文.as_bytes());

    let クライアント = WebPushClient::new().with_context(|| "WebPushClient の初期化に失敗")?;
    クライアント
        .send(メッセージ.build().with_context(|| "メッセージの組み立てに失敗")?)
        .await
        .with_context(|| "Web Push 送信に失敗")?;

    Ok(())
}

pub trait Vapid署名提供者 {
    fn vapid署名作成(
        &self,
        購読情報: &SubscriptionInfo,
        subject: &str,
    ) -> Result<web_push::VapidSignature>;
}

/// TPM/HSM 等のキーストアで署名することを前提とした暫定実装。
/// 実環境では秘密鍵はハードウェア内に閉じ込め、ここで扱うのは署名ハンドルのみになる想定。
pub struct ソフトウェアキーストア {
    vapid秘密鍵素材: String,
}

impl ソフトウェアキーストア {
    pub fn new(vapid秘密鍵素材: String) -> Self {
        Self { vapid秘密鍵素材 }
    }
}

impl Vapid署名提供者 for ソフトウェアキーストア {
    fn vapid署名作成(
        &self,
        購読情報: &SubscriptionInfo,
        subject: &str,
    ) -> Result<web_push::VapidSignature> {
        let base64設定 = B64Config::new(CharacterSet::UrlSafe, false);
        let mut ビルダー =
            VapidSignatureBuilder::from_base64(&self.vapid秘密鍵素材, base64設定, 購読情報)
                .with_context(|| "VAPID 署名ビルダーの生成に失敗")?;
        ビルダー.add_claim("sub", subject);
        let 署名 = ビルダー
            .build()
            .with_context(|| "VAPID 署名の生成に失敗")?;
        Ok(署名)
    }
}
