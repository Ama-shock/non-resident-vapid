use anyhow::{Context, Result, bail};
use web_push::{
    ContentEncoding, SubscriptionInfo, VapidSignature, WebPushClient, WebPushMessageBuilder,
};

use crate::subscription::購読データ;
use crate::key_store::KeyHandle;
use crate::credential_bundle::base64url_encode;
use serde_json::json;
use url::Url;
use std::time::{SystemTime, UNIX_EPOCH};

pub async fn pushを送信(
    購読: &購読データ,
    本文: &str,
    ttl: u32,
    subject: &str,
    鍵ハンドル: &dyn KeyHandle,
) -> Result<()> {
    let 購読情報: SubscriptionInfo = 購読.clone().into();
    let vapid署名 = vapid署名作成(鍵ハンドル, &購読情報, subject)?;

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

fn vapid署名作成(
    鍵ハンドル: &dyn KeyHandle,
    購読情報: &SubscriptionInfo,
    subject: &str,
) -> Result<VapidSignature> {
    let aud = aud_from_endpoint(&購読情報.endpoint)?;
    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| anyhow::anyhow!("システム時刻取得に失敗"))?
        .as_secs() + 12 * 60 * 60;

    let header_b64 = base64url_encode(r#"{"typ":"JWT","alg":"ES256"}"#);
    let payload_json = json!({
        "aud": aud,
        "exp": exp,
        "sub": subject,
    });
    let payload_b64 = base64url_encode(payload_json.to_string().as_bytes());
    let message = format!("{}.{}", header_b64, payload_b64);

    let sig = 鍵ハンドル.sign(message.as_bytes())?;
    if sig.len() != 64 {
        bail!("署名長が想定外です (expected 64 bytes)");
    }
    let sig_b64 = base64url_encode(sig);
    let jwt = format!("{}.{}", message, sig_b64);

    let auth_t = format!("WebPush {}", jwt);
    let auth_k = format!("p256ecdsa={}", base64url_encode(鍵ハンドル.public_key_bytes())).into_bytes();

    Ok(VapidSignature { auth_t, auth_k })
}

fn aud_from_endpoint(endpoint: &str) -> Result<String> {
    let url = Url::parse(endpoint).with_context(|| "endpoint URL の解析に失敗")?;
    let scheme = url.scheme();
    let host = url.host_str().ok_or_else(|| anyhow::anyhow!("endpoint にホストがありません"))?;
    let port = url.port().map(|p| format!(":{}", p)).unwrap_or_default();
    Ok(format!("{}://{}{}", scheme, host, port))
}
