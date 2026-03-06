//! # non-resident-vapid
//! WebPush/VAPID のクレデンシャルバンドルを暗号化・復号し、サーバ側で送信まで行うためのライブラリ。
//! WASM からのエンコード、サーバでの復号と Push 送信を 1 クレートで扱う。
//!
//! Git 依存での利用例:
//! ```toml
//! non-resident-vapid = { git = "https://github.com/Ama-shock/non-resident-vapid", tag = "v0.1.0" }
//! ```

pub mod credential_bundle;
pub mod subscription;
#[cfg(target_arch = "wasm32")]
pub mod wasm;
pub mod key_store;

#[cfg(all(not(target_arch = "wasm32"), feature = "server"))]
pub mod push_sender;

use anyhow::Result;
use key_store::{KeyStore};
#[cfg(all(not(target_arch = "wasm32"), feature = "server"))]
use push_sender::pushを送信;

/// 暗号化済みクレデンシャルバンドルを復号し、Push を送信する外部公開関数。
/// 復号・署名は KeyStore/KeyHandle 実装に委譲する。
#[cfg(all(not(target_arch = "wasm32"), feature = "server"))]
pub async fn deliver_push_from_bundle(
    bundle: &[u8],
    payload: &str,
    ttl: u32,
    subject: &str,
    key_store: &dyn KeyStore,
) -> Result<()> {
    if bundle.len() < 9 {
        anyhow::bail!("バンドル長が短すぎます");
    }
    let key_id: [u8; 8] = bundle[..8].try_into().unwrap();
    let handle = key_store.lookup(&key_id)?;
    let subscription = credential_bundle::decode_credential_bundle(bundle, key_store)?;
    pushを送信(&subscription, payload, ttl, subject, handle.as_ref()).await
}
