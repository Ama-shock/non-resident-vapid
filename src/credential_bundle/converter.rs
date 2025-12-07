use anyhow::{bail, Result};
use rand::Rng;

use crate::credential_bundle::{base64url_decode, base64url_encode, クレデンシャル};
use crate::subscription::購読データ;

/// 購読データからクレデンシャルへ変換する。
/// `指定有効期限_sec` と `鍵有効期限_sec`（任意）の最短と購読の `expirationTime` の最短を採用。
/// nonce は与えられなければ乱数を生成。
pub fn 購読データからクレデンシャル(
    購読: &購読データ,
    有効期限_sec: u64,
    nonce: Option<u16>,
) -> Result<クレデンシャル> {
    let p256dh = base64url_decode(&購読.p256dh)?;
    let auth = base64url_decode(&購読.auth)?;
    let endpoint = 購読.endpoint.clone();

    let mut 候補期限: Vec<u64> = vec![有効期限_sec];
    if let Some(exp) = 購読.expiration_time.as_ref() {
        if let Some(n) = exp.as_u64() {
            候補期限.push(n);
        }
    }
    if 候補期限.is_empty() {
        bail!("有効期限の候補がありません");
    }
    let expiration_time_48 = *候補期限.iter().min().unwrap();

    let nonce = nonce.unwrap_or_else(|| rand::thread_rng().gen());

    Ok(クレデンシャル {
        expiration_time_48,
        nonce,
        p256dh,
        auth,
        endpoint,
    })
}

/// クレデンシャルから購読データへ変換する（p256dh/auth は Base64URL 化）。
pub fn クレデンシャルから購読データ(cred: &クレデンシャル) -> 購読データ {
    購読データ {
        endpoint: cred.endpoint.clone(),
        auth: base64url_encode(&cred.auth),
        p256dh: base64url_encode(&cred.p256dh),
        expiration_time: Some(serde_json::Value::from(cred.expiration_time_48)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subscription::購読データ;

    #[test]
    fn 購読からクレデンシャルへ_期限最短を採用() {
        let 購読 = 購読データ {
            endpoint: "https://example.test".to_string(),
            auth: base64url_encode(&[1, 2, 3]),
            p256dh: base64url_encode(&[4, 5, 6]),
            expiration_time: Some(serde_json::Value::from(500u64)),
        };
        let cred = 購読データからクレデンシャル(&購読, 200, Some(0x1234)).unwrap();
        assert_eq!(cred.expiration_time_48, 200); // 200 < 500
        assert_eq!(cred.nonce, 0x1234);
        assert_eq!(cred.p256dh, vec![4, 5, 6]);
        assert_eq!(cred.auth, vec![1, 2, 3]);
    }

    #[test]
    fn クレデンシャルから購読へ_roundtrip() {
        let cred = クレデンシャル {
            expiration_time_48: 123,
            nonce: 0x1111,
            p256dh: vec![9, 8, 7],
            auth: vec![6, 5, 4],
            endpoint: "https://example.test".to_string(),
        };
        let sub = クレデンシャルから購読データ(&cred);
        assert_eq!(sub.endpoint, cred.endpoint);
        assert_eq!(sub.expiration_time, Some(serde_json::Value::from(123u64)));
        let back = 購読データからクレデンシャル(&sub, 9999, Some(0x1111)).unwrap();
        assert_eq!(back.p256dh, cred.p256dh);
        assert_eq!(back.auth, cred.auth);
        assert_eq!(back.endpoint, cred.endpoint);
    }
}
