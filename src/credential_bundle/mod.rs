pub mod autopush;
pub mod fcm;
pub mod general;
pub mod safari;
pub mod converter;
pub mod crypto;

use anyhow::{bail, Context, Result};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::subscription::購読データ;
use crate::credential_bundle::converter::{クレデンシャルから購読データ, 購読データからクレデンシャル};
use crate::credential_bundle::crypto::p256dhで暗号化;

/// 共通クレデンシャル表現
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct クレデンシャル {
    pub expiration_time_48: u64, // 下位 48bit を使用
    pub nonce: u16,
    pub p256dh: Vec<u8>,
    pub auth: Vec<u8>,
    pub endpoint: String,
}

#[derive(Debug)]
pub struct デコード結果 {
    pub 型カテゴリ: u8,
    pub マイナーバージョン: u8,
    pub クレデンシャル: クレデンシャル,
}

#[derive(Debug)]
pub struct エンコード結果 {
    pub 型カテゴリ: u8,
    pub マイナーバージョン: u8,
    pub クレデンシャル: クレデンシャル,
    pub バイト列: Vec<u8>,
}

pub struct エンコード戦略 {
    pub 型カテゴリ: u8,
    pub マイナーバージョン: u8,
    pub 優先度: u8,
    pub 判定: fn(&クレデンシャル) -> bool,
    pub エンコード: fn(&クレデンシャル, u8, u8) -> Result<Vec<u8>>,
    pub デコード: fn(&[u8]) -> Result<クレデンシャル>,
}

/// データ型 2 バイトをパースするためのヘルパ。
fn 型を取得(data: &[u8]) -> Result<(u8, u8)> {
    if data.len() < 2 {
        bail!("データ長不足: 型情報が 2 バイトありません");
    }
    Ok((data[0], data[1]))
}

/// クレデンシャルデータ全体をデコードし、カテゴリに応じたデコーダへ振り分ける。
pub fn クレデンシャルをデコード(data: &[u8]) -> Result<デコード結果> {
    let (カテゴリ, マイナー) = 型を取得(data)?;
    let 戦略 = 全戦略()
        .into_iter()
        .find(|s| s.型カテゴリ == カテゴリ && s.マイナーバージョン == マイナー)
        .ok_or_else(|| anyhow::anyhow!("未知の型カテゴリ/マイナー: {:#04x}/{:#04x}", カテゴリ, マイナー))?;

    let cred = (戦略.デコード)(data)?;
    Ok(デコード結果 {
        型カテゴリ: カテゴリ,
        マイナーバージョン: マイナー,
        クレデンシャル: cred,
    })
}

/// 4要素（p256dh/auth/endpoint/期限など）から最適なエンコード形式を自動選択してバイト列を生成する。
/// 型カテゴリ・マイナーバージョンは戦略判定結果として付与し、結果に含めて返す。
pub fn クレデンシャルを自動エンコード(
    expiration_time_48: u64,
    nonce: u16,
    p256dh: Vec<u8>,
    auth: Vec<u8>,
    endpoint: String,
) -> Result<エンコード結果> {
    let cred = クレデンシャル {
        expiration_time_48,
        nonce,
        p256dh,
        auth,
        endpoint,
    };

    let mut 戦略一覧 = 全戦略();
    戦略一覧.sort_by_key(|s| s.優先度);

    for 戦略 in 戦略一覧 {
        if (戦略.判定)(&cred) {
            let bytes = (戦略.エンコード)(&cred, 戦略.型カテゴリ, 戦略.マイナーバージョン)?;
            return Ok(エンコード結果 {
                型カテゴリ: 戦略.型カテゴリ,
                マイナーバージョン: 戦略.マイナーバージョン,
                クレデンシャル: cred,
                バイト列: bytes,
            });
        }
    }

    bail!("適用可能なエンコード戦略が見つかりませんでした");
}

/// 共通ヘッダ部分を読み書きするヘルパ。
pub(crate) fn 共通部をエンコード(型カテゴリ: u8, マイナーバージョン: u8, cred: &クレデンシャル, buf: &mut Vec<u8>) {
    buf.push(型カテゴリ);
    buf.push(マイナーバージョン);
    let exp = cred.expiration_time_48 & 0x0000_FFFF_FFFF_FFFF;
    buf.extend_from_slice(&exp.to_be_bytes()[2..]); // 上位 2 バイトを落として 6 バイト
    buf.extend_from_slice(&cred.nonce.to_be_bytes());
}

pub(crate) fn 共通部をデコード(data: &[u8]) -> Result<(u64, u16, usize)> {
    if data.len() < 10 {
        bail!("共通部の長さが足りません");
    }
    let exp_bytes: [u8; 8] = [0, 0, data[2], data[3], data[4], data[5], data[6], data[7]];
    let exp = u64::from_be_bytes(exp_bytes);
    let nonce = u16::from_be_bytes([data[8], data[9]]);
    Ok((exp, nonce, 10))
}

/// Base64URL (nopad) デコード
pub(crate) fn base64url_decode<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>> {
    base64::decode_config(input, base64::URL_SAFE_NO_PAD).context("Base64URL デコードに失敗")
}

/// Base64URL (nopad) エンコード
pub(crate) fn base64url_encode<T: AsRef<[u8]>>(input: T) -> String {
    base64::encode_config(input, base64::URL_SAFE_NO_PAD)
}

/// 暗号化済みクレデンシャルバンドルを生成する外部向け関数。
/// 先頭 8 バイトの鍵識別子と公開鍵は KeyHandle から取得し、暗号化は p256dh スイートで本関数内にて実施する。
pub fn encode_credential_bundle(
    subscription: &購読データ,
    key_handle: &dyn crate::key_store::KeyHandle,
    expiration_sec: u64,
    nonce: Option<u16>,
) -> Result<Vec<u8>> {
    let key_identifier = key_handle.key_identifier();
    if key_identifier.len() != 8 {
        bail!("鍵識別子は 8 バイトである必要があります");
    }

    let cred = 購読データからクレデンシャル(
        subscription,
        expiration_sec,
        nonce,
    )?;

    let encoded = クレデンシャルを自動エンコード(
        cred.expiration_time_48,
        cred.nonce,
        cred.p256dh,
        cred.auth,
        cred.endpoint,
    )?;

    let encrypted = p256dhで暗号化(key_handle.public_key_bytes(), &encoded.バイト列)?;

    let mut bundle = Vec::with_capacity(8 + encrypted.len());
    bundle.extend_from_slice(key_identifier);
    bundle.extend_from_slice(&encrypted);
    Ok(bundle)
}

/// 暗号化済みクレデンシャルバンドルを復号し、購読データへ変換する外部向け関数。
/// 期限切れの場合はエラーを返す。
pub fn decode_credential_bundle(
    bundle: &[u8],
    key_store: &dyn crate::key_store::KeyStore,
) -> Result<購読データ> {
    if bundle.len() < 9 {
        bail!("バンドル長が短すぎます");
    }
    let key_id: [u8; 8] = bundle[..8].try_into().unwrap();
    let ciphertext = &bundle[8..];

    let handle = key_store.lookup(&key_id)?;
    if handle.key_identifier() != key_id {
        bail!("鍵識別子が一致しません");
    }
    let plaintext = handle.decrypt(ciphertext)?;

    let decoded = クレデンシャルをデコード(&plaintext)?;
    let cred = decoded.クレデンシャル;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("システム時刻の取得に失敗")?
        .as_secs();
    if cred.expiration_time_48 <= now {
        bail!("クレデンシャルが期限切れです");
    }

    Ok(クレデンシャルから購読データ(&cred))
}

fn 全戦略() -> Vec<エンコード戦略> {
    let mut s = Vec::new();
    s.extend(general::戦略一覧());
    s.extend(fcm::戦略一覧());
    s.extend(autopush::戦略一覧());
    s.extend(safari::戦略一覧());
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::{SecretKey as P256SecretKey, elliptic_curve::sec1::ToEncodedPoint};
    use crate::subscription::購読データ;
    use std::time::{SystemTime, UNIX_EPOCH};
    use crate::credential_bundle::crypto::p256dhで復号;
    use crate::key_store::{KeyHandle, KeyStore};
    use rand::rngs::OsRng;

    #[test]
    fn デコード_unknown() {
        let data = [0xFFu8, 0xFF];
        let err = クレデンシャルをデコード(&data).unwrap_err();
        assert!(err.to_string().contains("未知"));
    }

    #[test]
    fn 自動エンコード_fcm_globalを選択() {
        let endpoint = "https://fcm.googleapis.com/fcm/send/YWFh:YmJi".to_string();
        let result = クレデンシャルを自動エンコード(
            1,
            2,
            vec![1; 33],
            vec![2; 3],
            endpoint.clone(),
        )
        .unwrap();
        // デコードして戻ることを確認
        assert_eq!(result.型カテゴリ, 0x11);
        assert_eq!(result.マイナーバージョン, 0x01);
        let decoded = クレデンシャルをデコード(&result.バイト列).unwrap();
        assert_eq!(decoded.クレデンシャル.endpoint, endpoint);
    }

    #[test]
    fn 自動エンコード_autopushを選択() {
        let endpoint = "https://push.services.mozilla.com/wpush/v2/YWJjZA".to_string();
        let result = クレデンシャルを自動エンコード(
            1,
            2,
            vec![1; 33],
            vec![2; 3],
            endpoint.clone(),
        )
        .unwrap();
        assert_eq!(result.型カテゴリ, 0x21);
        assert_eq!(result.マイナーバージョン, 0x00);
        let decoded = クレデンシャルをデコード(&result.バイト列).unwrap();
        assert_eq!(decoded.クレデンシャル.endpoint, endpoint);
    }

    #[test]
    fn 自動エンコード_safariを選択() {
        let endpoint = "https://webpush.apple.com/api/push/dG9rZW4".to_string();
        let result = クレデンシャルを自動エンコード(
            1,
            2,
            vec![1; 33],
            vec![2; 3],
            endpoint.clone(),
        )
        .unwrap();
        assert_eq!(result.型カテゴリ, 0x31);
        assert_eq!(result.マイナーバージョン, 0x00);
        let decoded = クレデンシャルをデコード(&result.バイト列).unwrap();
        assert_eq!(decoded.クレデンシャル.endpoint, endpoint);
    }

    #[test]
    fn 自動エンコード_汎用を選択() {
        let endpoint = "https://example.test/ep".to_string();
        let result = クレデンシャルを自動エンコード(
            1,
            2,
            vec![1; 33],
            vec![2; 3],
            endpoint.clone(),
        )
        .unwrap();
        assert_eq!(result.型カテゴリ, 0x01);
        assert_eq!(result.マイナーバージョン, 0x00);
        let decoded = クレデンシャルをデコード(&result.バイト列).unwrap();
        assert_eq!(decoded.クレデンシャル.endpoint, endpoint);
    }

    #[test]
    fn バンドル_encode_decode_roundtrip() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let browser_sk = P256SecretKey::random(&mut OsRng);
        let browser_pk = browser_sk.public_key();
        let subscription = 購読データ {
            endpoint: "https://fcm.googleapis.com/fcm/send/YWFh:YmJi".into(),
            auth: base64url_encode(&[0xAA, 0xBB, 0xCC]),
            p256dh: base64url_encode(browser_pk.to_encoded_point(false).as_bytes()),
            expiration_time: None,
        };
        let recipient_sk = P256SecretKey::random(&mut OsRng);
        let handle = テスト鍵ハンドル::new([0x10; 8], recipient_sk.clone());
        let store = テスト鍵ストア::new(handle.clone());
        let key_id = [0x10u8; 8];
        let expires = now + 3600;

        let bundle = encode_credential_bundle(
            &subscription,
            &handle,
            expires,
            Some(0x1234),
        )
        .unwrap();

        assert_eq!(&bundle[..8], &key_id);

        let decoded = decode_credential_bundle(&bundle, &store).unwrap();
        assert_eq!(decoded.endpoint, subscription.endpoint);
        assert_eq!(decoded.auth, subscription.auth);
        assert_eq!(decoded.p256dh, subscription.p256dh);
    }

    #[test]
    fn バンドル_decode_expired() {
        let browser_sk = P256SecretKey::random(&mut OsRng);
        let browser_pk = browser_sk.public_key();
        let subscription = 購読データ {
            endpoint: "https://example.test".into(),
            auth: base64url_encode(&[1, 2, 3]),
            p256dh: base64url_encode(browser_pk.to_encoded_point(false).as_bytes()),
            expiration_time: None,
        };
        let recipient_sk = P256SecretKey::random(&mut OsRng);
        let handle = テスト鍵ハンドル::new([0x20; 8], recipient_sk.clone());
        let store = テスト鍵ストア::new(handle.clone());

        let bundle = encode_credential_bundle(
            &subscription,
            &handle,
            1,
            Some(0),
        )
        .unwrap();

        let err = decode_credential_bundle(&bundle, &store).unwrap_err();
        assert!(err.to_string().contains("期限切れ"));
    }

    #[derive(Clone)]
    struct テスト鍵ハンドル {
        id: [u8; 8],
        secret: P256SecretKey,
        public: Vec<u8>,
    }

    impl テスト鍵ハンドル {
        fn new(id: [u8; 8], secret: P256SecretKey) -> Self {
            let public = secret.public_key().to_encoded_point(true).as_bytes().to_vec();
            Self { id, secret, public }
        }
    }

    impl KeyHandle for テスト鍵ハンドル {
        fn key_identifier(&self) -> &[u8] {
            &self.id
        }
        fn public_key_bytes(&self) -> &[u8] {
            &self.public
        }
        fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
            p256dhで復号(ciphertext, &self.secret)
        }
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
            use p256::ecdsa::{signature::Signer, SigningKey};
            let signing: SigningKey = (&self.secret).into();
            let sig: p256::ecdsa::Signature = signing.sign(message);
            Ok(sig.to_bytes().to_vec())
        }
    }

    struct テスト鍵ストア {
        handle: テスト鍵ハンドル,
    }

    impl テスト鍵ストア {
        fn new(handle: テスト鍵ハンドル) -> Self {
            Self { handle }
        }
    }

    impl KeyStore for テスト鍵ストア {
        fn lookup(&self, key_id: &[u8; 8]) -> Result<Box<dyn KeyHandle>> {
            if self.handle.id.as_slice() != key_id {
                bail!("未対応の鍵ID");
            }
            Ok(Box::new(self.handle.clone()))
        }
    }
}
