use anyhow::{bail, Result};

use crate::credential_bundle::{クレデンシャル, 共通部をエンコード, 共通部をデコード};
use crate::credential_bundle::エンコード戦略;

/// 0x01 / 0x00: 非圧縮・素の値（汎用）
pub fn エンコード_汎用_初版(cred: &クレデンシャル, 型カテゴリ: u8, マイナーバージョン: u8) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    共通部をエンコード(型カテゴリ, マイナーバージョン, cred, &mut buf);
    buf.extend_from_slice(&(cred.p256dh.len() as u16).to_be_bytes());
    buf.extend_from_slice(&cred.p256dh);
    buf.extend_from_slice(&(cred.auth.len() as u16).to_be_bytes());
    buf.extend_from_slice(&cred.auth);
    let endpoint_bytes = cred.endpoint.as_bytes();
    buf.extend_from_slice(&(endpoint_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(endpoint_bytes);
    Ok(buf)
}

pub fn デコード_汎用_初版(data: &[u8]) -> Result<クレデンシャル> {
    if data.len() < 10 {
        bail!("データ長不足");
    }
    let (exp, nonce, mut offset) = 共通部をデコード(data)?;

    let (p256dh, o1) = 長さ付き取得(data, offset)?;
    offset = o1;
    let (auth, o2) = 長さ付き取得(data, offset)?;
    offset = o2;
    let (endpoint_bytes, _o3) = 長さ付き取得(data, offset)?;
    let endpoint = String::from_utf8(endpoint_bytes)
        .map_err(|_| anyhow::anyhow!("endpoint は UTF-8 である必要があります"))?;

    Ok(クレデンシャル {
        expiration_time_48: exp,
        nonce,
        p256dh,
        auth,
        endpoint,
    })
}

fn 長さ付き取得(data: &[u8], offset: usize) -> Result<(Vec<u8>, usize)> {
    if data.len() < offset + 2 {
        bail!("長さフィールドが読み取れません");
    }
    let len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    let start = offset + 2;
    let end = start + len;
    if data.len() < end {
        bail!("データ長不足 (期待: {}, 実際: {})", end, data.len());
    }
    Ok((data[start..end].to_vec(), end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn 汎用初版_roundtrip() {
        let cred = クレデンシャル {
            expiration_time_48: 0x112233445566,
            nonce: 0x7788,
            p256dh: vec![1, 2, 3],
            auth: vec![4, 5],
            endpoint: "https://example.test/ep".to_string(),
        };
        let enc = エンコード_汎用_初版(&cred, 0x01, 0x00).unwrap();
        let dec = デコード_汎用_初版(&enc).unwrap();
        assert_eq!(cred, dec);
    }
}

pub fn 戦略一覧() -> Vec<エンコード戦略> {
    vec![エンコード戦略 {
        型カテゴリ: 0x01,
        マイナーバージョン: 0x00,
        優先度: 0xFF, // フォールバック
        判定: |_| true,
        エンコード: エンコード_汎用_初版,
        デコード: デコード_汎用_初版,
    }]
}
