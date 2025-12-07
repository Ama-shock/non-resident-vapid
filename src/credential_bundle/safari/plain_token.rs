use anyhow::{bail, Result};

use crate::credential_bundle::{クレデンシャル, 共通部をエンコード, 共通部をデコード};
use super::base64_token::token_from_endpoint;

/// 0x31 / 0x01: Safari 生文字列トークン（フォールバック）
pub fn エンコード_safari_plain(cred: &クレデンシャル, _cat: u8, _minor: u8) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    共通部をエンコード(0x31, 0x01, cred, &mut buf);

    buf.extend_from_slice(&cred.p256dh);
    buf.extend_from_slice(&[cred.auth.len() as u8]);
    buf.extend_from_slice(&cred.auth);

    let token_str = token_from_endpoint(cred.endpoint.as_str())?;
    let token_bytes = token_str.as_bytes();
    buf.push(0x00); // prefix ID
    buf.extend_from_slice(&(token_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(token_bytes);
    Ok(buf)
}

pub fn デコード_safari_plain(data: &[u8]) -> Result<クレデンシャル> {
    let (exp, nonce, mut offset) = 共通部をデコード(data)?;
    if data.len() < offset + 33 + 1 {
        bail!("p256dh/auth を読み取る長さが足りません");
    }
    let p256dh = data[offset..offset + 33].to_vec();
    offset += 33;
    let auth_len = data[offset] as usize;
    offset += 1;
    if data.len() < offset + auth_len + 3 {
        bail!("auth または endpoint データが不足");
    }
    let auth = data[offset..offset + auth_len].to_vec();
    offset += auth_len;

    let prefix_id = data[offset];
    if prefix_id != 0x00 {
        bail!("未知の Safari プレフィックス ID: {}", prefix_id);
    }
    offset += 1;
    let token_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    offset += 2;
    if data.len() < offset + token_len {
        bail!("token 長さが不足");
    }
    let token_slice = &data[offset..offset + token_len];
    let token = String::from_utf8(token_slice.to_vec())
        .map_err(|_| anyhow::anyhow!("token は UTF-8 である必要があります"))?;
    let endpoint = format!("https://webpush.apple.com/api/push/{}", token);

    Ok(クレデンシャル {
        expiration_time_48: exp,
        nonce,
        p256dh,
        auth,
        endpoint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safari_plain_roundtrip() {
        let cred = クレデンシャル {
            expiration_time_48: 0xABCDEF123456,
            nonce: 0xCAFE,
            p256dh: vec![9; 33],
            auth: vec![1, 2, 3, 4],
            endpoint: "https://webpush.apple.com/api/push/plain-token-raw".to_string(),
        };
        let enc = エンコード_safari_plain(&cred, 0x31, 0x01).unwrap();
        let dec = デコード_safari_plain(&enc).unwrap();
        assert_eq!(cred, dec);
    }
}
