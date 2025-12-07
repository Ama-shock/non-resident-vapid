use anyhow::{bail, Result};

use crate::credential_bundle::{
    base64url_decode, base64url_encode, クレデンシャル, 共通部をエンコード, 共通部をデコード,
};

const APPLE_PREFIX: &str = "https://webpush.apple.com/api/push/";

/// 0x31 / 0x00: Safari Base64URL トークン
pub fn エンコード_safari_base64(cred: &クレデンシャル, _cat: u8, _minor: u8) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    共通部をエンコード(0x31, 0x00, cred, &mut buf);

    buf.extend_from_slice(&cred.p256dh);
    buf.extend_from_slice(&[cred.auth.len() as u8]);
    buf.extend_from_slice(&cred.auth);

    let token = base64url_decode(token_from_endpoint(cred.endpoint.as_str())?)?;
    buf.push(0x00); // prefix ID
    buf.extend_from_slice(&(token.len() as u16).to_be_bytes());
    buf.extend_from_slice(&token);
    Ok(buf)
}

pub fn デコード_safari_base64(data: &[u8]) -> Result<クレデンシャル> {
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
    let token = base64url_encode(token_slice);
    let endpoint = format!("{}{}", APPLE_PREFIX, token);

    Ok(クレデンシャル {
        expiration_time_48: exp,
        nonce,
        p256dh,
        auth,
        endpoint,
    })
}

pub fn token_from_endpoint(endpoint: &str) -> Result<String> {
    if let Some(t) = endpoint.strip_prefix(APPLE_PREFIX) {
        Ok(t.to_string())
    } else {
        bail!("Safari endpoint プレフィックスが想定外です");
    }
}

pub fn is_base64url(token: &str) -> bool {
    base64url_decode(token).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safari_base64_roundtrip() {
        let cred = クレデンシャル {
            expiration_time_48: 0xABCDEF123456,
            nonce: 0xCAFE,
            p256dh: vec![9; 33],
            auth: vec![1, 2, 3, 4],
            endpoint: "https://webpush.apple.com/api/push/QWxhZGRpbjpvcGVuIHNlc2FtZQ".to_string(),
        };
        let enc = エンコード_safari_base64(&cred, 0x31, 0x00).unwrap();
        let dec = デコード_safari_base64(&enc).unwrap();
        assert_eq!(cred, dec);
    }
}
